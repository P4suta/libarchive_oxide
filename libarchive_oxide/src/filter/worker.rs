// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub(super) const QUEUE_DEPTH: usize = 2;

pub(super) enum InputMessage {
    Data(Vec<u8>),
    End,
}

#[derive(Debug)]
pub(super) enum WorkerEvent {
    NeedInput,
    Output(Vec<u8>),
}

pub(super) enum WorkerProgress {
    NeedInput,
    Output(usize),
    Finished,
}

impl WorkerProgress {
    pub(super) fn produced(self) -> usize {
        match self {
            Self::NeedInput | Self::Finished => 0,
            Self::Output(bytes) => bytes,
        }
    }
}

#[cfg(test)]
pub(super) mod testing {
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;

    use libarchive_oxide_core::{ArchiveError, CodecStatus, CodecStep};

    use super::{InputMessage, QUEUE_DEPTH, WorkerEvent};

    const SCHEDULE_PARTICIPANTS: usize = 2;

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum DriveCheckpoint {
        InputFull,
        Waiting,
        Finished,
    }

    pub(crate) struct DriveSchedule {
        notify: mpsc::SyncSender<DriveCheckpoint>,
        release: Arc<Barrier>,
    }

    impl DriveSchedule {
        pub(crate) fn pause(&self, checkpoint: DriveCheckpoint) {
            self.notify.send(checkpoint).expect("driver checkpoint");
            self.release.wait();
        }
    }

    pub(crate) struct DriverChannels<Message = InputMessage, Event = WorkerEvent> {
        pub(crate) sender: mpsc::SyncSender<Message>,
        pub(crate) events: mpsc::Receiver<Event>,
        pub(crate) schedule: Arc<DriveSchedule>,
        pub(crate) retained: Vec<u8>,
    }

    pub(crate) fn assert_retained_input_progress(
        magic: &'static [u8],
        drive: impl FnOnce(DriverChannels) -> Result<Option<CodecStep>, ArchiveError> + Send + 'static,
    ) {
        assert_retained_input_progress_with(
            magic,
            InputMessage::Data,
            WorkerEvent::NeedInput,
            |message| match message {
                InputMessage::Data(bytes) => Some(bytes),
                InputMessage::End => None,
            },
            drive,
        );
    }

    pub(crate) fn assert_retained_input_progress_with<
        Message: Send + 'static,
        Event: Send + 'static,
    >(
        magic: &'static [u8],
        data: impl Fn(Vec<u8>) -> Message,
        need_input: Event,
        into_bytes: impl Fn(Message) -> Option<Vec<u8>>,
        drive: impl FnOnce(DriverChannels<Message, Event>) -> Result<Option<CodecStep>, ArchiveError>
        + Send
        + 'static,
    ) {
        let (sender, input) = mpsc::sync_channel(QUEUE_DEPTH);
        let prefix = &magic[..QUEUE_DEPTH];
        for &byte in prefix {
            sender.send(data(vec![byte])).unwrap();
        }
        let retained = magic[QUEUE_DEPTH..].to_vec();
        let (events, receiver) = mpsc::sync_channel(QUEUE_DEPTH);
        let (notify, checkpoints) = mpsc::sync_channel(QUEUE_DEPTH);
        let release = Arc::new(Barrier::new(SCHEDULE_PARTICIPANTS));
        let channels = DriverChannels {
            sender,
            events: receiver,
            schedule: Arc::new(DriveSchedule {
                notify: notify.clone(),
                release: Arc::clone(&release),
            }),
            retained: retained.clone(),
        };
        let owner = thread::spawn(move || {
            let result = drive(channels);
            notify.send(DriveCheckpoint::Finished).unwrap();
            result
        });
        let first = checkpoints.recv().unwrap();
        let mut completed = false;
        let mut queued_prefix = Vec::new();
        let mut delivered = None;
        if first == DriveCheckpoint::InputFull {
            for _ in prefix {
                queued_prefix.push(input.try_recv());
            }
            events.send(need_input).unwrap();
            release.wait();
            let next = checkpoints.recv().unwrap();
            completed = next == DriveCheckpoint::Finished;
            delivered = Some(input.try_recv());
            drop(events);
            if !completed {
                release.wait();
            }
        } else {
            drop(events);
            if first != DriveCheckpoint::Finished {
                release.wait();
            }
        }
        drop(input);
        let result = owner.join().expect("scheduled codec owner");

        assert_eq!(first, DriveCheckpoint::InputFull);
        assert!(completed, "owner waited after consuming an input request");
        for (message, &byte) in queued_prefix.into_iter().zip(prefix) {
            let message = message.expect("queued prefix");
            assert_eq!(into_bytes(message).as_deref(), Some([byte].as_slice()));
        }
        let delivered = delivered
            .expect("retained input delivered")
            .expect("retained input queued");
        assert_eq!(into_bytes(delivered).as_deref(), Some(retained.as_slice()));
        let step = result.unwrap().unwrap();
        assert_eq!(step.status, CodecStatus::NeedInput);
        assert_eq!((step.consumed, step.produced), (0, 0));
    }
}
