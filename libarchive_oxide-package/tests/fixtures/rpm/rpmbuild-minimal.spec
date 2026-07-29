# SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

Name:           libarchive-oxide-interop
Version:        1.0
Release:        1
Summary:        Deterministic RPM integrity interoperability fixture
License:        MIT OR Apache-2.0
BuildArch:      noarch

%description
Synthetic package used only to test RPM parsing and payload digest verification.

%install
install -d %{buildroot}/usr/share/libarchive-oxide
printf 'libarchive-oxide RPM interoperability fixture\n' \
    > %{buildroot}/usr/share/libarchive-oxide/fixture.txt
touch -d '@946684800' %{buildroot}/usr/share/libarchive-oxide/fixture.txt

%files
%dir /usr/share/libarchive-oxide
/usr/share/libarchive-oxide/fixture.txt

%changelog
* Sat Jan 01 2000 libarchive_oxide contributors
- Deterministic interoperability fixture
