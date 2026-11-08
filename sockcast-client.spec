%global debug_package %{nil}

Name:           sockcast-client
Version:        0.1.0
Release:        1%{?dist}
Summary:        Workstation GUI and Enrollment CLI for Sockcast Roaming SSH Agent
License:        MIT OR Apache-2.0
URL:            https://github.com/theraphim/sockcast-client
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  systemd-rpm-macros
Requires:       systemd

%description
Sockcast Workstation Client (sockcast-client) maintains persistent outbound
bidirectional gRPC streams to sockcast-server coordinators, verifies relay
NodeGrants and end-to-end SignRequest signatures, pops a native egui approval
window (displaying verified hostname, target SSH user, and 6-level /proc
ancestry), and bridges approved requests to the local OS SSH agent.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release --locked

%check
cargo test --release --locked

%install
install -D -m 0755 target/release/sockcast-client %{buildroot}%{_bindir}/sockcast-client
install -D -m 0644 systemd/sockcast-client.service %{buildroot}%{_userunitdir}/sockcast-client.service

%post
%systemd_user_post sockcast-client.service

%preun
%systemd_user_preun sockcast-client.service

%files
%doc README.md
%{_bindir}/sockcast-client
%{_userunitdir}/sockcast-client.service

%changelog
* Sun Nov 08 2026 Paul Komkoff <i@stingr.net> - 0.1.0-1
- Initial Fedora RPM package for sockcast-client
