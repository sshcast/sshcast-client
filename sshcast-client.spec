%global debug_package %{nil}
%global rustflags_codegen_units 16

Name:           sshcast-client
Version:        0.1.0
Release:        1%{?dist}
Summary:        Workstation GUI and Enrollment CLI for Sshcast Roaming SSH Agent
License:        MIT OR Apache-2.0
URL:            https://github.com/sshcast/sshcast-client
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  systemd-rpm-macros
Requires:       systemd

%description
Sshcast Workstation Client (sshcast-client) maintains persistent outbound
bidirectional gRPC streams to sshcast-server coordinators, verifies relay
NodeGrants and end-to-end SignRequest signatures, pops a native egui approval
window (displaying verified hostname, target SSH user, and 6-level /proc
ancestry), and bridges approved requests to the local OS SSH agent.

%prep
%autosetup -n %{name}-%{version}

%build
export CARGO_BUILD_JOBS="${RPM_BUILD_NCPUS:-$(nproc)}"
cargo build %{?_smp_mflags} --release --locked --bins

%check
export CARGO_BUILD_JOBS="${RPM_BUILD_NCPUS:-$(nproc)}"
cargo test %{?_smp_mflags} --release --locked

%install
install -D -m 0755 target/release/sshcast-client %{buildroot}%{_bindir}/sshcast-client
install -D -m 0644 systemd/sshcast-client.service %{buildroot}%{_userunitdir}/sshcast-client.service

%post
%systemd_user_post sshcast-client.service

%preun
%systemd_user_preun sshcast-client.service

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md
%{_bindir}/sshcast-client
%{_userunitdir}/sshcast-client.service

%changelog
* Sun Nov 08 2026 Paul Komkoff <i@stingr.net> - 0.1.0-1
- Initial Fedora RPM package for sshcast-client
