# RPM spec for COPR / manual rpmbuild. Fedora-native equivalents of the nfpm
# package: sysusers.d replaces postinstall's groupadd, systemd scriptlet macros
# replace the postinstall/preremove shell scripts. Dependencies are vendored
# (Source1) because COPR RPM builds run without network.

# EL find-debuginfo emits an empty debugsource file list for vendored cargo
# builds, failing the build. Keep debuginfo, drop only the debugsource
# subpackage there; Fedora is unaffected.
%if 0%{?rhel}
%undefine _debugsource_packages
%endif

Name:           machine-krb-service
Version:        0.1.1
Release:        1%{?dist}
Summary:        Keep an Active Directory machine-account Kerberos ticket fresh

License:        MIT OR Apache-2.0
URL:            https://github.com/techneut92/machine-krb
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.xz

BuildRequires:  cargo
BuildRequires:  rust >= 1.85
BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros

Requires:       krb5-workstation

%description
Renews (or mints from /etc/krb5.keytab) the machine TGT into
/run/machine-krb/armor.ccache so FAST armoring / compound authentication
consumers always find a valid, group-readable ticket.

%prep
%autosetup
tar -xJf %{SOURCE1}
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

%build
cargo build --release --offline --locked -p machine-krb-service

%install
install -D -m 0755 target/release/machine-krb-service %{buildroot}%{_bindir}/machine-krb-service
install -D -m 0644 config/config.yaml %{buildroot}%{_sysconfdir}/machine-krb/config.yaml

# unit ships with the dev-box /usr/local path; packages install to /usr/bin
sed 's|ExecStart=/usr/local/bin/|ExecStart=%{_bindir}/|' \
    systemd/machine-krb-service.service > machine-krb-service.service.pkg
install -D -m 0644 machine-krb-service.service.pkg %{buildroot}%{_unitdir}/machine-krb-service.service
install -D -m 0644 systemd/machine-krb-service.timer %{buildroot}%{_unitdir}/machine-krb-service.timer
install -D -m 0644 systemd/machine-krb.tmpfiles.conf %{buildroot}%{_tmpfilesdir}/machine-krb.conf
install -D -m 0755 systemd/90-machine-krb-service \
    %{buildroot}%{_prefix}/lib/NetworkManager/dispatcher.d/90-machine-krb-service

# membership == ability to authenticate to AD as this computer — see
# config.yaml. rpm >= 4.19 (F39+/EL10) creates the group natively from this
# file at install time, before %%post needs it — no %%pre scriptlet.
echo 'g machine-krb -' > machine-krb.sysusers
install -D -m 0644 machine-krb.sysusers %{buildroot}%{_sysusersdir}/machine-krb.conf

%post
%systemd_post machine-krb-service.service machine-krb-service.timer
%tmpfiles_create machine-krb.conf

%preun
%systemd_preun machine-krb-service.timer machine-krb-service.service

%postun
%systemd_postun machine-krb-service.service machine-krb-service.timer

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md
%{_bindir}/machine-krb-service
%dir %{_sysconfdir}/machine-krb
%config(noreplace) %{_sysconfdir}/machine-krb/config.yaml
%{_unitdir}/machine-krb-service.service
%{_unitdir}/machine-krb-service.timer
%{_tmpfilesdir}/machine-krb.conf
%{_sysusersdir}/machine-krb.conf
%dir %{_prefix}/lib/NetworkManager
%dir %{_prefix}/lib/NetworkManager/dispatcher.d
%{_prefix}/lib/NetworkManager/dispatcher.d/90-machine-krb-service

%changelog
* Sun Jul 12 2026 Dylan Westra <dylanwestra@gmail.com> - 0.1.1-1
- Distro packaging and automated publishing (COPR, OBS); no functional changes

* Sun Jul 12 2026 Dylan Westra <dylanwestra@gmail.com> - 0.1.0-1
- Initial package
