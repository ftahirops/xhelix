Name:           xhelix
Version:        0.0.2
Release:        1%{?dist}
Summary:        Real-time Linux runtime security agent

License:        Apache-2.0
URL:            https://github.com/xhelix/xhelix
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.22
BuildRequires:  make
BuildRequires:  systemd-rpm-macros

Requires:       systemd
Requires(pre):  shadow-utils

%if %{with_selinux}
BuildRequires:  selinux-policy-devel
Requires:       policycoreutils, policycoreutils-python-utils
%endif

%description
xhelix observes processes, files, network, and identity events in real
time and produces high-signal security alerts. It uses eBPF for
kernel-level observation, CEL-based detection rules, and provides
tamper-evident forensics via Ed25519-signed hash chains.

%prep
%autosetup

%build
make build

%install
install -D -m 0755 xhelix %{buildroot}%{_bindir}/xhelix
install -D -m 0755 xhelixctl %{buildroot}%{_bindir}/xhelixctl
install -D -m 0755 xhelix-verify %{buildroot}%{_bindir}/xhelix-verify

install -D -m 0644 packaging/deb/etc/systemd/system/xhelix.service \
    %{buildroot}%{_unitdir}/xhelix.service
install -D -m 0644 packaging/deb/etc/xhelix/xhelix.yaml \
    %{buildroot}%{_sysconfdir}/xhelix/xhelix.yaml

# Ruleset
install -d -m 0755 %{buildroot}%{_sysconfdir}/xhelix/rules.d
install -d -m 0755 %{buildroot}%{_sysconfdir}/xhelix/suricata-rules.d

# State directories
install -d -m 0750 %{buildroot}%{_sharedstatedir}/xhelix
install -d -m 0750 %{buildroot}%{_localstatedir}/log/xhelix
install -d -m 0750 %{buildroot}%{_rundir}/xhelix

# SELinux policy
%if %{with_selinux}
install -D -m 0644 packaging/selinux/xhelix.te %{buildroot}%{_datadir}/selinux/packages/xhelix.te
%endif

%pre
getent group xhelix >/dev/null || groupadd -r xhelix
getent passwd xhelix >/dev/null || \
    useradd -r -g xhelix -d %{_sharedstatedir}/xhelix -s /sbin/nologin \
    -c "xhelix runtime security agent" xhelix

%post
%systemd_post xhelix.service

# SELinux: build and load policy if in enforcing/permissive mode
%if %{with_selinux}
if command -v semodule >/dev/null 2>&1; then
    cd %{_datadir}/selinux/packages
    make -f /usr/share/selinux/devel/Makefile xhelix.pp 2>/dev/null || true
    if [ -f xhelix.pp ]; then
        semodule -i xhelix.pp 2>/dev/null || true
    fi
fi
%endif

mkdir -p %{_sharedstatedir}/xhelix %{_localstatedir}/log/xhelix %{_rundir}/xhelix
chown xhelix:xhelix %{_sharedstatedir}/xhelix %{_localstatedir}/log/xhelix %{_rundir}/xhelix

echo "xhelix installed. Enable with: systemctl enable --now xhelix"

%preun
%systemd_preun xhelix.service

%postun
%systemd_postun_with_restart xhelix.service

%if %{with_selinux}
if [ "$1" -eq 0 ] && command -v semodule >/dev/null 2>&1; then
    semodule -r xhelix 2>/dev/null || true
fi
%endif

%files
%license LICENSE
%doc README.md CHANGELOG.md docs/
%{_bindir}/xhelix
%{_bindir}/xhelixctl
%{_bindir}/xhelix-verify
%{_unitdir}/xhelix.service
%config(noreplace) %{_sysconfdir}/xhelix/xhelix.yaml
%dir %{_sysconfdir}/xhelix
%dir %{_sysconfdir}/xhelix/rules.d
%dir %{_sysconfdir}/xhelix/suricata-rules.d
%attr(0750,xhelix,xhelix) %dir %{_sharedstatedir}/xhelix
%attr(0750,xhelix,xhelix) %dir %{_localstatedir}/log/xhelix
%attr(0750,xhelix,xhelix) %dir %{_rundir}/xhelix
%if %{with_selinux}
%{_datadir}/selinux/packages/xhelix.te
%endif

%changelog
* Fri May 01 2026 xhelix authors <maintainers@xhelix.dev> - 0.0.2-1
- Phase 1-8: eBPF, FIM, decoys, NetIDS, identity, correlation,
  memory, enforcement, forensics
- SELinux policy module
- 33 bundled detection rules

* Wed Apr 30 2026 xhelix authors <maintainers@xhelix.dev> - 0.0.1-1
- Phase 0 bootstrap release
