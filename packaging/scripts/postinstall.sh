#!/bin/sh
# postinstall — runs on rpm (Fedora/RHEL), deb (Debian/Ubuntu) and apk (Alpine).
set -e

# Dedicated group whose members may read the armor ticket. Membership is
# equivalent to holding the machine account's TGT — keep it tight.
if command -v groupadd >/dev/null 2>&1; then
    groupadd -rf machine-krb 2>/dev/null || groupadd -r machine-krb 2>/dev/null || true
elif command -v addgroup >/dev/null 2>&1; then
    addgroup -S machine-krb 2>/dev/null || true
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemd-tmpfiles --create machine-krb.conf 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    echo "machine-krb-service installed."
    echo "  enable:    systemctl enable --now machine-krb-service.timer"
    echo "  grant use: usermod -aG machine-krb <user>   (re-login applies)"
    echo "  configure: /etc/machine-krb/config.yaml"
else
    # Non-systemd (Alpine): hourly refresh via busybox crond.
    echo "machine-krb-service installed (non-systemd)."
    echo "  hourly refresh: /etc/periodic/hourly/machine-krb-service (busybox crond)"
    echo "  grant use:      addgroup <user> machine-krb"
    echo "  configure:      /etc/machine-krb/config.yaml"
fi
exit 0
