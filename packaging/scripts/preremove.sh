#!/bin/sh
# preremove — stop and disable the units before the files disappear.
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now machine-krb-service.timer 2>/dev/null || true
    systemctl stop machine-krb-service.service 2>/dev/null || true
fi
exit 0
