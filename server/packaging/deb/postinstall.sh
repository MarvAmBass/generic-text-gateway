#!/bin/sh
set -e
if ! getent group gtg >/dev/null; then
    groupadd --system gtg
fi
if ! getent passwd gtg >/dev/null; then
    useradd --system --gid gtg --groups dialout --home-dir /var/lib/generic-text-gateway \
            --shell /usr/sbin/nologin gtg
fi
mkdir -p /var/lib/generic-text-gateway
chown gtg:gtg /var/lib/generic-text-gateway
chmod 750 /var/lib/generic-text-gateway
systemctl daemon-reload 2>/dev/null || true
exit 0
