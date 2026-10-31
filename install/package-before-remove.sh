#!/bin/sh
set -e
# Stop and disable the service on removal, not on upgrade: dpkg passes `upgrade`,
# rpm the count of versions left (1 or more), pacman runs this only on removal.
case $1 in
    upgrade | failed-upgrade | [1-9]) exit 0 ;;
esac
if [ -d /run/systemd/system ]; then
    systemctl --no-reload disable --now honk-core.service || true
fi
