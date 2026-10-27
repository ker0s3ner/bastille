#!/bin/bash
# thl-unlock-initramfs — called from initramfs to unlock the root LUKS volume.
#
# Install this as a cryptsetup-initramfs keyscript:
#   /etc/crypttab:
#     root UUID=<uuid> none luks,keyscript=/usr/local/sbin/thl-unlock-initramfs.sh
#
# The keyscript is exec'd by cryptsetup-initramfs; it receives the device
# as $CRYPTTAB_SOURCE and must write the key to stdout.

set -euo pipefail

KEYGUARD=/usr/local/sbin/thl-keyguard
DEVICE="${CRYPTTAB_SOURCE:-/dev/sda3}"

exec "$KEYGUARD" unlock --device "$DEVICE"
