#!/bin/bash
# THL duress action: emergency-poweroff
#
# Triggered by a duress PIN with action=power.
# Waits a short moment (so PAM can return cleanly to the caller and
# the screen doesn't freeze mid-animation, which would be a tell),
# then immediately cuts power without a clean shutdown.
# This gives the OS no time to write anything to disk.

set -euo pipefail

logger -t "thl-duress-power" "DURESS POWEROFF initiated"

# 1-second delay so PAM conversation completes and greetd shows
# the normal unlock animation before the screen goes dark
sleep 1

# Sync nothing — we want an abrupt power-off, not a clean unmount.
# If LUKS is set up, keys are only in RAM and are lost on power-off.
echo o > /proc/sysrq-trigger 2>/dev/null \
    || systemctl poweroff --force --force \
    || halt -f -p
