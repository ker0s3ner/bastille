#!/bin/bash
# fake-wipe — duress action: appears to wipe but switches to a decoy profile
#
# What the coercer sees:
#   - Screen goes black briefly
#   - System comes back to a clean-looking desktop
#   - No files, no messages, no traces of the real data
#
# What actually happens:
#   - Real profile is unmounted and LUKS container is closed (real data safe)
#   - A pre-configured decoy profile is mounted instead
#   - WireGuard reconnects with the decoy profile's config (if any)
#   - The transition looks like a normal login
#
# Setup:
#   1. Create a decoy profile: thl-profile create decoy
#   2. Add some plausible-looking files to it
#   3. Set DECOY_PROFILE in /etc/thl/duress.conf

set -euo pipefail

DECOY_PROFILE="${THL_DECOY_PROFILE:-decoy}"
LOCK_CMD="/usr/local/sbin/thl-lock"

# Close the real profile silently
thl-profile lock 2>/dev/null || true

# Evict LUKS keys (real data is now inaccessible even if device is seized)
/usr/local/sbin/thl-keyguard evict 2>/dev/null || true

# Short pause — decoy switch should look natural
sleep 0.3

# Switch to decoy profile if it exists
if thl-profile list 2>/dev/null | grep -q "^$DECOY_PROFILE$"; then
    thl-profile switch "$DECOY_PROFILE" 2>/dev/null || true
fi

# Lock screen — coercer sees a normal login prompt
# When they unlock with the "normal" PIN, they get the decoy profile
exec "$LOCK_CMD"
