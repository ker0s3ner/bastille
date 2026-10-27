#!/bin/bash
# THL duress action: decoy profile switch
#
# Called with the target profile name as $1.
# Arranges for the next login (or the current session startup) to
# land in the named decoy profile instead of the real one.
# The decoy profile must be pre-configured via thl-profile.

set -euo pipefail

PROFILE="${1:-decoy}"
NEXT_PROFILE_FILE="/run/thl/next-profile"

logger -t "thl-duress-decoy" "DURESS DECOY: switching to profile '$PROFILE'"

mkdir -p /run/thl
echo "$PROFILE" > "$NEXT_PROFILE_FILE"

# Signal the profile switcher to act on next session init.
# thl-profile-switch reads this file at session start.
# (Implemented in src/thl-profile — upcoming component)

exit 0
