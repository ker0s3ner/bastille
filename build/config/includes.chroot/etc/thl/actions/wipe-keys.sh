#!/bin/bash
# THL duress action: wipe-keys
#
# Called by pam_thl_duress when a wipe duress PIN is entered.
# Runs as root in a detached background process — the PAM conversation
# has already returned PAM_SUCCESS so the coercer sees a normal login.
#
# What this destroys:
#   1. WireGuard private key (in-memory and on disk)
#   2. GPG private keyring
#   3. /etc/thl/duress.conf (so duress config cannot be read)
#   4. Any THL profile keys in /var/lib/thl/profiles/
#
# After wiping, the session continues normally so the coercer
# has access only to a key-less shell — nothing to hand over.
#
# To customise: add/remove paths from SENSITIVE_PATHS below.

set -euo pipefail

LOG_TAG="thl-duress-wipe"

log() {
    logger -t "$LOG_TAG" "$*"
}

# Overwrite a file with random data before unlinking.
shred_file() {
    local path="$1"
    if [ -f "$path" ]; then
        shred -u -z -n 3 "$path" 2>/dev/null || {
            # Fallback if shred is unavailable
            dd if=/dev/urandom of="$path" bs=4096 count=1 conv=notrunc 2>/dev/null
            rm -f "$path"
        }
        log "shredded: $path"
    fi
}

# Overwrite every regular file under a directory, then remove it.
shred_dir() {
    local dir="$1"
    if [ -d "$dir" ]; then
        find "$dir" -type f -exec shred -u -z -n 3 {} \; 2>/dev/null || true
        rm -rf "$dir"
        log "shredded dir: $dir"
    fi
}

log "DURESS WIPE initiated"

# 1. WireGuard key (config contains the private key in plaintext)
shred_file /etc/wireguard/wg0.conf

# Bring down the interface so the in-memory key is also gone
if command -v wg >/dev/null 2>&1; then
    ip link delete wg0 2>/dev/null || true
fi

# 2. GPG private keyring for all users
for homedir in /root /home/*; do
    shred_dir "$homedir/.gnupg/private-keys-v1.d"
    shred_file "$homedir/.gnupg/secring.gpg"  # legacy
done

# 3. THL duress config (contains PIN hashes)
shred_file /etc/thl/duress.conf

# 4. THL profile key material
shred_dir /var/lib/thl/profiles

# 5. Any ephemeral secrets in tmpfs
shred_dir /run/thl

log "DURESS WIPE complete"

# Do NOT exit with error — session continues normally
exit 0
