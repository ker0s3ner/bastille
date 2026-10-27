#!/bin/bash
# full-wipe — duress action: destroy everything and power off
#
# Order of operations is critical:
#   1. Evict LUKS RAM half first (device becomes BFU immediately)
#   2. Kill the VPN and delete its key
#   3. Shred all profile data, GnuPG keys, SSH keys
#   4. Overwrite LUKS headers on all THL profile containers
#   5. Corrupt the duress config itself
#   6. Fill remaining RAM with random bytes (overwrite any lingering keys)
#   7. Abrupt poweroff via sysrq (no disk flush — avoids writing data)
#
# This is the "nuclear option" — all data is gone after this.
# Recovery is impossible without the original LUKS passphrases.
#
# Triggered by a duress PIN in pam_thl_duress.so.

set -euo pipefail

KEYGUARD="/usr/local/sbin/thl-keyguard"
WG_CONF="/etc/wireguard/wg0.conf"
GNUPG_DIRS=(/home/user/.gnupg /root/.gnupg)
SSH_DIRS=(/home/user/.ssh /root/.ssh)
PROFILE_DIR="/var/lib/thl/profiles"
DURESS_CONF="/etc/thl/duress.conf"
KEYSTORE_DIR="/etc/thl/keystore"
PERSIST_DIR="/run/thl"
THL_CERTS="/etc/thl"

shred_file() {
    [ -f "$1" ] && shred -u -z -n 3 "$1" 2>/dev/null || true
}
shred_dir() {
    [ -d "$1" ] && find "$1" -type f -exec shred -u -z -n 3 {} + 2>/dev/null || true
    [ -d "$1" ] && rm -rf "$1" 2>/dev/null || true
}

# ── Step 1: Evict LUKS RAM half (device → BFU) ───────────────────────────
"$KEYGUARD" evict 2>/dev/null || true

# ── Step 2: Kill VPN ─────────────────────────────────────────────────────
ip link delete wg0 2>/dev/null || true
shred_file "$WG_CONF"

# ── Step 3: Shred all key material ────────────────────────────────────────
for d in "${GNUPG_DIRS[@]}"; do shred_dir "$d"; done
for d in "${SSH_DIRS[@]}";   do shred_dir "$d"; done

# ── Step 4: Overwrite LUKS headers on profile containers ──────────────────
for img in "$PROFILE_DIR"/*.img; do
    [ -f "$img" ] || continue
    # LUKS2 header occupies the first 4 MB
    dd if=/dev/urandom of="$img" bs=4M count=1 conv=notrunc 2>/dev/null || true
    shred -u -z -n 1 "$img" 2>/dev/null || true
done

# ── Step 5: Destroy keystore (LUKS split-key storage) ─────────────────────
shred_dir "$KEYSTORE_DIR"

# ── Step 6: Corrupt duress config ─────────────────────────────────────────
shred_file "$DURESS_CONF"

# ── Step 7: Clear /run/thl (runtime key material) ─────────────────────────
shred_dir "$PERSIST_DIR"

# ── Step 8: RAM overwrite ─────────────────────────────────────────────────
# Write random bytes to a tmpfs file to overwrite as many RAM pages as possible.
# This pushes key material out of the page cache.
# We write until out of memory, then delete.
(dd if=/dev/urandom of=/dev/shm/thl-wipe-ram bs=1M 2>/dev/null || true)
rm -f /dev/shm/thl-wipe-ram 2>/dev/null || true

# ── Step 9: Abrupt poweroff via sysrq ────────────────────────────────────
# echo o does immediate poweroff with NO disk flush.
# This is intentional — we don't want a clean shutdown that might
# write journal entries or flush dirty buffers.
sleep 1
echo o > /proc/sysrq-trigger

# Fallback if sysrq unavailable
poweroff -f
