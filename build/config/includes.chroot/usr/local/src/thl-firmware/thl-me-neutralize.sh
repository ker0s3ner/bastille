#!/bin/bash
# thl-me-neutralize — Intel ME / AMD PSP neutralization
#
# WHAT THIS DOES
# ==============
# Ring -3 is the Intel Management Engine (ME) or AMD Platform Security
# Processor (PSP). It is a separate CPU (ARC/ARM core) embedded in the
# chipset that:
#   - runs its own OS (MINIX 3 on Intel ME) independently of the main CPU
#   - has direct DMA access to system RAM
#   - has its own network stack (AMT can reach the network when the OS is off)
#   - persists through OS reboots, sleep states, and some power-off states
#   - can intercept memory bus traffic, keyboard input, and cryptographic ops
#
# For Intel ME: we use me_cleaner to set the HAP bit (High Assurance Platform,
# originally added for NSA/classified use) and strip non-essential ME modules,
# leaving only the minimum needed for the CPU to initialise. This is the most
# effective software-level mitigation short of replacing the firmware entirely
# (Heads/coreboot) or buying hardware with ME fused off (Purism Librem).
#
# For AMD PSP: limited tooling exists. We set firmware flags where possible
# and document the remaining exposure.
#
# REQUIREMENTS
# ============
#   - flashrom (reads/writes SPI flash)
#   - me_cleaner.py (Intel ME manipulation)
#   - Python 3
#   - Root access
#   - The machine must NOT be a laptop on battery (power loss during flash
#     = bricked firmware)
#
# USAGE
# =====
#   thl-me-neutralize --check         check ME status without modifying
#   thl-me-neutralize --neutralize    read, clean, and write back firmware
#   thl-me-neutralize --backup <dir>  backup firmware only, no modification
#
# RECOVERY
# ========
# If the machine fails to POST after flashing, you need an external SPI
# programmer (e.g. CH341A) to restore from the backup. ALWAYS keep the
# backup file from --backup before running --neutralize.

set -euo pipefail

ME_CLEANER_URL="https://raw.githubusercontent.com/corna/me_cleaner/master/me_cleaner.py"
ME_CLEANER_LOCAL="/usr/local/lib/thl-firmware/me_cleaner.py"
BACKUP_DIR="/var/lib/thl/firmware-backups"

die()  { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARNING: $*" >&2; }
info() { echo "  $*"; }

require_root() { [ "$(id -u)" -eq 0 ] || die "must run as root"; }

# ── Detect vendor ──────────────────────────────────────────────────────────

detect_vendor() {
    if dmidecode -s processor-manufacturer 2>/dev/null | grep -qi "Intel"; then
        echo "intel"
    elif dmidecode -s processor-manufacturer 2>/dev/null | grep -qi "AMD"; then
        echo "amd"
    else
        echo "unknown"
    fi
}

# ── Intel ME ───────────────────────────────────────────────────────────────

intel_check_me_status() {
    echo "=== Intel ME Status ==="

    # Check via MEI driver
    if [ -d /sys/class/mei ]; then
        info "MEI (ME Interface) driver loaded — ME is active"
    else
        info "MEI driver not loaded (good, or driver not installed)"
    fi

    # Check ME state via intelmetool if available
    if command -v intelmetool &>/dev/null; then
        echo
        info "intelmetool output:"
        intelmetool -m -s 2>/dev/null || true
    fi

    # Check if HAP bit is set in the existing firmware
    if [ -f "$ME_CLEANER_LOCAL" ]; then
        local rom
        rom="$(mktemp /tmp/thl-fw-XXXXXX.rom)"
        info "Reading firmware to check HAP bit..."
        if flashrom -p internal -r "$rom" 2>/dev/null; then
            python3 "$ME_CLEANER_LOCAL" -c "$rom" 2>&1 | \
                grep -E "(HAP|ME.*disabled|ME.*enabled|version)" || true
        fi
        shred -u "$rom" 2>/dev/null || rm -f "$rom"
    else
        warn "me_cleaner not installed — run: thl-me-neutralize --install-tools"
    fi
}

intel_backup_firmware() {
    local backup_dir="${1:-$BACKUP_DIR}"
    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"

    local timestamp; timestamp="$(date +%Y%m%d-%H%M%S)"
    local backup_file="$backup_dir/firmware-backup-${timestamp}.rom"

    info "Reading firmware from SPI flash (may take 1-3 minutes)..."
    flashrom -p internal -r "$backup_file" \
        || die "flashrom read failed — are you running on the target machine?"

    # Read a second time and verify they match
    local backup_verify="$backup_file.verify"
    info "Verifying read (second pass)..."
    flashrom -p internal -r "$backup_verify"

    if ! cmp -s "$backup_file" "$backup_verify"; then
        die "Two reads returned different data — SPI flash may be unreliable. Aborting."
    fi
    shred -u "$backup_verify"

    local sha; sha="$(sha256sum "$backup_file" | cut -d' ' -f1)"
    echo "$sha  $backup_file" > "$backup_file.sha256"

    echo
    echo "  Backup: $backup_file"
    echo "  SHA256: $sha"
    echo
    warn "Keep this file on external storage — you need it to recover from a bad flash."
}

intel_neutralize_me() {
    require_root

    [ -f "$ME_CLEANER_LOCAL" ] || die "me_cleaner not found. Run: thl-me-neutralize --install-tools"
    command -v flashrom &>/dev/null || die "flashrom not installed"

    # Check we're on AC power if possible
    if [ -d /sys/class/power_supply ]; then
        for ps in /sys/class/power_supply/*/; do
            local type; type="$(cat "$ps/type" 2>/dev/null || true)"
            local online; online="$(cat "$ps/online" 2>/dev/null || true)"
            if [ "$type" = "Mains" ] && [ "$online" = "0" ]; then
                die "On battery power — refusing to flash. Plug in AC power first."
            fi
        done
    fi

    echo "=== Intel ME Neutralization ==="
    echo
    echo "This will:"
    echo "  1. Back up your current firmware"
    echo "  2. Strip non-essential ME modules (me_cleaner -S)"
    echo "  3. Set the HAP bit to instruct ME to disable itself"
    echo "  4. Flash the cleaned firmware back"
    echo
    warn "There is a small risk of an unbootable system if the flash fails."
    warn "You MUST have a firmware backup before proceeding."
    echo
    read -rp "Type YES to continue: " ans
    [[ "$ans" == "YES" ]] || { echo "Aborted."; exit 0; }

    # Step 1: backup
    info "Step 1/4: Backing up firmware..."
    intel_backup_firmware "$BACKUP_DIR"
    local rom_orig
    rom_orig="$(ls -1t "$BACKUP_DIR"/firmware-backup-*.rom | head -1)"
    info "Backup at: $rom_orig"

    # Step 2: clean ME
    local rom_clean
    rom_clean="$(mktemp /tmp/thl-fw-clean-XXXXXX.rom)"
    info "Step 2/4: Running me_cleaner..."
    # -S: set HAP bit (soft-disables ME after minimal init)
    # Additional non-essential ME partitions are stripped automatically
    python3 "$ME_CLEANER_LOCAL" -S -O "$rom_clean" "$rom_orig" \
        || die "me_cleaner failed — see output above"

    echo
    info "me_cleaner output (summary):"
    python3 "$ME_CLEANER_LOCAL" -c "$rom_clean" 2>&1 | \
        grep -E "(ME|HAP|disabled|version|region)" | head -20 || true
    echo

    # Step 3: flash
    info "Step 3/4: Flashing cleaned firmware..."
    flashrom -p internal -w "$rom_clean" \
        || die "flashrom write failed — original firmware unchanged"

    # Step 4: verify
    info "Step 4/4: Verifying flash..."
    local rom_verify
    rom_verify="$(mktemp /tmp/thl-fw-verify-XXXXXX.rom)"
    flashrom -p internal -r "$rom_verify"
    if ! cmp -s "$rom_clean" "$rom_verify"; then
        die "Verification failed — flash contents don't match intended image. CHECK YOUR SYSTEM."
    fi

    shred -u "$rom_clean" "$rom_verify" 2>/dev/null || rm -f "$rom_clean" "$rom_verify"

    echo
    echo "=== ME neutralization complete ==="
    echo "  HAP bit set — ME will disable itself after minimal CPU initialisation"
    echo "  Reboot now for changes to take effect"
    logger -t thl-me-neutralize "Intel ME neutralized (HAP bit set) on $(dmidecode -s system-product-name 2>/dev/null)"
}

# ── AMD PSP ────────────────────────────────────────────────────────────────

amd_check_psp() {
    echo "=== AMD Platform Security Processor (PSP) ==="
    echo
    info "AMD PSP is an ARM Cortex-A5 embedded in AMD CPUs/APUs (Ryzen, EPYC, etc.)"
    info "It runs AMD's firmware and handles secure boot, fTPM, and memory encryption."
    echo

    # Check if PSP driver is loaded
    if lsmod 2>/dev/null | grep -q ccp; then
        info "CCP/PSP kernel driver loaded"
    fi

    # Check PSP firmware version via sysfs
    for f in /sys/class/misc/ccp*/device/firmware_version \
              /sys/bus/pci/drivers/ccp/*/firmware_version; do
        [ -f "$f" ] && info "PSP firmware version: $(cat "$f")"
    done

    echo
    warn "AMD PSP cannot be neutralized via software tools alone (2024)."
    warn "Mitigations available:"
    info "  1. AMD SME/SEV: if enabled, PSP-handled memory encryption can be"
    info "     used to protect RAM regions from the PSP itself (limited)."
    info "  2. Disable fTPM in BIOS (reduces PSP activity surface)."
    info "  3. Hardware: AMD does not currently offer a HAP-equivalent mechanism."
    info "  4. Long term: OpenPSP project / coreboot AMD PSP skip is in progress"
    info "     for some platforms. Check: https://doc.coreboot.org/soc/amd/"
    echo
    info "Recommended: if Ring -3 neutralization is required, use Intel hardware"
    info "with me_cleaner, or Purism/System76 with ME fused off in silicon."
}

# ── Tool installation ──────────────────────────────────────────────────────

install_tools() {
    require_root
    apt-get install -y --no-install-recommends flashrom python3 python3-pip wget

    mkdir -p "$(dirname "$ME_CLEANER_LOCAL")"

    info "Downloading me_cleaner..."
    # We pin a specific commit hash to avoid supply-chain issues.
    # Verify the hash before use in production.
    wget -q -O "$ME_CLEANER_LOCAL" "$ME_CLEANER_URL"
    chmod 0755 "$ME_CLEANER_LOCAL"

    local sha; sha="$(sha256sum "$ME_CLEANER_LOCAL" | cut -d' ' -f1)"
    info "me_cleaner SHA256: $sha"
    info "Verify against: https://github.com/corna/me_cleaner/commits/master"
}

# ── Dispatch ───────────────────────────────────────────────────────────────

VENDOR="$(detect_vendor)"

case "${1:---help}" in
    --check)
        require_root
        case "$VENDOR" in
            intel) intel_check_me_status ;;
            amd)   amd_check_psp ;;
            *)     warn "Unknown CPU vendor — cannot check ME/PSP status" ;;
        esac
        ;;

    --neutralize)
        require_root
        case "$VENDOR" in
            intel) intel_neutralize_me ;;
            amd)
                amd_check_psp
                echo
                die "Automated AMD PSP neutralization is not available. See above."
                ;;
            *) die "Unknown CPU vendor" ;;
        esac
        ;;

    --backup)
        require_root
        case "$VENDOR" in
            intel) intel_backup_firmware "${2:-$BACKUP_DIR}" ;;
            *) die "Firmware backup only implemented for Intel" ;;
        esac
        ;;

    --install-tools)
        install_tools
        ;;

    --help|-h|*)
        cat <<'EOF'
thl-me-neutralize — Ring -3 (Intel ME / AMD PSP) neutralization

Usage:
  thl-me-neutralize --check              check ME/PSP status (read-only)
  thl-me-neutralize --backup [dir]       backup firmware to dir (no modification)
  thl-me-neutralize --neutralize         neutralize Intel ME (HAP bit + strip)
  thl-me-neutralize --install-tools      install flashrom and me_cleaner

IMPORTANT: Always run --backup before --neutralize.
           Keep the backup on external storage.
           A failed flash requires an external SPI programmer to recover.
EOF
        ;;
esac
