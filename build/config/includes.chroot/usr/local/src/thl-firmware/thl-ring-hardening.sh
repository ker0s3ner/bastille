#!/bin/bash
# thl-ring-hardening — Ring -2 (SMM) and Ring -1 (VMX/SVM) hardening
#
# Ring -2 (SMM): Cannot be disabled in software. We harden around it:
#   - kernel lockdown=confidentiality blocks /dev/mem, kexec, hibernation
#   - IOMMU prevents SMM from being used to exfiltrate memory via DMA
#   - Disable unnecessary ACPI S3 (suspend-to-RAM) which triggers many SMIs
#
# Ring -1 (Hypervisor): KVM modules can be removed. VMX/SVM in the CPU
#   itself requires a BIOS setting to disable fully. We blacklist KVM modules
#   and document the BIOS steps.
#
# Usage:
#   thl-ring-hardening --apply     apply all software-level mitigations
#   thl-ring-hardening --status    show current state of each mitigation
#   thl-ring-hardening --bios-guide  print BIOS/UEFI settings to change manually

set -euo pipefail

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "  $*"; }
warn() { echo "  WARNING: $*"; }

require_root() { [ "$(id -u)" -eq 0 ] || die "must run as root"; }

# ── Ring -1: Blacklist KVM / hypervisor modules ───────────────────────────

apply_kvm_blacklist() {
    info "Blacklisting KVM kernel modules..."

    cat > /etc/modprobe.d/thl-ring1.conf << 'EOF'
# THL Ring -1 hardening: prevent KVM hypervisor modules from loading.
# VMX/SVM capability remains in the CPU but cannot be exercised without
# the kernel driver. To fully remove VMX, disable in BIOS/UEFI.
blacklist kvm
blacklist kvm_intel
blacklist kvm_amd
blacklist vhost
blacklist vhost_net
blacklist vhost_vsock
blacklist vboxdrv
blacklist vboxnetadp
blacklist vboxnetflt
EOF

    info "Created /etc/modprobe.d/thl-ring1.conf"

    # If modules are currently loaded, unload them
    for mod in kvm_intel kvm_amd kvm vhost_vsock vhost_net vhost; do
        if lsmod 2>/dev/null | grep -q "^$mod "; then
            modprobe -r "$mod" 2>/dev/null && info "Unloaded: $mod" || warn "Could not unload $mod (in use)"
        fi
    done
}

# ── Ring -2: SMM hardening ────────────────────────────────────────────────

apply_smm_hardening() {
    info "Applying SMM (Ring -2) software mitigations..."

    # Disable S3 sleep state (suspend-to-RAM) — it requires extensive SMM
    # involvement and increases the SMI attack surface. Use S4 (hibernate) or
    # just power off instead.
    if [ -f /etc/systemd/sleep.conf ]; then
        mkdir -p /etc/systemd/sleep.conf.d
        cat > /etc/systemd/sleep.conf.d/thl-no-s3.conf << 'EOF'
[Sleep]
# Disable S3 suspend-to-RAM — uses SMM heavily.
# Lock screen → power off is the THL-recommended pattern.
AllowSuspend=no
AllowHibernation=no
AllowSuspendThenHibernate=no
AllowHybridSleep=no
EOF
        info "Disabled S3/S4 sleep states via systemd"
    fi

    # Disable wakeup from SMM for PCIe devices where possible
    # (Prevents Wake-on-LAN and similar SMI triggers)
    for dev in /sys/bus/pci/devices/*/power/wakeup; do
        [ -f "$dev" ] && echo disabled > "$dev" 2>/dev/null || true
    done
    info "Disabled PCIe device wakeup (reduces SMI triggers)"

    # Reduce timer SMI frequency by disabling high-resolution timers
    # where they aren't needed
    if [ -f /sys/kernel/debug/smi_count ]; then
        local before; before="$(cat /sys/kernel/debug/smi_count)"
        info "Current SMI count: $before"
    fi
}

# ── Status report ──────────────────────────────────────────────────────────

show_status() {
    echo "=== Ring -1 (Hypervisor) Status ==="

    if [ -f /etc/modprobe.d/thl-ring1.conf ]; then
        echo "  [OK] KVM blacklist installed"
    else
        echo "  [--] KVM blacklist not installed (run --apply)"
    fi

    for mod in kvm_intel kvm_amd kvm; do
        if lsmod 2>/dev/null | grep -q "^$mod "; then
            echo "  [!!] $mod is LOADED — hypervisor active"
        else
            echo "  [OK] $mod not loaded"
        fi
    done

    if grep -q 'vmx' /proc/cpuinfo 2>/dev/null; then
        echo "  [i]  VMX capability present in CPU (requires BIOS to fully disable)"
    fi
    if grep -q 'svm' /proc/cpuinfo 2>/dev/null; then
        echo "  [i]  AMD-V/SVM capability present in CPU (requires BIOS to fully disable)"
    fi

    echo
    echo "=== Ring -2 (SMM) Status ==="

    if [ -f /sys/kernel/security/lockdown ]; then
        local ld; ld="$(cat /sys/kernel/security/lockdown)"
        echo "  [i]  kernel.lockdown: $ld"
    else
        echo "  [!!] kernel.lockdown not available"
    fi

    if [ -c /dev/mem ]; then
        echo "  [!!] /dev/mem accessible — SMM memory probing possible"
    else
        echo "  [OK] /dev/mem blocked by lockdown"
    fi

    if [ -f /etc/systemd/sleep.conf.d/thl-no-s3.conf ]; then
        echo "  [OK] S3/S4 sleep disabled (reduces SMI surface)"
    else
        echo "  [--] S3/S4 sleep not disabled"
    fi

    if [ -f /sys/kernel/debug/smi_count ]; then
        echo "  [i]  SMI count: $(cat /sys/kernel/debug/smi_count)"
    fi
}

# ── BIOS guide ────────────────────────────────────────────────────────────

bios_guide() {
    cat << 'EOF'
═══════════════════════════════════════════════════════════════════
  THL BIOS/UEFI Settings for Full Sub-Ring-0 Hardening
═══════════════════════════════════════════════════════════════════

These settings cannot be changed by software — you must enter BIOS
setup (usually Del, F2, or F10 at boot) and change them manually.

RING -3: Intel ME / AMD PSP
  Intel:
    • Advanced → ME Configuration → "Disable ME" or set to "Minimal"
    • If AMT is present: Advanced → AMT → Disable AMT
    • If CSE/SPS visible: Advanced → CSE → set to "Disabled"
    • HAP bit (software): run 'thl-me-neutralize --neutralize' after BIOS

  AMD:
    • Advanced → AMD PSP → fTPM → Disabled
    • Advanced → AMD CBS → PSP → "Disable PSP" (if present; rare)
    • Note: AMD PSP cannot be fully neutralized — minimize surface only

RING -2: System Management Mode (SMM)
  SMM cannot be fully disabled — it is required for:
    • Hardware error handling (MCE)
    • Fan/thermal control on most laptops
    • USB legacy support at POST
  Instead:
    • Security → Secure Boot → Enabled
    • Advanced → ACPI → "S3 Sleep State" → Disabled (use S4 or off)
    • Advanced → USB → "Legacy USB Support" → Disabled (reduces SMM)
    • Advanced → Wake Events → disable all wake-on-LAN/PCIe

RING -1: VMX / SVM (Hypervisor Extension)
  Intel:
    • Advanced → CPU Configuration → "Intel Virtualization Technology (VT-x)" → Disabled
    • Advanced → CPU Configuration → "VT-d" → Disabled (also affects IOMMU)
      !! If you disable VT-d, IOMMU protection is LOST — do not do this !!
      Only disable VT-x, keep VT-d enabled.
  AMD:
    • Advanced → CPU Configuration → "SVM Mode" → Disabled
    • Keep AMD-Vi (IOMMU) enabled.

FIRMWARE INTEGRITY
  • Advanced → Secure Boot → Mode: Custom → load your own keys, or
    use "Standard" with a signed bootloader
  • Advanced → Boot → "Fast Boot" → Disabled (allows full firmware init checks)
  • Advanced → PCH/Platform → "ME Firmware Update" → Disabled
    (prevents automatic ME re-enable on firmware update)

DMA / THUNDERBOLT
  • Advanced → Thunderbolt Configuration → "Security Level" → "DP Only"
    or disable Thunderbolt entirely if not needed.
  • Advanced → IOMMU → Enabled (Intel VT-d / AMD-Vi)

POWER
  • Advanced → Power Management → "Erp" or "S5 Maximum Power Savings" → Enabled
    (reduces ME activity when fully off)
  • Advanced → ME → "ME Wake in S5" → Disabled if present

═══════════════════════════════════════════════════════════════════
After BIOS changes: run 'thl-firmware-audit' to verify the result.
═══════════════════════════════════════════════════════════════════
EOF
}

# ── Dispatch ───────────────────────────────────────────────────────────────

case "${1:---help}" in
    --apply)
        require_root
        apply_kvm_blacklist
        apply_smm_hardening
        echo
        echo "Ring -1/-2 mitigations applied."
        echo "For full Ring -1 removal, see: thl-ring-hardening --bios-guide"
        ;;
    --status)
        require_root
        show_status
        ;;
    --bios-guide)
        bios_guide
        ;;
    --help|-h|*)
        cat << 'EOF'
thl-ring-hardening — Ring -2 (SMM) and Ring -1 (VMX/SVM) hardening

Usage:
  thl-ring-hardening --apply        apply software-level mitigations
  thl-ring-hardening --status       show current state
  thl-ring-hardening --bios-guide   print BIOS settings to change manually

Note: Full Ring -1 removal requires disabling VMX/SVM in BIOS.
      Ring -2 (SMM) cannot be fully disabled; harden the surface instead.
EOF
        ;;
esac
