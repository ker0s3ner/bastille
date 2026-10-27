#!/bin/bash
# thl-firmware-audit — enumerate and assess all sub-ring-0 attack surfaces
#
# Checks Ring -3 (ME/PSP), Ring -2 (SMM), Ring -1 (hypervisor/VMX),
# firmware integrity, and IOMMU/DMA protection status.
# Produces a structured report with PASS/WARN/FAIL/INFO ratings.
#
# Usage: thl-firmware-audit [--json] [--quiet]

set -euo pipefail

JSON_MODE=false
QUIET_MODE=false
PASS=0; WARN=0; FAIL=0

for arg in "$@"; do
    case "$arg" in
        --json)  JSON_MODE=true ;;
        --quiet) QUIET_MODE=true ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "ERROR: must run as root" >&2; exit 1; }

# ── Output helpers ─────────────────────────────────────────────────────────

declare -a FINDINGS=()

emit() {
    local level="$1"; local msg="$2"
    case "$level" in
        PASS) ((PASS++)) ;;
        WARN) ((WARN++)) ;;
        FAIL) ((FAIL++)) ;;
    esac
    FINDINGS+=("{\"level\":\"$level\",\"msg\":$(printf '%s' "$msg" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}")
    if ! $QUIET_MODE && ! $JSON_MODE; then
        case "$level" in
            PASS) printf "  \033[32m[PASS]\033[0m %s\n" "$msg" ;;
            WARN) printf "  \033[33m[WARN]\033[0m %s\n" "$msg" ;;
            FAIL) printf "  \033[31m[FAIL]\033[0m %s\n" "$msg" ;;
            INFO) printf "  \033[36m[INFO]\033[0m %s\n" "$msg" ;;
        esac
    fi
}

section() {
    $JSON_MODE || $QUIET_MODE || echo
    $JSON_MODE || $QUIET_MODE || echo "=== $* ==="
}

# ── Ring -3: Intel ME ──────────────────────────────────────────────────────

check_intel_me() {
    section "Ring -3: Intel Management Engine"

    # MEI driver presence (me_i915, mei_me, mei)
    if lsmod 2>/dev/null | grep -qE '^mei[_ ]'; then
        emit WARN "MEI kernel driver loaded — ME is active and has a host interface"
    else
        emit PASS "MEI kernel driver not loaded — no host↔ME interface active"
    fi

    # AMT (Active Management Technology) network port
    if ss -tlnp 2>/dev/null | grep -q ':16992\|:16993\|:16994\|:16995'; then
        emit FAIL "AMT network ports open (16992-16995) — ME has network presence"
    else
        emit PASS "AMT network ports not detected"
    fi

    # Check HAP bit via me_cleaner if available
    local mecleaner="/usr/local/lib/thl-firmware/me_cleaner.py"
    if [ -f "$mecleaner" ] && command -v flashrom &>/dev/null; then
        local rom; rom="$(mktemp /tmp/thl-audit-XXXXXX.rom)"
        if flashrom -p internal -r "$rom" 2>/dev/null; then
            local hap_out; hap_out="$(python3 "$mecleaner" -c "$rom" 2>&1 || true)"
            if echo "$hap_out" | grep -qi "HAP.*set\|disabled"; then
                emit PASS "Intel ME: HAP bit set — ME will self-disable after minimal init"
            elif echo "$hap_out" | grep -qi "HAP.*not set\|enabled"; then
                emit FAIL "Intel ME: HAP bit NOT set — ME is fully active"
            else
                emit WARN "Intel ME: could not determine HAP bit state from firmware"
            fi
        fi
        shred -u "$rom" 2>/dev/null || rm -f "$rom"
    else
        emit INFO "me_cleaner/flashrom not installed — cannot check HAP bit (run thl-me-neutralize --install-tools)"
    fi

    # PCH/ME version from DMI
    local me_ver; me_ver="$(dmidecode -t bios 2>/dev/null | grep -i 'firmware' | head -1 || true)"
    [ -n "$me_ver" ] && emit INFO "BIOS firmware: $me_ver"
}

# ── Ring -3: AMD PSP ───────────────────────────────────────────────────────

check_amd_psp() {
    section "Ring -3: AMD Platform Security Processor"

    if lsmod 2>/dev/null | grep -q '^ccp'; then
        emit WARN "CCP/PSP kernel driver loaded — PSP has a host interface"
    else
        emit PASS "CCP/PSP driver not loaded"
    fi

    # fTPM (PSP-backed TPM)
    if [ -d /sys/class/tpm ] && ls /sys/class/tpm/ 2>/dev/null | grep -q tpm; then
        local tpm_type; tpm_type="$(cat /sys/class/tpm/tpm0/device/description 2>/dev/null || echo 'unknown')"
        if echo "$tpm_type" | grep -qi "ftpm\|amd\|psp"; then
            emit WARN "AMD fTPM (PSP-backed) active — disable in BIOS to reduce PSP surface"
        else
            emit INFO "TPM present: $tpm_type"
        fi
    fi

    emit INFO "AMD PSP neutralization requires hardware or coreboot — no HAP equivalent available"
}

# ── Ring -2: System Management Mode ───────────────────────────────────────

check_smm() {
    section "Ring -2: System Management Mode (SMM)"

    # SMRAM lock: bit 3 of MCH_SMRAM (0x9d) should be set
    # Check via /dev/mem (only available without lockdown)
    if [ -c /dev/mem ]; then
        emit WARN "/dev/mem accessible — kernel lockdown not active (enables SMM probing)"
    else
        emit PASS "/dev/mem blocked — kernel lockdown preventing SMM memory access"
    fi

    # Check lockdown mode
    if [ -f /sys/kernel/security/lockdown ]; then
        local ld; ld="$(cat /sys/kernel/security/lockdown)"
        case "$ld" in
            *confidentiality*) emit PASS "kernel.lockdown=confidentiality — SMM/kexec/kcore blocked" ;;
            *integrity*)       emit WARN "kernel.lockdown=integrity — partial (kexec blocked but /dev/mem not)" ;;
            *none*)            emit FAIL "kernel.lockdown=none — no SMM/memory protection" ;;
            *)                 emit INFO "kernel.lockdown: $ld" ;;
        esac
    else
        emit WARN "kernel.lockdown not available — kernel may not have lockdown support"
    fi

    # SMI handler count via /sys/kernel/debug/acpi (can indicate attack surface)
    if [ -d /sys/kernel/debug/acpi ]; then
        local smi_count; smi_count="$(cat /sys/kernel/debug/acpi/sci_count 2>/dev/null || echo 'n/a')"
        emit INFO "ACPI SCI count: $smi_count (SMI handler activity indicator)"
    fi

    # Check if SMRAM_LOCK bit is set via MSR 0x9b (IA32_SMM_MONITOR_CTL) on Intel
    if [ -c /dev/cpu/0/msr ] && command -v rdmsr &>/dev/null; then
        local smm_ctl; smm_ctl="$(rdmsr -p 0 0x9b 2>/dev/null || echo 'n/a')"
        if [ "$smm_ctl" != "n/a" ]; then
            emit INFO "IA32_SMM_MONITOR_CTL (MSR 0x9b): 0x$smm_ctl"
        fi
    fi

    emit INFO "SMM cannot be fully disabled via software — rely on kernel lockdown + IOMMU"
}

# ── Ring -1: Hypervisor / VMX / SVM ───────────────────────────────────────

check_hypervisor() {
    section "Ring -1: Hypervisor (VMX/SVM)"

    # Check if we're running under a hypervisor
    local hypervisor_bit; hypervisor_bit="$(grep -c 'hypervisor' /proc/cpuinfo 2>/dev/null || echo 0)"
    if [ "$hypervisor_bit" -gt 0 ]; then
        local hv_vendor; hv_vendor="$(grep 'hypervisor_vendor\|^vendor' /proc/cpuinfo 2>/dev/null | head -1 || true)"
        emit WARN "Hypervisor present — running in a VM ($hv_vendor)"
    else
        emit PASS "No hypervisor detected — running on bare metal"
    fi

    # VMX (Intel VT-x) enabled in CPU
    if grep -q 'vmx' /proc/cpuinfo 2>/dev/null; then
        # Check if kvm_intel is loaded
        if lsmod 2>/dev/null | grep -q '^kvm_intel\|^kvm_amd'; then
            emit WARN "KVM hypervisor modules loaded — guest VMs could be created"
            emit INFO "To disable: modprobe -r kvm_intel kvm (or add to /etc/modprobe.d blacklist)"
        else
            emit PASS "KVM modules not loaded — VMX present in CPU but not exploitable via kernel"
        fi
        emit INFO "VMX capability present — disable in BIOS for full Ring -1 removal"
    fi

    # SVM (AMD-V)
    if grep -q 'svm' /proc/cpuinfo 2>/dev/null; then
        if lsmod 2>/dev/null | grep -q '^kvm_amd'; then
            emit WARN "KVM (AMD-V) modules loaded"
        else
            emit PASS "KVM AMD modules not loaded"
        fi
        emit INFO "SVM/AMD-V present — disable in BIOS for full Ring -1 removal"
    fi
}

# ── IOMMU / DMA protection ─────────────────────────────────────────────────

check_iommu() {
    section "IOMMU / DMA protection"

    # Check kernel cmdline for IOMMU flags
    local cmdline; cmdline="$(cat /proc/cmdline 2>/dev/null || true)"

    if echo "$cmdline" | grep -q 'intel_iommu=on\|amd_iommu=on'; then
        emit PASS "IOMMU enabled in kernel cmdline"
    else
        emit FAIL "IOMMU not enabled in cmdline — DMA attacks via PCIe/Thunderbolt possible"
    fi

    if echo "$cmdline" | grep -q 'iommu=force'; then
        emit PASS "iommu=force — all devices behind IOMMU, no passthrough bypass"
    else
        emit WARN "iommu=force not set — some devices may bypass IOMMU"
    fi

    if echo "$cmdline" | grep -q 'iommu.strict=1'; then
        emit PASS "iommu.strict=1 — no deferred TLB invalidation (strict DMA isolation)"
    else
        emit WARN "iommu.strict=1 not set — deferred invalidation may allow brief DMA windows"
    fi

    # Check IOMMU groups via sysfs
    if [ -d /sys/kernel/iommu_groups ]; then
        local group_count; group_count="$(ls /sys/kernel/iommu_groups/ 2>/dev/null | wc -l)"
        if [ "$group_count" -gt 0 ]; then
            emit PASS "IOMMU groups active: $group_count groups"
        else
            emit FAIL "IOMMU groups directory empty — IOMMU may not be functioning"
        fi
    else
        emit FAIL "/sys/kernel/iommu_groups missing — IOMMU not active"
    fi

    # Thunderbolt (DMA via USB4/TB)
    if [ -d /sys/bus/thunderbolt ]; then
        local tb_level; tb_level="$(cat /sys/bus/thunderbolt/devices/*/security 2>/dev/null | head -1 || echo 'none')"
        case "$tb_level" in
            none|*)
                emit WARN "Thunderbolt present — ensure security=dponly or disable in BIOS" ;;
        esac
    fi
}

# ── Secure Boot ───────────────────────────────────────────────────────────

check_secure_boot() {
    section "Secure Boot / Firmware Integrity"

    if [ -d /sys/firmware/efi ]; then
        local sb; sb="$(cat /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | xxd 2>/dev/null | tail -1 || true)"
        # SecureBoot EFI var: last byte is 01 = enabled, 00 = disabled
        if od -An -t u1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | \
           awk '{print $NF}' | grep -q '^1$'; then
            emit PASS "Secure Boot enabled"
        else
            emit WARN "Secure Boot disabled — firmware/bootloader integrity not verified at boot"
        fi
    else
        emit INFO "Non-UEFI boot — Secure Boot not applicable (legacy BIOS)"
    fi

    # Check if kernel module signing is enforced
    if grep -q 'module.sig_enforce=1' /proc/cmdline 2>/dev/null; then
        emit PASS "Kernel module signature enforcement active"
    else
        emit WARN "module.sig_enforce=1 not set — unsigned kernel modules can load"
    fi
}

# ── Memory protections ─────────────────────────────────────────────────────

check_memory() {
    section "Memory Protections"

    local cmdline; cmdline="$(cat /proc/cmdline 2>/dev/null || true)"

    if echo "$cmdline" | grep -q 'init_on_free=1'; then
        emit PASS "init_on_free=1 — freed pages zeroed immediately"
    else
        emit WARN "init_on_free=1 not set — freed memory may retain key material"
    fi

    if echo "$cmdline" | grep -q 'init_on_alloc=1'; then
        emit PASS "init_on_alloc=1 — allocated pages zeroed before use"
    else
        emit WARN "init_on_alloc=1 not set"
    fi

    # kptr_restrict
    local kptr; kptr="$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo 'n/a')"
    if [ "$kptr" = "2" ]; then
        emit PASS "kernel.kptr_restrict=2 — kernel pointers hidden from root"
    elif [ "$kptr" = "1" ]; then
        emit WARN "kernel.kptr_restrict=1 — pointers hidden from non-root only"
    else
        emit FAIL "kernel.kptr_restrict=$kptr — kernel pointers exposed"
    fi

    # Check for swap (key material risk)
    local swap; swap="$(swapon --show 2>/dev/null | wc -l)"
    if [ "$swap" -gt 1 ]; then
        emit WARN "Swap active — key material may be written to disk if not encrypted"
    else
        emit PASS "No active swap"
    fi
}

# ── Main ───────────────────────────────────────────────────────────────────

VENDOR="unknown"
dmidecode -s processor-manufacturer 2>/dev/null | grep -qi "Intel" && VENDOR="intel"
dmidecode -s processor-manufacturer 2>/dev/null | grep -qi "AMD"   && VENDOR="amd"

$JSON_MODE || echo "THL Firmware Audit — $(date)"
$JSON_MODE || echo "Platform: $(dmidecode -s system-product-name 2>/dev/null) ($VENDOR)"

case "$VENDOR" in
    intel) check_intel_me ;;
    amd)   check_amd_psp ;;
    *)     emit WARN "Unknown CPU vendor — skipping ME/PSP check" ;;
esac

check_smm
check_hypervisor
check_iommu
check_secure_boot
check_memory

# ── Summary ────────────────────────────────────────────────────────────────

if $JSON_MODE; then
    echo "{"
    echo "  \"pass\": $PASS,"
    echo "  \"warn\": $WARN,"
    echo "  \"fail\": $FAIL,"
    echo "  \"findings\": ["
    local sep=""
    for f in "${FINDINGS[@]}"; do
        printf "%s    %s\n" "$sep" "$f"
        sep=","
    done
    echo "  ]"
    echo "}"
else
    echo
    echo "─────────────────────────────────────────────────"
    printf "  Results: \033[32m%d PASS\033[0m  \033[33m%d WARN\033[0m  \033[31m%d FAIL\033[0m\n" "$PASS" "$WARN" "$FAIL"
    echo "─────────────────────────────────────────────────"
    if [ "$FAIL" -gt 0 ]; then
        echo "  Action required: run thl-me-neutralize and review GRUB cmdline"
        logger -t thl-firmware-audit "FAIL: $FAIL findings on $(dmidecode -s system-product-name 2>/dev/null)"
        exit 1
    elif [ "$WARN" -gt 0 ]; then
        echo "  Review warnings above — some mitigations incomplete"
        logger -t thl-firmware-audit "WARN: $WARN findings"
        exit 0
    else
        echo "  All checks passed"
        logger -t thl-firmware-audit "PASS: clean audit"
        exit 0
    fi
fi
