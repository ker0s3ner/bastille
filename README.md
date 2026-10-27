# Bastille

A privacy-hardened desktop Linux built for people who need their computer to keep secrets. Bastille is a Debian live system — it boots entirely from USB, runs in RAM, and leaves nothing on the host machine.

It is a spiritual successor to the 2002 [Shmoo Group Tinfoil Hat Linux](https://github.com/luvettee/boberbob229.github.io) floppy distro, rebuilt for a threat landscape that includes hardware-level attacks, forensic extraction tools, and always-on adversarial networks.

**Website:** https://ker0s3ner.github.io/bastille/

---

## What it does

Every protection is on by default. Nothing requires manual configuration after boot.

| Layer | Protection |
|---|---|
| Network | WireGuard kill-switch — all traffic through VPN or nothing. nftables drops plain HTTP. DNS locked to systemd-resolved (DoT + DNSSEC). |
| Storage | LUKS2 Argon2id split-key: one half in kernel logon keyring (write-once), one on disk. Screen lock = Before-First-Unlock state. |
| Access | Three-PIN system: normal, decoy (opens a clean profile), full-wipe (shreds key material, powers off without flushing disk). Constant-time PIN comparison. |
| USB | Resident daemon matches connected devices against forensic tool VID:PID signatures (Cellebrite, MSAB, Qualcomm EDL, MediaTek BROM). On match: de-authorise → evict keys → shred → re-authorise. HID devices emitting >40 events/100ms are treated as BadUSB and blocked. |
| Firmware | Intel ME stripped to HAP bit via `me_cleaner`. KVM blacklisted. S3 suspend disabled (SMM attack surface). IOMMU in strict mode. Firmware audit service runs at boot. |
| Physical | OpenCV face detection at 5 fps. No face for 10s → screen locks. Second face detected → backlight drops to 5%. |
| Anonymity | i2pd (C++ I2P router) runs inside the WireGuard tunnel. SOCKS5 and HTTP proxies on localhost. |
| Memory | Key material in `sodium_malloc` + `mlock`. Page cache scrubbed every 5 minutes. Transparent hugepages disabled. `vm.swappiness=0`. |

## Threat model

Bastille is designed for border crossings, device seizure, and hostile networks. It does not protect against a fully compromised supply chain or a nation-state with physical access to the CPU die.

| Threat | Status |
|---|---|
| Network interception | Mitigated |
| Disk forensics (BFU) | Mitigated |
| Live forensics / Cellebrite (AFU) | Mitigated |
| Coerced unlock | Mitigated |
| BadUSB / O.MG cable | Mitigated |
| Firmware persistence (ME/SMM) | Partial — hardware-specific |
| Shoulder surfing | Mitigated |

## Stack

Built on **Debian Bookworm** using `live-build`. Every configuration file, hook, and compiled component is in this repository. No binary blobs added post-bootstrap.

- **Desktop:** Sway / Wayland (no X11), greetd + tuigreet
- **VPN:** WireGuard (in-kernel), nftables kill-switch
- **DNS:** systemd-resolved, DoT + DNSSEC, `chattr +i /etc/resolv.conf`
- **Anonymity:** i2pd
- **Encryption:** LUKS2 + Argon2id (1 GB memory cost)
- **Crypto:** libsodium (Argon2id, HKDF, HMAC-SHA256, `sodium_malloc`)
- **Key storage:** Linux kernel logon keyring
- **Auth:** PAM (`pam_thl_duress.so`)
- **Isolation:** AppArmor + USBGuard
- **Firmware:** me_cleaner + flashrom

## Building

Requires a Debian/Ubuntu host (or Docker). Build produces a live ISO.

```sh
# Native Debian host
sudo apt install live-build debootstrap squashfs-tools xorriso
sudo bash build.sh

# Docker (builds arm64 on Apple Silicon)
docker build -f Dockerfile.build -t bastille-builder .
docker run --rm --privileged \
  -v "$(pwd)/output:/output" \
  bastille-builder
```

The ISO is written to `output/bastille-arm64.iso` (or `amd64` on x86 hosts).

## Repository layout

```
build/
  auto/           live-build config scripts
  config/
    hooks/live/   chroot hooks (0010–0090)
    includes.chroot/  files copied into the live system
    package-lists/
src/
  thl-keyguard/   split-key LUKS2 daemon (C + libsodium)
  thl-duress/     PAM duress module (C)
  gpggrid/        keyboard-logger-defeating passphrase entry (C + ncurses)
  thl-usb/        USB threat detection daemon (C)
  thl-vision/     face-detection screen guard (Python + OpenCV)
  thl-firmware/   firmware audit and ME neutralisation scripts
  thl-persist/    live USB LUKS2 persistence setup
docs/             GitHub Pages site
```

## Origin

The original Tinfoil Hat Linux was a 1.44 MB floppy image released by the Shmoo Group in 2002. It contained GnuPG and nothing else — the premise being that a truly minimal system has the smallest possible attack surface. Bastille keeps that premise and extends it to a full desktop OS.

## License

GPL-2.0. See [LICENSE](LICENSE).
