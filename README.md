# Bastille OS

A security-hardened Debian 13 (Trixie) live and installable Linux desktop. It can
run ephemerally from USB or install to an encrypted local disk for daily use.

Current release: **1.1.0** "Hyena" (see `VERSION` and `CODENAME`). Targets amd64 and arm64.

---

## What it is

Bastille is a live OS designed for people who need genuine security — not security theatre. It runs entirely in RAM, randomises its hostname on every boot, encrypts DNS, enforces a WireGuard kill switch, and provides a duress system that can silently destroy keys or brick UEFI under coercion.

The live image includes the core desktop, Firefox, PipeWire, Bluetooth, broad
firmware coverage, printing/scanning support, Flatpak, and the Bastille apps.
The first-boot wizard lets you choose which optional launchers remain enabled.
Tor Browser is optional; privacy-focused normal browsers such as LibreWolf and
Zen are allowed through Bastille's curated Flatpak gate without forcing Tor.

---

## Architecture

| Repo | What's in it |
|---|---|
| [`bastille-linux/bastille`](https://github.com/bastille-linux/bastille) | ISO build system — live-build config, hooks, security daemons |
| [`bastille-linux/apps`](https://github.com/bastille-linux/apps) | GTK4 native apps (Notes, Music, Calendar, Maps, Mail, Settings) |
| [`bastille-linux/security`](https://github.com/bastille-linux/security) | C security subsystems — duress, keyguard, USB inspector, gpggrid |
| [`bastille-linux/site`](https://github.com/bastille-linux/site) | Website and docs |

The core apps and their runtime dependencies are baked into the ISO. Optional
app dependencies can be fetched by the installer or first-boot flow; app
updates do not require a new ISO.

---

## Security features

- **OpenRC init** — no systemd attack surface
- **seatd** — seat management without logind
- **WireGuard kill switch** — nftables blocks all traffic unless through `wg0`
- **dnscrypt-proxy** — encrypted DNS, locked to `127.0.0.1:53`
- **AppArmor + USBGuard** — mandatory access control + USB whitelisting
- **Duress system** — fake duress PIN (decoy session) + real duress PIN (key destruction / UEFI brick)
- **DSM (Device Stress Mode)** — crypto-erases NVMe, bricks UEFI via firmware write
- **RAM wipe on shutdown** — `/etc/init.d/bastille-ramwipe`
- **Hostname randomisation** — new hostname every boot
- **ME neutralisation** — Intel Management Engine mitigation on supported hardware
- **BFU eviction** — before-first-unlock LUKS key eviction

---

## Building

### CI (GitHub Actions)

Every push to `main` triggers builds for both architectures. Releases are created automatically at `bastille-linux/bastille`.

### Local (Docker)

```bash
# amd64
bash build-amd64-local.sh

# arm64 (on Apple Silicon or ARM host)
bash build-arm64-local.sh
```

Requires Docker with `--privileged` support. ISOs are written under `build/`
(`live-image-<arch>.hybrid.iso`); checksums and logs land in `output/`.

### Validation and tests

CI runs these before building, and you can run them locally:

```bash
bash scripts/validate-build.sh --check-apt   # hook order/permissions, package references (--check-apt needs apt-cache, i.e. a Debian host)
bash scripts/test-installer-preflight.sh     # installer refuses unsafe installs (e.g. Secure Boot on)
bash scripts/test-update-rollback.sh         # live-media update and rollback
bash scripts/test-backup-safety.sh           # bastille-backup safety checks
bash scripts/test-backup-roundtrip.sh        # backup create/list/restore round trip
bash scripts/test-duress-verify.sh           # bastille-duress-verify audit
```

---

## Live first boot

1. Boot from USB
2. The Bastille greeter starts the Sway desktop
3. Complete the setup wizard — choose apps, set PINs, and configure WireGuard

The live image is intentionally ephemeral. Use the installer when you want a
persistent encrypted root filesystem and a normal user account.

The current installer requires Secure Boot to be disabled: the installed
system uses Bastille's removable GRUB path and does not yet ship a Bastille-
signed boot chain. The installer detects Secure Boot and refuses to erase a
disk rather than producing an installation that firmware will not boot.

### Lenovo ThinkPad T530

The T530 in the reference hardware photo is an amd64 Ivy Bridge ThinkPad. Use
the amd64 ISO, boot it in UEFI mode, and select **Lenovo / IBM ThinkPad** in the
installer. The image includes Intel microcode, Intel Wi-Fi firmware, Intel
graphics support, ACPI laptop controls, TrackPoint/touchpad input, PipeWire
audio, webcam tools, and battery/power management. Disable Secure Boot before
installing; this release uses an unsigned removable GRUB path. If the machine
has the optional NVIDIA NVS 5400M, leave the firmware on integrated/Optimus
graphics for the most reliable Wayland session.

## Installed systems

The graphical installer creates a GPT layout with a 512 MiB EFI system
partition, a 1 GiB `/boot`, and a LUKS2-encrypted ext4 root. It installs the
OpenRC-based system and configures the selected user, profiles, accounts, and
apps. The installer records a hardware profile for ThinkPads, modern
Windows/UEFI laptops, Intel MacBooks, or unknown systems; Intel Mac support is
experimental and T2/Apple Silicon Macs are not supported yet. Recovery entries
remain enabled in GRUB.

Installed systems update through signed Debian repositories with:

```bash
sudo bastille-update apply
```

Before an installed-system package update, Bastille creates a protected local
configuration recovery point. List or restore points from a rescue shell with:

```bash
sudo bastille-recovery list
sudo bastille-recovery restore <name>
```

Live-media updates retain the previous bootable image. If a newly downloaded
image does not behave correctly after reboot, boot the live session, run
`bastille-update rollback`, and reboot again.

For user-data recovery, the desktop user can create an age-encrypted home
backup on an external disk. Cache files and the desktop trash are omitted;
restore writes to a new directory unless `--into-home` is explicitly used:

```bash
bastille-backup create /media/user/backup/bastille-home.age
bastille-backup list /media/user/backup/bastille-home.age
bastille-backup restore /media/user/backup/bastille-home.age
```

Duress protection has two layers. The ordinary Duress PIN destroys configured
cryptographic key material and powers off; `bastille-duress-verify` audits the
configuration and required protections without performing a wipe. Device
Stress Mode (DSM) is separate and explicitly destructive: firmware overwrite
and storage crypto-erase are hardware-dependent and must not be treated as a
universal recovery guarantee.

---

## Repo structure

```
VERSION, CODENAME           release version and name
build/
  auto/                     live-build config/build/clean scripts
  config/
    package-lists/          packages baked into the ISO
    hooks/live/             numbered chroot hooks, run in order
    includes.chroot/        files dropped into the live filesystem
      etc/bastille/         runtime config (duress PINs, keystore, actions)
      etc/init.d/           OpenRC services
      usr/local/src/        C security tool sources (compiled during build)
      usr/local/sbin/       compiled binaries and shell helpers
        (bastille-update, bastille-recovery, bastille-duress-verify,
         bastille-install-backend, bastille-dsm, bastille-network-guard, ...)
src/                        auditable source for the security tools:
                            bastille-duress, bastille-keyguard, bastille-usb,
                            bastille-firmware, bastille-persist, bastille-profile,
                            bastille-vision, gpggrid
scripts/                    validate-build.sh, test-*.sh, sync-apps-repo.py
docs/                       static HTML docs: build, features, threat model
site/docs/                  markdown docs (first boot, threat model)
plans/daily-driver.md       roadmap to a daily-driver release
.github/workflows/          CI: build-iso.yml (amd64), build-iso-arm64.yml
```

---

## Threat model

Bastille is designed for:
- Journalists, activists, and researchers working in hostile environments
- People who need plausible deniability under physical coercion
- Anyone who cannot trust the host machine they boot from

It is **not** designed for:
- A guaranteed hardware support matrix without testing the target machine
- Recovery from a physically destroyed disk without an external backup
- Scenarios where the attacker has unlimited pre-boot access

---

## Contributing

Security issues: open a private advisory on GitHub.  
Everything else: PRs welcome.
