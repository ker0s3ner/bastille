# Tinfoil Hat Linux — Modernised

A privacy-hardened, security-focused desktop Linux distribution.  
Spiritual successor to the original [Tinfoil Hat Linux](https://en.wikipedia.org/wiki/Tinfoil_Hat_Linux) (Shmoo Group, 2002).

## Features

| # | Feature | Implementation |
|---|---------|----------------|
| 1 | GUI desktop | Sway (Wayland) — no X11 |
| 2 | I2P routing | i2pd, system service |
| 3 | Forced DNS | systemd-resolved + DoT, nftables blocks port 53 bypass |
| 4 | VPN kill-switch | WireGuard + nftables (all traffic dropped if VPN is down) |
| 5 | PGP tools | GPG 2.x, Kleopatra, modernised gpggrid |
| 6 | Browser allowlist | AppArmor profile; only listed browsers can exec |
| 7 | Duress PINs | PAM module (thl-duress) |
| 8 | Profiles | Per-use-case environments with separate encrypted storage |
| 9 | Disk encryption | LUKS2 (Argon2id) full-disk, set up by installer |

## Project layout

```
build/              live-build configuration
  auto/             lb config / build / clean scripts
  config/
    hooks/live/     chroot hooks (run during image build)
    includes.chroot/ files dropped verbatim into the image
    package-lists/  APT packages to install
src/                custom THL components
  gpggrid/          modernised gpggrid (ported from original C)
  thl-profile/      profile switcher
  thl-duress/       PAM duress module
  thl-gui/          GTK4 settings GUI
installer/          Calamares installer config
thl-source/         original THL source (reference / historical)
docs/               design docs
```

## Building

Requires Debian or Ubuntu host with `live-build` installed:

```bash
sudo apt install live-build debootstrap squashfs-tools xorriso
sudo ./build.sh
```

The resulting ISO is `build/live-image-amd64.hybrid.iso`.  
Write to USB: `dd if=build/live-image-amd64.hybrid.iso of=/dev/sdX bs=4M status=progress`

## VPN setup

Before the kill-switch allows any traffic, copy the WireGuard template and fill it in:

```bash
sudo cp /etc/wireguard/wg0.conf.template /etc/wireguard/wg0.conf
sudo nano /etc/wireguard/wg0.conf   # add your keys and endpoint
sudo systemctl start wg-quick@wg0
```

## Original THL components preserved

- `gpggrid` — keyboard-logger-defeating passphrase entry (being ported)
- `clrngd` — clock-based entropy daemon
- `blinker` / `text2morse` — LED morse output (paranoid mode)
- `ree` — ROM/NVRAM hash checker
- `ctheme` — screen contrast manipulator (paranoid mode)
