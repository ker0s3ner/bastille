# thl-duress — PAM duress PIN module

## Overview

`pam_thl_duress.so` is a Linux PAM authentication module that supports two
classes of PIN:

- **Normal PIN** — grants ordinary access, nothing else happens.
- **Duress PIN** — also grants access (so a coercer sees no difference), but
  silently triggers a configurable action in the background.

## Config file: `/etc/thl/duress.conf`

```
# type    argon2id-hash                   action   arg
normal    $argon2id$v=19$m=...            -
duress    $argon2id$v=19$m=...            wipe     /etc/thl/actions/wipe-keys.sh
duress    $argon2id$v=19$m=...            silent   tag1
duress    $argon2id$v=19$m=...            decoy    decoy-profile
duress    $argon2id$v=19$m=...            power
```

File must be owned by root, mode `0600`. The module refuses to load it otherwise.

## Actions

| Action | Effect |
|--------|--------|
| `wipe <script>` | Shreds WireGuard keys, GPG keyring, THL profile keys — then session continues normally |
| `silent <tag>` | Logs event to syslog with the given tag; session continues normally |
| `decoy <profile>` | Switches to the named decoy profile for this session |
| `power` | Powers off immediately (abrupt — no clean unmount) |

## Setup

```bash
sudo thl-duress-setup          # interactive wizard
sudo thl-duress-setup --show   # list configured entry types
sudo thl-duress-setup --clear  # remove all entries
```

## Security design

- All PIN hashes use **Argon2id** with `OPSLIMIT_SENSITIVE` / `MEMLIMIT_SENSITIVE`.
- Comparisons use **libsodium's constant-time verifier** — no timing leak between
  normal and duress paths.
- The PAM module iterates every entry on every verify call to equalise timing
  regardless of which PIN matched or how many entries exist.
- PIN string is **zeroed from memory** (`sodium_memzero`) immediately after verification.
- Duress actions run in a **double-forked daemon** — the PAM conversation returns
  before the action completes, so there is no measurable delay.
- The module returns `PAM_SUCCESS` for both normal and duress PINs. A coercer
  watching the login screen sees identical behaviour either way.

## Building

```bash
apt install libpam0g-dev libsodium-dev gcc make
make
sudo make install
```
