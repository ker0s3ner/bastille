#!/bin/sh
# Bastille OS session bootstrap — sourced on login

# Fix home dir ownership if needed (live ISO copies files as root)
if [ "$(stat -c '%U' "$HOME" 2>/dev/null)" != "$(whoami)" ]; then
    sudo chown -R "$(whoami):$(whoami)" "$HOME" 2>/dev/null || true
fi

# Launch sway as Wayland session if running on a VT and DISPLAY/WAYLAND_DISPLAY unset
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    case "$(tty 2>/dev/null)" in
        /dev/tty[12])
            exec dbus-run-session sway
            ;;
    esac
fi
