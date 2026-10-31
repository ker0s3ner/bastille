#!/usr/bin/env python3
"""Bastille OS Settings — GTK4/libadwaita system settings application."""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

import os
import sys
import json
import subprocess
import shutil
from gi.repository import Gtk, Adw, Gio, GLib, Pango

APP_ID = "org.bastilleos.Settings"
VERSION = "1.0.0"

BASTILLE_ACCENT = "#4f8fd4"

def pkexec(cmd, *args):
    """Run a polkit-gated helper. Returns (returncode, stdout, stderr)."""
    full = ["pkexec", cmd] + list(args)
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "timed out"
    except Exception as e:
        return 1, "", str(e)

def read_file(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return default

def file_exists(path):
    return os.path.exists(path)


class BastilleRow(Adw.ActionRow):
    """Helper: ActionRow with optional toggle or chevron."""
    def __init__(self, title, subtitle=None, icon_name=None, toggle=False,
                 toggle_active=False, on_toggle=None, activatable=False):
        super().__init__()
        self.set_title(title)
        if subtitle:
            self.set_subtitle(subtitle)
        if icon_name:
            img = Gtk.Image.new_from_icon_name(icon_name)
            img.set_pixel_size(24)
            self.add_prefix(img)
        if toggle:
            sw = Gtk.Switch()
            sw.set_active(toggle_active)
            sw.set_valign(Gtk.Align.CENTER)
            if on_toggle:
                sw.connect("notify::active", lambda s, _: on_toggle(s.get_active()))
            self.add_suffix(sw)
        elif activatable:
            self.set_activatable(True)


class CodeBox(Gtk.Box):
    """Scrollable monospace text editor for advanced config."""
    def __init__(self, content="", editable=True):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        sw = Gtk.ScrolledWindow()
        sw.set_vexpand(True)
        sw.set_min_content_height(200)
        tv = Gtk.TextView()
        tv.set_editable(editable)
        tv.set_monospace(True)
        tv.set_wrap_mode(Gtk.WrapMode.NONE)
        tv.set_left_margin(12)
        tv.set_right_margin(12)
        tv.set_top_margin(8)
        tv.set_bottom_margin(8)
        tv.get_buffer().set_text(content)
        sw.set_child(tv)
        self.append(sw)
        self._tv = tv

    def get_text(self):
        buf = self._tv.get_buffer()
        return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)

    def set_text(self, text):
        self._tv.get_buffer().set_text(text)


class DualView(Gtk.Box):
    """Visual + Advanced tab switcher for each settings section."""
    def __init__(self, visual_widget, advanced_widget):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        tabs = Gtk.StackSwitcher()
        stack = Gtk.Stack()
        stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        stack.add_titled(visual_widget, "visual", "Visual")
        stack.add_titled(advanced_widget, "advanced", "Advanced")
        tabs.set_stack(stack)
        tabs.set_halign(Gtk.Align.CENTER)
        tabs.set_margin_bottom(12)
        self.append(tabs)
        self.append(stack)


# ── Section pages ─────────────────────────────────────────────────────────────

class PrivacySecurityPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32)
        box.set_margin_end(32)
        box.set_margin_top(24)
        box.set_margin_bottom(24)

        # Profile group
        pg = Adw.PreferencesGroup()
        pg.set_title("Security profile")
        pg.set_description("Controls the active threat model preset")
        row = Adw.ComboRow()
        row.set_title("Active profile")
        row.set_subtitle("Applies a bundle of settings")
        model = Gtk.StringList.new(["Standard", "High security", "Anonymity", "Custom"])
        row.set_model(model)
        row.set_selected(1)
        pg.add(row)
        box.append(pg)

        # AppArmor / Kernel
        sg = Adw.PreferencesGroup()
        sg.set_title("Kernel security")
        for title, sub, icon in [
            ("AppArmor", "Mandatory access control enforcing", "security-high-symbolic"),
            ("Kernel lockdown", "Restricts /dev/mem, kexec, module loading", "emblem-system-symbolic"),
            ("ASLR", "Address-space layout randomisation (always on)", "emblem-system-symbolic"),
        ]:
            r = BastilleRow(title, sub, icon, toggle=True, toggle_active=True)
            sg.add(r)
        box.append(sg)

        # Anti-forensics
        ag = Adw.PreferencesGroup()
        ag.set_title("Anti-forensics")
        r1 = BastilleRow("RAM wipe on shutdown", "sdmem -ll overwrites memory", "user-trash-symbolic",
                         toggle=True, toggle_active=True,
                         on_toggle=lambda v: self._set_ramwipe(v))
        r2 = BastilleRow("Periodic RAM scrub", "Every 5 minutes via cron", "appointment-symbolic",
                         toggle=True, toggle_active=True)
        r3 = Adw.SpinRow.new_with_range(1, 120, 1)
        r3.set_title("BFU idle timeout (minutes)")
        r3.set_subtitle("Poweroff after this many minutes idle")
        r3.set_value(30)
        ag.add(r1); ag.add(r2); ag.add(r3)
        box.append(ag)

        # Connectivity kill switches
        cg = Adw.PreferencesGroup()
        cg.set_title("Hardware kill switches")
        for title, sub, icon in [
            ("Bluetooth", "Block via rfkill at boot", "bluetooth-symbolic"),
            ("Webcam", "Deny access via udev rule", "camera-photo-symbolic"),
            ("Microphone", "Deny access via udev rule", "audio-input-microphone-symbolic"),
            ("Intel ME neutralisation", "Disable management engine (x86)", "emblem-system-symbolic"),
        ]:
            r = BastilleRow(title, sub, icon, toggle=True, toggle_active=True)
            cg.add(r)
        box.append(cg)

        self.set_child(box)

    def _set_ramwipe(self, enabled):
        if enabled:
            pkexec("/usr/local/sbin/bastille-set-service", "bastille-ramwipe", "enable")
        else:
            pkexec("/usr/local/sbin/bastille-set-service", "bastille-ramwipe", "disable")


class SecurityPinsPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32)
        box.set_margin_end(32)
        box.set_margin_top(24)
        box.set_margin_bottom(24)

        banner = Adw.Banner()
        banner.set_title("PINs are stored hashed in /etc/bastille/pins.conf — never in plaintext.")
        banner.set_revealed(True)
        box.append(banner)

        # Login PIN
        lg = Adw.PreferencesGroup()
        lg.set_title("Login PIN")
        lg.set_description("Additional PIN required at the greeter after password entry")
        r = Adw.ActionRow()
        r.set_title("Login PIN")
        r.set_subtitle("Not set")
        btn = Gtk.Button.new_with_label("Set PIN")
        btn.set_valign(Gtk.Align.CENTER)
        btn.add_css_class("pill")
        btn.connect("clicked", lambda _: self._set_pin("login"))
        r.add_suffix(btn)
        lg.add(r)
        box.append(lg)

        # Duress PIN
        dg = Adw.PreferencesGroup()
        dg.set_title("Duress PIN")
        dg.set_description("Entering this PIN at login triggers a silent RAM wipe and emergency shutdown. "
                           "Use when physically coerced to unlock the device.")
        r = Adw.ActionRow()
        r.set_title("Duress PIN")
        r.set_subtitle("Wipes RAM → immediate poweroff")
        btn = Gtk.Button.new_with_label("Set PIN")
        btn.set_valign(Gtk.Align.CENTER)
        btn.add_css_class("pill")
        btn.add_css_class("destructive-action")
        btn.connect("clicked", lambda _: self._set_pin("duress"))
        r.add_suffix(btn)
        dg.add(r)

        r2 = BastilleRow("Wipe persistence volume", "Also wipe LUKS2 persistence on duress",
                         "drive-removable-media-symbolic", toggle=True, toggle_active=True)
        r3 = BastilleRow("Send distress signal", "Send network beacon before wipe (requires VPN)",
                         "network-transmit-symbolic", toggle=True, toggle_active=False)
        dg.add(r2); dg.add(r3)
        box.append(dg)

        # Fake duress PIN
        fg = Adw.PreferencesGroup()
        fg.set_title("Fake Duress PIN (Plausible Deniability)")
        fg.set_description("Looks identical to duress — initiates a fake wipe animation, then boots "
                           "into a sanitised decoy session. The attacker sees a reboot; you are in the decoy.")
        r = Adw.ActionRow()
        r.set_title("Fake duress PIN")
        r.set_subtitle("Decoy boot — no actual wipe")
        btn = Gtk.Button.new_with_label("Set PIN")
        btn.set_valign(Gtk.Align.CENTER)
        btn.add_css_class("pill")
        btn.connect("clicked", lambda _: self._set_pin("fake-duress"))
        r.add_suffix(btn)
        fg.add(r)

        r2 = Adw.ActionRow()
        r2.set_title("Decoy session path")
        r2.set_subtitle("/etc/bastille/decoy/")
        btn2 = Gtk.Button.new_with_label("Configure")
        btn2.set_valign(Gtk.Align.CENTER)
        btn2.add_css_class("pill")
        r2.add_suffix(btn2)
        fg.add(r2)
        box.append(fg)

        # DSM — Dead Switch Mode
        dm = Adw.PreferencesGroup()
        dm.set_title("DSM — Dead Switch Mode")
        dm.set_description("Automatically triggers duress wipe if a check-in PIN is not entered "
                           "within the configured interval. Designed for covert operations or custody scenarios.")
        r_en = BastilleRow("Enable DSM", "Requires check-in at interval", "appointment-soon-symbolic",
                           toggle=True, toggle_active=file_exists("/etc/bastille/dsm.enabled"),
                           on_toggle=self._toggle_dsm)
        dm.add(r_en)
        r_pin = Adw.ActionRow()
        r_pin.set_title("DSM check-in PIN")
        r_pin.set_subtitle("Enter this periodically to suppress the dead switch")
        btn3 = Gtk.Button.new_with_label("Set PIN")
        btn3.set_valign(Gtk.Align.CENTER)
        btn3.add_css_class("pill")
        btn3.connect("clicked", lambda _: self._set_pin("dsm"))
        r_pin.add_suffix(btn3)
        dm.add(r_pin)

        r_interval = Adw.SpinRow.new_with_range(5, 1440, 5)
        r_interval.set_title("Check-in interval (minutes)")
        r_interval.set_subtitle("DSM fires if not checked in within this window")
        r_interval.set_value(60)
        dm.add(r_interval)

        r_warning = Adw.SpinRow.new_with_range(1, 30, 1)
        r_warning.set_title("Warning time (minutes)")
        r_warning.set_subtitle("Visible notification before DSM fires")
        r_warning.set_value(5)
        dm.add(r_warning)

        for lbl, icon in [
            ("Trigger duress wipe on expiry", "user-trash-symbolic"),
            ("Trigger fake duress on expiry", "face-uncertain-symbolic"),
        ]:
            rr = BastilleRow(lbl, icon_name=icon, toggle=True, toggle_active=True)
            dm.add(rr)
        box.append(dm)

        self.set_child(box)

    def _set_pin(self, pin_type):
        dlg = Adw.MessageDialog.new(None)
        dlg.set_heading(f"Set {pin_type.replace('-', ' ').title()} PIN")
        dlg.set_body("Enter a PIN (4–16 digits). This will be stored as an Argon2id hash.")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(16); box.set_margin_end(16)
        e1 = Gtk.PasswordEntry()
        e1.set_show_peek_icon(False)
        e1.set_placeholder_text("New PIN")
        e2 = Gtk.PasswordEntry()
        e2.set_show_peek_icon(False)
        e2.set_placeholder_text("Confirm PIN")
        box.append(e1); box.append(e2)
        dlg.set_extra_child(box)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("set", "Set PIN")
        dlg.set_response_appearance("set", Adw.ResponseAppearance.SUGGESTED)
        def on_response(d, resp):
            if resp == "set":
                pin = e1.get_text()
                if pin == e2.get_text() and len(pin) >= 4:
                    rc, _, err = pkexec("/usr/local/sbin/bastille-set-pins",
                                        f"--type={pin_type}", f"--pin={pin}")
                    if rc != 0:
                        self._show_error(f"Failed to set PIN: {err}")
            d.close()
        dlg.connect("response", on_response)
        dlg.present()

    def _toggle_dsm(self, enabled):
        flag = "/etc/bastille/dsm.enabled"
        if enabled:
            pkexec("/usr/local/sbin/bastille-set-service", "bastille-dsm-watchdog", "enable")
        else:
            pkexec("/usr/local/sbin/bastille-set-service", "bastille-dsm-watchdog", "disable")

    def _show_error(self, msg):
        dlg = Adw.MessageDialog.new(None)
        dlg.set_heading("Error")
        dlg.set_body(msg)
        dlg.add_response("ok", "OK")
        dlg.present()


class InternetAccountsPage(Gtk.ScrolledWindow):
    """Secure credential store — similar to macOS Keychain / Internet Accounts."""
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32)
        box.set_margin_end(32)
        box.set_margin_top(24)
        box.set_margin_bottom(24)

        banner = Adw.Banner()
        banner.set_title("Credentials are encrypted with your login passphrase via libsecret.")
        banner.set_revealed(True)
        box.append(banner)

        # Accounts list
        ag = Adw.PreferencesGroup()
        ag.set_title("Accounts")
        ag.set_description("Applications request credentials through the secure keyring — never stored in plaintext.")

        for name, kind, icon in [
            ("Add email account", "IMAP / SMTP", "mail-unread-symbolic"),
            ("Add VPN credentials", "WireGuard / OpenVPN", "network-vpn-symbolic"),
            ("Add web account", "OAuth token storage", "web-browser-symbolic"),
            ("Add SSH key", "Passphrase-protected key", "security-medium-symbolic"),
        ]:
            r = Adw.ActionRow()
            r.set_title(name)
            r.set_subtitle(kind)
            img = Gtk.Image.new_from_icon_name(icon)
            img.set_pixel_size(24)
            r.add_prefix(img)
            r.set_activatable(True)
            chevron = Gtk.Image.new_from_icon_name("go-next-symbolic")
            r.add_suffix(chevron)
            ag.add(r)
        box.append(ag)

        # Keyring settings
        kg = Adw.PreferencesGroup()
        kg.set_title("Keyring settings")
        r1 = BastilleRow("Auto-lock after idle", "Lock keyring after 10 minutes", "system-lock-screen-symbolic",
                         toggle=True, toggle_active=True)
        r2 = BastilleRow("Lock on screen lock", "Lock keyring with screen", "system-lock-screen-symbolic",
                         toggle=True, toggle_active=True)
        r3 = Adw.ActionRow()
        r3.set_title("Lock keyring now")
        r3.set_activatable(True)
        lock_btn = Gtk.Button.new_with_label("Lock")
        lock_btn.add_css_class("pill")
        lock_btn.add_css_class("destructive-action")
        lock_btn.set_valign(Gtk.Align.CENTER)
        r3.add_suffix(lock_btn)
        kg.add(r1); kg.add(r2); kg.add(r3)
        box.append(kg)

        self.set_child(box)


class FirewallPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        nft_rules = read_file("/etc/nftables.conf",
            "# No nftables config found.\n# Edit here and click Apply.\ntable inet filter {\n  chain input {\n    type filter hook input priority 0; policy drop;\n    ct state established,related accept\n    iif lo accept\n  }\n}")

        visual = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        visual.set_margin_start(8)
        visual.set_margin_end(8)
        visual.set_margin_top(8)

        fg = Adw.PreferencesGroup()
        fg.set_title("Firewall")
        r1 = BastilleRow("Firewall enabled", "nftables active", "network-firewall-symbolic",
                         toggle=True, toggle_active=True,
                         on_toggle=lambda v: pkexec("/usr/local/sbin/bastille-set-service", "nftables",
                                                     "enable" if v else "disable"))
        r2 = BastilleRow("Default policy: DROP", "Reject all uninvited inbound traffic", "network-offline-symbolic",
                         toggle=True, toggle_active=True)
        r3 = BastilleRow("Block outbound for non-VPN traffic", "Killswitch: drop if VPN down",
                         "network-vpn-symbolic", toggle=True, toggle_active=False)
        fg.add(r1); fg.add(r2); fg.add(r3)
        visual.append(fg)

        # Port rules
        pg = Adw.PreferencesGroup()
        pg.set_title("Allowed inbound ports")
        pg.set_description("These rules are generated from the visual config above")
        for port, proto, svc in [("22", "TCP", "SSH (disabled by default)"),
                                  ("53", "UDP", "DNS (local only)"),
                                  ("67-68", "UDP", "DHCP client")]:
            r = Adw.ActionRow()
            r.set_title(f"Port {port}/{proto}")
            r.set_subtitle(svc)
            sw = Gtk.Switch()
            sw.set_valign(Gtk.Align.CENTER)
            sw.set_active(port == "53" or port == "67-68")
            r.add_suffix(sw)
            pg.add(r)
        visual.append(pg)

        advanced = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        advanced.set_margin_start(8); advanced.set_margin_end(8)
        advanced.set_margin_top(8)
        cb = CodeBox(nft_rules)
        advanced.append(cb)
        apply_btn = Gtk.Button.new_with_label("Apply nftables rules")
        apply_btn.add_css_class("pill")
        apply_btn.add_css_class("suggested-action")
        apply_btn.set_halign(Gtk.Align.END)
        apply_btn.set_margin_top(8)
        apply_btn.connect("clicked", lambda _: self._apply_nft(cb.get_text()))
        advanced.append(apply_btn)

        sv = Gtk.ScrolledWindow()
        sv.set_child(visual)
        self.set_child(DualView(sv, advanced))

    def _apply_nft(self, rules):
        import tempfile, os
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".nft", mode="w")
        tmp.write(rules)
        tmp.close()
        rc, _, err = pkexec("/usr/local/sbin/bastille-set-nft", tmp.name)
        os.unlink(tmp.name)
        if rc != 0:
            print(f"nftables error: {err}", file=sys.stderr)


class VPNPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        wg_conf = read_file("/etc/wireguard/wg0.conf",
            "# No WireGuard config found.\n# Paste your wg0.conf here and click Apply.\n")

        visual = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        visual.set_margin_start(8); visual.set_margin_end(8); visual.set_margin_top(8)

        sg = Adw.PreferencesGroup()
        sg.set_title("WireGuard VPN")
        r1 = BastilleRow("VPN enabled", "wg0 tunnel up/down", "network-vpn-symbolic",
                         toggle=True, toggle_active=file_exists("/etc/wireguard/wg0.conf"),
                         on_toggle=lambda v: pkexec("/usr/local/sbin/bastille-set-wg",
                                                     "up" if v else "down"))
        r2 = BastilleRow("DNS killswitch", "Block DNS if VPN down", "network-offline-symbolic",
                         toggle=True, toggle_active=True)
        r3 = BastilleRow("Traffic killswitch", "Block all non-VPN traffic", "network-firewall-symbolic",
                         toggle=True, toggle_active=False)
        sg.add(r1); sg.add(r2); sg.add(r3)

        # Status
        status_row = Adw.ActionRow()
        status_row.set_title("VPN status")
        try:
            out = subprocess.check_output(["wg", "show", "wg0"], text=True, stderr=subprocess.DEVNULL)
            status_row.set_subtitle("Connected")
        except Exception:
            status_row.set_subtitle("Not connected")
        sg.add(status_row)
        visual.append(sg)

        advanced = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        advanced.set_margin_start(8); advanced.set_margin_end(8); advanced.set_margin_top(8)
        cb = CodeBox(wg_conf)
        advanced.append(cb)
        apply_btn = Gtk.Button.new_with_label("Save WireGuard config")
        apply_btn.add_css_class("pill")
        apply_btn.add_css_class("suggested-action")
        apply_btn.set_halign(Gtk.Align.END)
        apply_btn.set_margin_top(8)
        apply_btn.connect("clicked", lambda _: pkexec("/usr/local/sbin/bastille-set-wg",
                                                       "config", cb.get_text()))
        advanced.append(apply_btn)

        sv = Gtk.ScrolledWindow()
        sv.set_child(visual)
        self.set_child(DualView(sv, advanced))


class DNSPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        dns_conf = read_file("/etc/dnscrypt-proxy/dnscrypt-proxy.toml", "")
        blocklist = read_file("/etc/dnscrypt-proxy/blocked-names.txt", "")

        visual = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        visual.set_margin_start(8); visual.set_margin_end(8); visual.set_margin_top(8)

        dg = Adw.PreferencesGroup()
        dg.set_title("DNS provider")
        row = Adw.ComboRow()
        row.set_title("Resolver")
        row.set_model(Gtk.StringList.new([
            "Cloudflare (DoH, DNSSEC, malware filter)",
            "Quad9 (DNSCrypt, threat-filtered)",
            "NextDNS (configurable blocklist)",
            "Custom",
        ]))
        row.set_selected(0)
        dg.add(row)

        for title, sub, active in [
            ("DNSSEC validation", "Reject unsigned responses", True),
            ("No-log requirement", "Only use zero-log resolvers", True),
            ("Anonymised routing", "Route through relays to hide client IP", True),
            ("Encrypted DNS only", "No plaintext DNS fallback", True),
        ]:
            r = BastilleRow(title, sub, toggle=True, toggle_active=active)
            dg.add(r)
        visual.append(dg)

        bg = Adw.PreferencesGroup()
        bg.set_title("Block list")
        bg.set_description("Blocked domains are resolved as NXDOMAIN")
        for name, sub in [("Malware domains", "Updated via OISD basic"), ("Ad domains", "EasyList DNS"),
                           ("Tracking pixels", "Disconnect.me"), ("Custom list", "/etc/dnscrypt-proxy/blocked-names.txt")]:
            r = BastilleRow(name, sub, toggle=True, toggle_active=True)
            bg.add(r)
        visual.append(bg)

        adv = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        adv.set_margin_start(8); adv.set_margin_end(8); adv.set_margin_top(8)
        lbl = Gtk.Label.new("dnscrypt-proxy.toml")
        lbl.add_css_class("caption")
        lbl.set_halign(Gtk.Align.START)
        adv.append(lbl)
        cb1 = CodeBox(dns_conf)
        adv.append(cb1)
        lbl2 = Gtk.Label.new("blocked-names.txt")
        lbl2.add_css_class("caption")
        lbl2.set_halign(Gtk.Align.START)
        lbl2.set_margin_top(12)
        adv.append(lbl2)
        cb2 = CodeBox(blocklist)
        adv.append(cb2)
        apply_btn = Gtk.Button.new_with_label("Apply DNS config")
        apply_btn.add_css_class("pill"); apply_btn.add_css_class("suggested-action")
        apply_btn.set_halign(Gtk.Align.END); apply_btn.set_margin_top(8)
        apply_btn.connect("clicked", lambda _: pkexec("/usr/local/sbin/bastille-set-dns",
                                                       cb1.get_text(), cb2.get_text()))
        adv.append(apply_btn)

        sv = Gtk.ScrolledWindow()
        sv.set_child(visual)
        self.set_child(DualView(sv, adv))


class AnonymityPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32); box.set_margin_end(32)
        box.set_margin_top(24); box.set_margin_bottom(24)

        tg = Adw.PreferencesGroup()
        tg.set_title("Tor integration")
        for title, sub, active in [
            ("Route traffic through Tor", "All non-VPN TCP via transparent proxy", False),
            ("Tor over VPN", "VPN first, then Tor (recommended)", True),
            ("Block non-Tor leaks", "Hard nftables rule: Tor or nothing", False),
        ]:
            tg.add(BastilleRow(title, sub, toggle=True, toggle_active=active))
        box.append(tg)

        mg = Adw.PreferencesGroup()
        mg.set_title("Metadata stripping")
        for title, sub in [
            ("Strip EXIF on share", "Remove photo metadata before sending"),
            ("PDF metadata wipe", "MAT2 on every exported PDF"),
            ("Randomise MAC at boot", "New hardware address each session"),
        ]:
            mg.add(BastilleRow(title, sub, toggle=True, toggle_active=True))
        box.append(mg)

        tg2 = Adw.PreferencesGroup()
        tg2.set_title("Timezone & locale")
        for title, sub in [
            ("Force UTC timezone", "Prevents time-zone fingerprinting"),
            ("Uniform locale (en_US)", "Resist language-based fingerprinting"),
        ]:
            tg2.add(BastilleRow(title, sub, toggle=True, toggle_active=True))
        box.append(tg2)

        self.set_child(box)


class USBSecurityPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32); box.set_margin_end(32)
        box.set_margin_top(24); box.set_margin_bottom(24)

        ug = Adw.PreferencesGroup()
        ug.set_title("USBGuard")
        ug.set_description("Blocks all new USB devices unless explicitly authorised")
        r1 = BastilleRow("USBGuard enforcing", "New USB devices are blocked by default",
                         "drive-removable-media-symbolic", toggle=True, toggle_active=True)
        r2 = BastilleRow("Allow USB hubs", "Permit hub enumeration", toggle=True, toggle_active=True)
        r3 = BastilleRow("Allow HID keyboards/mice", "Auto-permit input devices", toggle=True, toggle_active=True)
        r4 = BastilleRow("Allow boot-time devices", "Permit devices present at boot", toggle=True, toggle_active=True)
        ug.add(r1); ug.add(r2); ug.add(r3); ug.add(r4)
        box.append(ug)

        # Authorised devices list
        ag = Adw.PreferencesGroup()
        ag.set_title("Authorised devices")
        ag.set_description("Devices always permitted regardless of attach time")
        r_add = Adw.ActionRow()
        r_add.set_title("Authorise connected device")
        r_add.set_subtitle("Temporarily permit the currently attached device")
        r_add.set_activatable(True)
        btn = Gtk.Button.new_with_label("Authorise")
        btn.add_css_class("pill"); btn.add_css_class("suggested-action")
        btn.set_valign(Gtk.Align.CENTER)
        r_add.add_suffix(btn)
        ag.add(r_add)
        box.append(ag)

        self.set_child(box)


class AppearancePage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32); box.set_margin_end(32)
        box.set_margin_top(24); box.set_margin_bottom(24)

        ag = Adw.PreferencesGroup()
        ag.set_title("Theme")
        r_dark = Adw.ActionRow()
        r_dark.set_title("Colour scheme")
        combo = Adw.ComboRow()
        combo.set_title("Colour scheme")
        combo.set_model(Gtk.StringList.new(["Dark (Bastille)", "Light", "System"]))
        combo.set_selected(0)
        combo.connect("notify::selected", self._on_scheme)
        ag.add(combo)

        accent = Adw.ComboRow()
        accent.set_title("Accent colour")
        accent.set_model(Gtk.StringList.new(["Bastille Blue", "Red", "Green", "Purple", "Orange"]))
        accent.set_selected(0)
        ag.add(accent)

        font_row = Adw.ActionRow()
        font_row.set_title("Interface font")
        font_row.set_subtitle("IBM Plex Sans — 11pt")
        font_row.set_activatable(True)
        ag.add(font_row)

        mono_row = Adw.ActionRow()
        mono_row.set_title("Monospace font")
        mono_row.set_subtitle("IBM Plex Mono — 11pt")
        mono_row.set_activatable(True)
        ag.add(mono_row)
        box.append(ag)

        wm = Adw.PreferencesGroup()
        wm.set_title("Window manager")
        wm_combo = Adw.ComboRow()
        wm_combo.set_title("Desktop environment")
        wm_combo.set_subtitle("Requires logout to apply")
        wm_combo.set_model(Gtk.StringList.new(["Sway (Wayland, tiling)", "GNOME (Wayland)", "KDE Plasma (Wayland)"]))
        wm_combo.set_selected(0)
        wm.add(wm_combo)
        box.append(wm)

        self.set_child(box)

    def _on_scheme(self, combo, _):
        mgr = Adw.StyleManager.get_default()
        idx = combo.get_selected()
        mgr.set_color_scheme([
            Adw.ColorScheme.FORCE_DARK,
            Adw.ColorScheme.FORCE_LIGHT,
            Adw.ColorScheme.DEFAULT,
        ][idx])


class PersistencePage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32); box.set_margin_end(32)
        box.set_margin_top(24); box.set_margin_bottom(24)

        pg = Adw.PreferencesGroup()
        pg.set_title("LUKS2 persistence volume")
        pg.set_description("Encrypted persistent storage on the boot medium")

        # Status
        status_row = Adw.ActionRow()
        status_row.set_title("Persistence status")
        try:
            out = subprocess.check_output(
                ["thl-persist-setup", "--status"], text=True, stderr=subprocess.DEVNULL)
            status_row.set_subtitle(out.strip()[:80])
        except Exception:
            status_row.set_subtitle("Not active or not available")
        pg.add(status_row)

        r_create = Adw.ActionRow()
        r_create.set_title("Create persistence volume")
        r_create.set_subtitle("Format a partition with LUKS2+argon2id")
        r_create.set_activatable(True)
        btn = Gtk.Button.new_with_label("Create…")
        btn.add_css_class("pill"); btn.add_css_class("suggested-action")
        btn.set_valign(Gtk.Align.CENTER)
        r_create.add_suffix(btn)
        pg.add(r_create)

        r_nuke = Adw.ActionRow()
        r_nuke.set_title("Nuke persistence volume")
        r_nuke.set_subtitle("Permanently destroy all persistent data")
        r_nuke.set_activatable(True)
        btn2 = Gtk.Button.new_with_label("Nuke")
        btn2.add_css_class("pill"); btn2.add_css_class("destructive-action")
        btn2.set_valign(Gtk.Align.CENTER)
        r_nuke.add_suffix(btn2)
        pg.add(r_nuke)
        box.append(pg)

        ig = Adw.PreferencesGroup()
        ig.set_title("Install to disk")
        ig.set_description("Full LUKS2-encrypted installation (not live mode)")
        r_install = Adw.ActionRow()
        r_install.set_title("Install Bastille OS to disk")
        r_install.set_subtitle("Overwrites target disk — runs bastille-install wizard")
        r_install.set_activatable(True)
        btn3 = Gtk.Button.new_with_label("Install…")
        btn3.add_css_class("pill")
        btn3.set_valign(Gtk.Align.CENTER)
        btn3.connect("clicked", lambda _: subprocess.Popen(
            ["bastille-install"], start_new_session=True))
        r_install.add_suffix(btn3)
        ig.add(r_install)
        box.append(ig)

        self.set_child(box)


class UpdatesPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32); box.set_margin_end(32)
        box.set_margin_top(24); box.set_margin_bottom(24)

        ug = Adw.PreferencesGroup()
        ug.set_title("OS updates")
        ug.set_description("In-place squashfs update verified against GitHub Releases SHA256")

        ver = read_file("/etc/bastille/version", "unknown")
        r_ver = Adw.ActionRow()
        r_ver.set_title("Installed version")
        r_ver.set_subtitle(ver)
        ug.add(r_ver)

        r_check = Adw.ActionRow()
        r_check.set_title("Check for updates")
        r_check.set_subtitle("Queries GitHub Releases API")
        r_check.set_activatable(True)
        btn = Gtk.Button.new_with_label("Check now")
        btn.add_css_class("pill")
        btn.set_valign(Gtk.Align.CENTER)
        btn.connect("clicked", lambda _: self._check_update())
        r_check.add_suffix(btn)
        ug.add(r_check)

        r_auto = BastilleRow("Check at boot", "Run bastille-update check on startup",
                             toggle=True, toggle_active=True)
        ug.add(r_auto)
        box.append(ug)

        self.set_child(box)

    def _check_update(self):
        try:
            out = subprocess.check_output(
                ["bastille-update", "check"], text=True, stderr=subprocess.STDOUT, timeout=30)
            dlg = Adw.MessageDialog.new(None)
            dlg.set_heading("Update check")
            dlg.set_body(out.strip())
            dlg.add_response("ok", "OK")
            dlg.present()
        except Exception as e:
            print(str(e), file=sys.stderr)


class ApplicationsPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32); box.set_margin_end(32)
        box.set_margin_top(24); box.set_margin_bottom(24)

        ig = Adw.PreferencesGroup()
        ig.set_title("Installed applications")
        ig.set_description("Applications in the Bastille verified catalogue")

        for name, pkg, icon, installed in [
            ("Tor Browser", "torbrowser-launcher", "web-browser-symbolic", False),
            ("Signal", "signal-desktop", "chat-symbolic", False),
            ("OnionShare", "onionshare", "emblem-shared-symbolic", False),
            ("KeePassXC", "keepassxc", "dialog-password-symbolic", True),
            ("Thunderbird", "thunderbird", "mail-unread-symbolic", True),
            ("Kleopatra (GPG)", "kleopatra", "security-high-symbolic", False),
            ("Metadata Cleaner", "metadata-cleaner", "document-edit-symbolic", False),
            ("Veracrypt", "veracrypt", "drive-harddisk-symbolic", False),
        ]:
            r = Adw.ActionRow()
            r.set_title(name)
            r.set_subtitle(pkg)
            img = Gtk.Image.new_from_icon_name(icon)
            img.set_pixel_size(24)
            r.add_prefix(img)
            btn = Gtk.Button.new_with_label("Remove" if installed else "Install")
            btn.add_css_class("pill")
            if not installed:
                btn.add_css_class("suggested-action")
            else:
                btn.add_css_class("destructive-action")
            btn.set_valign(Gtk.Align.CENTER)
            r.add_suffix(btn)
            ig.add(r)
        box.append(ig)

        self.set_child(box)


class UsersPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32); box.set_margin_end(32)
        box.set_margin_top(24); box.set_margin_bottom(24)

        ug = Adw.PreferencesGroup()
        ug.set_title("User accounts")
        ug.set_description("No account has sudo. System changes go through polkit helpers.")

        r = Adw.ActionRow()
        r.set_title("user")
        r.set_subtitle("Standard account — no administrator privileges")
        img = Gtk.Image.new_from_icon_name("avatar-default-symbolic")
        img.set_pixel_size(32)
        r.add_prefix(img)
        ug.add(r)

        r2 = Adw.ActionRow()
        r2.set_title("Change password")
        r2.set_activatable(True)
        btn = Gtk.Button.new_with_label("Change…")
        btn.add_css_class("pill")
        btn.set_valign(Gtk.Align.CENTER)
        r2.add_suffix(btn)
        ug.add(r2)
        box.append(ug)

        self.set_child(box)


# ── Additional security pages ──────────────────────────────────────────────────

class KernelBootPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32); box.set_margin_end(32)
        box.set_margin_top(24); box.set_margin_bottom(24)

        kg = Adw.PreferencesGroup()
        kg.set_title("Kernel hardening")
        kg.set_description("sysctl parameters applied at boot via /etc/sysctl.d/99-bastille.conf")
        for title, sub, val in [
            ("kptr_restrict", "Hide kernel pointer addresses (2 = always hidden)", "2"),
            ("dmesg_restrict", "Restrict dmesg to root only", "1"),
            ("ptrace_scope", "Block ptrace except root (3 = fully disabled)", "3"),
            ("unprivileged_bpf", "Disable unprivileged eBPF", "1"),
            ("perf_event_paranoid", "Disallow perf counters for unprivileged users (3)", "3"),
        ]:
            r = Adw.ActionRow()
            r.set_title(title)
            r.set_subtitle(sub)
            lbl = Gtk.Label(label=val)
            lbl.add_css_class("caption"); lbl.add_css_class("accent")
            r.add_suffix(lbl)
            kg.add(r)
        box.append(kg)

        mg = Adw.PreferencesGroup()
        mg.set_title("CPU mitigations")
        for title, sub in [
            ("Spectre/Meltdown", "mitigations=auto,nosmt kernel cmdline"),
            ("SMT disabled", "Hyper-threading off to block cross-thread attacks"),
            ("IOMMU enabled", "intel_iommu=on or amd_iommu=on"),
        ]:
            r = BastilleRow(title, sub, "emblem-system-symbolic", toggle=True, toggle_active=True)
            mg.add(r)
        box.append(mg)

        bg = Adw.PreferencesGroup()
        bg.set_title("Boot integrity")
        r1 = BastilleRow("Secure Boot", "Custom MOK enrolled, shim + grub signed", "security-high-symbolic", toggle=True, toggle_active=True)
        r2 = BastilleRow("Measured boot (TPM2)", "Extend PCRs; seal LUKS key to boot state", "emblem-system-symbolic", toggle=True, toggle_active=False)
        r3 = BastilleRow("GRUB password", "Require passphrase to edit boot entries", "dialog-password-symbolic", toggle=True, toggle_active=True)
        bg.add(r1); bg.add(r2); bg.add(r3)
        box.append(bg)

        adv = CodeBox(read_file("/etc/sysctl.d/99-bastille.conf"))
        apply_btn = Gtk.Button.new_with_label("Apply sysctl")
        apply_btn.add_css_class("suggested-action")
        apply_btn.set_halign(Gtk.Align.END)
        apply_btn.set_margin_end(32)
        apply_btn.connect("clicked", lambda _: pkexec("sysctl", "-p", "/etc/sysctl.d/99-bastille.conf"))

        visual = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        visual.append(kg); visual.append(mg); visual.append(bg)

        self.set_child(DualView(visual, adv))


class DiskEncryptionPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32); box.set_margin_end(32)
        box.set_margin_top(24); box.set_margin_bottom(24)

        sg = Adw.PreferencesGroup()
        sg.set_title("LUKS2 status")
        luks_info = read_file("/etc/crypttab")
        r = Adw.ActionRow()
        r.set_title("Encryption scheme")
        r.set_subtitle("LUKS2 / aes-xts-plain64 / argon2id KDF")
        icon = Gtk.Image.new_from_icon_name("channel-secure-symbolic")
        r.add_prefix(icon)
        sg.add(r)
        r2 = BastilleRow("TRIM discard", "Allow discard for SSDs (reduces metadata security)", "drive-harddisk-symbolic", toggle=True, toggle_active=False)
        r3 = BastilleRow("Suspend-to-RAM allowed", "Lock LUKS slot on suspend", "system-suspend-symbolic", toggle=True, toggle_active=False)
        sg.add(r2); sg.add(r3)
        box.append(sg)

        hg = Adw.PreferencesGroup()
        hg.set_title("Header backup")
        hg_r = Adw.ActionRow()
        hg_r.set_title("Backup LUKS header")
        hg_r.set_subtitle("Export header to encrypted USB backup")
        btn = Gtk.Button.new_with_label("Backup now")
        btn.set_valign(Gtk.Align.CENTER)
        btn.add_css_class("pill")
        btn.connect("clicked", lambda _: self._backup_header())
        hg_r.add_suffix(btn)
        hg.add(hg_r)
        box.append(hg)

        pg = Adw.PreferencesGroup()
        pg.set_title("Passphrase management")
        chg_r = Adw.ActionRow()
        chg_r.set_title("Change passphrase")
        chg_r.set_subtitle("Rotate LUKS slot 0 passphrase")
        chg_btn = Gtk.Button.new_with_label("Change…")
        chg_btn.set_valign(Gtk.Align.CENTER)
        chg_btn.add_css_class("pill")
        chg_btn.add_css_class("destructive-action")
        chg_r.add_suffix(chg_btn)
        pg.add(chg_r)
        box.append(pg)

        adv = CodeBox(luks_info or "# /etc/crypttab not found")
        self.set_child(DualView(box, adv))

    def _backup_header(self):
        pkexec("/usr/local/sbin/bastille-luks-backup")


class AppArmorPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32); box.set_margin_end(32)
        box.set_margin_top(24); box.set_margin_bottom(24)

        sg = Adw.PreferencesGroup()
        sg.set_title("AppArmor status")
        r = BastilleRow("AppArmor enforcing", "Mandatory access control active", "security-high-symbolic", toggle=True, toggle_active=True,
                        on_toggle=lambda v: pkexec("aa-teardown" if not v else "aa-enforce", "/etc/apparmor.d/*"))
        sg.add(r)
        box.append(sg)

        pg = Adw.PreferencesGroup()
        pg.set_title("Profiles")
        pg.set_description("Manage individual AppArmor profiles")
        profiles = self._get_profiles()
        for name, mode in profiles[:20]:
            row = Adw.ActionRow()
            row.set_title(name)
            row.set_subtitle(mode)
            badge = Gtk.Label(label=mode)
            badge.add_css_class("caption")
            badge.add_css_class("accent" if mode == "enforce" else "warning")
            row.add_suffix(badge)
            pg.add(row)
        box.append(pg)

        adv = CodeBox("# AppArmor profiles in /etc/apparmor.d/\n" + "\n".join(f"# {n} ({m})" for n, m in profiles[:20]))
        self.set_child(DualView(box, adv))

    def _get_profiles(self):
        try:
            import subprocess
            r = subprocess.run(["aa-status", "--json"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                import json
                data = json.loads(r.stdout)
                result = []
                for name in data.get("profiles", {}).get("enforce", []):
                    result.append((name, "enforce"))
                for name in data.get("profiles", {}).get("complain", []):
                    result.append((name, "complain"))
                return result
        except Exception:
            pass
        return [("bastille-browser", "enforce"), ("bastille-terminal", "enforce"),
                ("bastille-mail", "enforce"), ("bastille-messages", "enforce"),
                ("evince", "enforce"), ("libreoffice", "complain")]


class HardwareSecurityPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32); box.set_margin_end(32)
        box.set_margin_top(24); box.set_margin_bottom(24)

        ug = Adw.PreferencesGroup()
        ug.set_title("USBGuard")
        ug.set_description("Block unauthorized USB devices at kernel level")
        r1 = BastilleRow("USBGuard daemon", "Block all USB by default-deny policy", "drive-removable-media-symbolic", toggle=True, toggle_active=True,
                         on_toggle=lambda v: pkexec("systemctl", "start" if v else "stop", "usbguard"))
        ug.add(r1)

        allow_row = Adw.ActionRow()
        allow_row.set_title("Allow connected device")
        allow_row.set_subtitle("Whitelist currently attached USB devices")
        allow_btn = Gtk.Button.new_with_label("Allow all now")
        allow_btn.set_valign(Gtk.Align.CENTER)
        allow_btn.add_css_class("pill")
        allow_btn.connect("clicked", lambda _: pkexec("usbguard", "allow-device", "-p"))
        allow_row.add_suffix(allow_btn)
        ug.add(allow_row)
        box.append(ug)

        mg = Adw.PreferencesGroup()
        mg.set_title("Intel ME (Management Engine)")
        r = BastilleRow("ME neutralisation", "Set HAP bit via me_cleaner (irreversible)", "emblem-system-symbolic", toggle=True, toggle_active=True)
        mg.add(r)
        box.append(mg)

        tg = Adw.PreferencesGroup()
        tg.set_title("TPM2")
        for title, sub in [
            ("TPM2 available", "Hardware trusted platform module detected"),
            ("PCR0 sealed", "Measured boot seals LUKS key to PCR 0,7"),
        ]:
            r = BastilleRow(title, sub, "security-high-symbolic", toggle=True, toggle_active=True)
            tg.add(r)
        box.append(tg)

        self.set_child(box)


class ScreenLockPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32); box.set_margin_end(32)
        box.set_margin_top(24); box.set_margin_bottom(24)

        sg = Adw.PreferencesGroup()
        sg.set_title("Screen lock")
        r1 = Adw.SpinRow.new_with_range(1, 60, 1)
        r1.set_title("Lock after (minutes)")
        r1.set_subtitle("Idle timeout before screen locks")
        r1.set_value(5)
        r2 = BastilleRow("Lock on suspend", "Lock screen when suspending", "system-suspend-symbolic", toggle=True, toggle_active=True)
        r3 = BastilleRow("Lock on lid close", "Lock when laptop lid closes", "input-keyboard-symbolic", toggle=True, toggle_active=True)
        sg.add(r1); sg.add(r2); sg.add(r3)
        box.append(sg)

        ag = Adw.PreferencesGroup()
        ag.set_title("Authentication")
        r4 = BastilleRow("Require password to unlock", "PAM authentication on unlock", "dialog-password-symbolic", toggle=True, toggle_active=True)
        r5 = BastilleRow("Require PIN (extra factor)", "Second factor after password", "input-dialpad-symbolic", toggle=True, toggle_active=False)
        r6 = BastilleRow("Disable USB on lock", "rfkill + USBGuard engage on lock", "drive-removable-media-symbolic", toggle=True, toggle_active=True)
        ag.add(r4); ag.add(r5); ag.add(r6)
        box.append(ag)

        self.set_child(box)


class UpdatesIntegrityPage(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        box.set_margin_start(32); box.set_margin_end(32)
        box.set_margin_top(24); box.set_margin_bottom(24)

        ug = Adw.PreferencesGroup()
        ug.set_title("System updates")
        r1 = BastilleRow("Check for updates", "apt-get update via Tor", "software-update-available-symbolic", activatable=True)
        r2 = BastilleRow("Automatic security updates", "unattended-upgrades for security only", "security-high-symbolic", toggle=True, toggle_active=True)
        ug.add(r1); ug.add(r2)
        box.append(ug)

        ig = Adw.PreferencesGroup()
        ig.set_title("Package integrity")
        r3 = BastilleRow("Verify APT signatures", "apt-key / signed-by enforced", "channel-secure-symbolic", toggle=True, toggle_active=True)
        r4 = BastilleRow("Tor for APT", "Route apt traffic via tor proxy", "network-vpn-symbolic", toggle=True, toggle_active=True,
                         on_toggle=lambda v: pkexec("/usr/local/sbin/bastille-apt-tor", "on" if v else "off"))
        r5 = BastilleRow("Verify installed binaries", "debsums integrity check", "emblem-ok-symbolic", activatable=True)
        ig.add(r3); ig.add(r4); ig.add(r5)
        box.append(ig)

        self.set_child(box)


# ── Main window ───────────────────────────────────────────────────────────────

NAV_ITEMS = [
    ("You", [
        ("Users", "avatar-default-symbolic", UsersPage),
        ("Internet Accounts", "web-browser-symbolic", InternetAccountsPage),
    ]),
    ("Security", [
        ("Privacy & Security", "security-high-symbolic", PrivacySecurityPage),
        ("Security Pins", "dialog-password-symbolic", SecurityPinsPage),
        ("Screen Lock & Auth", "input-dialpad-symbolic", ScreenLockPage),
        ("AppArmor", "security-high-symbolic", AppArmorPage),
        ("Hardware Security", "emblem-system-symbolic", HardwareSecurityPage),
        ("Firewall", "network-firewall-symbolic", FirewallPage),
        ("VPN", "network-vpn-symbolic", VPNPage),
        ("DNS", "network-server-symbolic", DNSPage),
        ("Anonymity", "face-uncertain-symbolic", AnonymityPage),
        ("USB Security", "drive-removable-media-symbolic", USBSecurityPage),
    ]),
    ("System", [
        ("Kernel & Boot", "emblem-system-symbolic", KernelBootPage),
        ("Disk Encryption", "channel-secure-symbolic", DiskEncryptionPage),
        ("Updates & Integrity", "software-update-available-symbolic", UpdatesIntegrityPage),
        ("Appearance", "preferences-desktop-wallpaper-symbolic", AppearancePage),
        ("Displays", "video-display-symbolic", None),
        ("Sound", "audio-volume-high-symbolic", None),
        ("Keyboard", "input-keyboard-symbolic", None),
        ("Accessibility", "preferences-desktop-accessibility-symbolic", None),
        ("Notifications", "notification-symbolic", None),
    ]),
    ("Network", [
        ("Wi-Fi", "network-wireless-symbolic", None),
        ("Bluetooth", "bluetooth-symbolic", None),
    ]),
    ("Storage", [
        ("Persistence", "drive-harddisk-symbolic", PersistencePage),
        ("Updates", "software-update-available-symbolic", UpdatesPage),
    ]),
    ("Apps", [
        ("Applications", "application-x-executable-symbolic", ApplicationsPage),
        ("Printers & Scanners", "printer-symbolic", None),
    ]),
]


class BastilleSettings(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("Bastille Settings")
        self.set_default_size(900, 620)

        # Page cache
        self._pages = {}
        self._rows = {}

        split = Adw.NavigationSplitView()
        split.set_min_sidebar_width(220)
        split.set_max_sidebar_width(260)

        # Sidebar
        sidebar_nav = Adw.NavigationPage()
        sidebar_nav.set_title("Settings")
        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(False)
        sidebar_box.append(header)

        search = Gtk.SearchEntry()
        search.set_placeholder_text("Search settings")
        search.set_margin_start(12); search.set_margin_end(12)
        search.set_margin_bottom(8)
        sidebar_box.append(search)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        nav_list = Gtk.ListBox()
        nav_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        nav_list.add_css_class("navigation-sidebar")
        nav_list.connect("row-selected", self._on_nav_select)

        for section, items in NAV_ITEMS:
            lbl = Gtk.Label.new(section)
            lbl.add_css_class("heading")
            lbl.add_css_class("dim-label")
            lbl.set_halign(Gtk.Align.START)
            lbl.set_margin_start(12); lbl.set_margin_top(12); lbl.set_margin_bottom(4)
            sep_row = Gtk.ListBoxRow()
            sep_row.set_child(lbl)
            sep_row.set_selectable(False)
            sep_row.set_activatable(False)
            nav_list.append(sep_row)

            for name, icon, page_cls in items:
                row = Gtk.ListBoxRow()
                row_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
                row_box.set_margin_start(12); row_box.set_margin_end(12)
                row_box.set_margin_top(7); row_box.set_margin_bottom(7)
                img = Gtk.Image.new_from_icon_name(icon)
                img.set_pixel_size(20)
                lbl2 = Gtk.Label.new(name)
                lbl2.set_halign(Gtk.Align.START)
                lbl2.set_hexpand(True)
                row_box.append(img)
                row_box.append(lbl2)
                row.set_child(row_box)
                row._page_name = name
                row._page_cls = page_cls
                nav_list.append(row)
                self._rows[name] = row

        scroll.set_child(nav_list)
        sidebar_box.append(scroll)

        sidebar_page = Adw.ToolbarView()
        sidebar_page.set_content(sidebar_box)
        sidebar_nav.set_child(sidebar_page)

        # Content
        self._content_nav = Adw.NavigationPage()
        self._content_nav.set_title("Settings")
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self._content_header = Adw.HeaderBar()
        content_box.append(self._content_header)
        self._content_area = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self._content_area.set_vexpand(True)

        # Placeholder
        ph = Adw.StatusPage()
        ph.set_icon_name("security-high-symbolic")
        ph.set_title("Bastille Settings")
        ph.set_description("Select a category from the sidebar.")
        self._content_area.append(ph)
        self._placeholder = ph

        content_box.append(self._content_area)
        self._content_nav.set_child(content_box)

        split.set_sidebar(sidebar_nav)
        split.set_content(self._content_nav)
        self.set_content(split)

        # Select first real row
        first = self._rows.get("Privacy & Security")
        if first:
            nav_list.select_row(first)

    def _on_nav_select(self, listbox, row):
        if row is None or not hasattr(row, '_page_cls'):
            return
        name = row._page_name
        self._content_header.set_title_widget(Adw.WindowTitle.new(name, ""))
        self._content_nav.set_title(name)

        # Clear old content
        child = self._content_area.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self._content_area.remove(child)
            child = nxt

        if row._page_cls is None:
            ph = Adw.StatusPage()
            ph.set_icon_name("preferences-system-symbolic")
            ph.set_title(name)
            ph.set_description("This section is coming soon.")
            ph.set_vexpand(True)
            self._content_area.append(ph)
            return

        if name not in self._pages:
            self._pages[name] = row._page_cls()
        page = self._pages[name]
        page.set_vexpand(True)
        self._content_area.append(page)


class BastilleSettingsApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", self._on_activate)

    def _on_activate(self, app):
        mgr = Adw.StyleManager.get_default()
        mgr.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
        win = BastilleSettings(app)
        win.present()


if __name__ == "__main__":
    app = BastilleSettingsApp()
    sys.exit(app.run(sys.argv))
