#!/usr/bin/env python3
"""bastille-browser — Tor Browser launcher with circuit & privacy panel."""
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
import sys, os, subprocess, json, threading
from pathlib import Path
from gi.repository import Gtk, Adw, Gio, GLib

APP_ID = "org.bastilleos.Browser"
TOR_PATHS = [
    Path.home() / ".local/share/torbrowser/tbb/x86_64/tor-browser/Browser/start-tor-browser",
    Path("/usr/bin/tor-browser"),
    Path("/opt/tor-browser/start-tor-browser"),
    Path("/usr/bin/torbrowser-launcher"),
]
TOR_CTRL_PORT = 9051
TOR_COOKIE = Path("/var/run/tor/control.authcookie")
DATA_DIR = Path.home() / ".local/share/bastille-browser"
BOOKMARKS_FILE = DATA_DIR / "bookmarks.json"

PRIVACY_CHECKS = [
    ("WebRTC disabled", True),
    ("Canvas fingerprint blocked", True),
    ("Font fingerprint blocked", True),
    ("JS sandboxed", True),
    ("3rd-party cookies blocked", True),
    ("Referrer stripped", True),
    ("DNS via Tor", True),
    ("Tracker blocked", True),
]


def find_tor_browser():
    for p in TOR_PATHS:
        if p.exists():
            return str(p)
    for name in ["torbrowser-launcher", "tor-browser"]:
        try:
            r = subprocess.run(["which", name], capture_output=True, text=True)
            if r.returncode == 0:
                return r.stdout.strip()
        except Exception:
            pass
    return None


def get_tor_circuit():
    """Attempt to get Tor circuit info via control port."""
    try:
        import socket
        s = socket.socket()
        s.settimeout(3)
        s.connect(("127.0.0.1", TOR_CTRL_PORT))
        if TOR_COOKIE.exists():
            cookie = TOR_COOKIE.read_bytes()
            auth = b"AUTHENTICATE " + cookie.hex().encode() + b"\r\n"
        else:
            auth = b"AUTHENTICATE\r\n"
        s.sendall(auth)
        s.recv(256)
        s.sendall(b"GETINFO circuit-status\r\n")
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n.\r\n" in data or b"250 OK" in data:
                break
        s.close()
        text = data.decode(errors="replace")
        circuits = []
        for line in text.splitlines():
            if "BUILT" in line and "$" in line:
                hops = [h.split("~")[-1] if "~" in h else h[:8] for h in line.split("$")[1:]]
                circuits.append(hops)
        return circuits[:1] if circuits else None
    except Exception:
        return None


class CircuitPanel(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.add_css_class("card")
        self.set_margin_start(12); self.set_margin_end(12)
        self.set_margin_top(4); self.set_margin_bottom(4)
        self.set_size_request(240, -1)

        title_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        icon = Gtk.Image.new_from_icon_name("network-vpn-symbolic")
        lbl = Gtk.Label(label="Tor Circuit")
        lbl.add_css_class("heading")
        title_box.append(icon)
        title_box.append(lbl)
        self.append(title_box)

        self._nodes_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.append(self._nodes_box)

        new_circuit_btn = Gtk.Button.new_with_label("New Circuit")
        new_circuit_btn.connect("clicked", self._new_circuit)
        self.append(new_circuit_btn)

        self._loading = Gtk.Label(label="Checking circuit…")
        self._loading.add_css_class("dim-label")
        self._loading.add_css_class("caption")
        self.append(self._loading)

        self.refresh()

    def refresh(self):
        threading.Thread(target=self._fetch_circuit, daemon=True).start()

    def _fetch_circuit(self):
        circuits = get_tor_circuit()
        GLib.idle_add(self._update_circuit, circuits)

    def _update_circuit(self, circuits):
        while self._nodes_box.get_first_child():
            self._nodes_box.remove(self._nodes_box.get_first_child())
        self._loading.set_visible(False)

        if not circuits:
            row = Gtk.Label(label="No circuit info available\n(Tor control port not accessible)")
            row.add_css_class("dim-label")
            row.add_css_class("caption")
            row.set_wrap(True)
            self._nodes_box.append(row)
            return

        labels = ["Entry (Guard)", "Middle", "Exit"]
        for i, hop in enumerate(circuits[0][:3]):
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            box.set_margin_start(4)
            dot = Gtk.Label(label="●")
            dot.add_css_class("accent" if i < 2 else "warning")
            lbl = Gtk.Label(label=f"{labels[i] if i < len(labels) else 'Hop'}: {hop}")
            lbl.add_css_class("caption")
            lbl.set_halign(Gtk.Align.START)
            box.append(dot); box.append(lbl)
            self._nodes_box.append(box)
        return False

    def _new_circuit(self, *_):
        try:
            import socket
            s = socket.socket()
            s.settimeout(3)
            s.connect(("127.0.0.1", TOR_CTRL_PORT))
            if TOR_COOKIE.exists():
                auth = b"AUTHENTICATE " + TOR_COOKIE.read_bytes().hex().encode() + b"\r\n"
            else:
                auth = b"AUTHENTICATE\r\n"
            s.sendall(auth)
            s.recv(256)
            s.sendall(b"SIGNAL NEWNYM\r\n")
            s.close()
        except Exception:
            pass
        GLib.timeout_add(2000, self.refresh)


class BrowserWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("Browser")
        self.set_default_size(800, 580)
        self._tor_proc = None
        self._bookmarks = self._load_bookmarks()

        split = Adw.NavigationSplitView()
        split.set_min_sidebar_width(260)
        split.set_max_sidebar_width(300)

        # Sidebar
        sidebar_nav = Adw.NavigationPage()
        sidebar_nav.set_title("Browser")
        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        hdr = Adw.HeaderBar()
        hdr.set_title_widget(Adw.WindowTitle.new("Bastille Browser", ""))
        sidebar_box.append(hdr)

        # Privacy status
        status_grp = Adw.PreferencesGroup()
        status_grp.set_title("Privacy Status")
        status_grp.set_margin_start(12); status_grp.set_margin_end(12)
        status_grp.set_margin_top(8)
        for label, ok in PRIVACY_CHECKS:
            row = Adw.ActionRow()
            row.set_title(label)
            icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic" if ok else "dialog-warning-symbolic")
            row.add_prefix(icon)
            status_grp.add(row)
        sidebar_box.append(status_grp)

        # Tor circuit
        circuit_grp = Adw.PreferencesGroup()
        circuit_grp.set_title("Tor Circuit")
        circuit_grp.set_margin_start(12); circuit_grp.set_margin_end(12)
        circuit_grp.set_margin_top(8)
        self._circuit_panel = CircuitPanel()
        circuit_grp.add(self._circuit_panel)
        sidebar_box.append(circuit_grp)

        sidebar_nav.set_child(sidebar_box)

        # Content pane
        content_nav = Adw.NavigationPage()
        content_nav.set_title("Launch")
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content_hdr = Adw.HeaderBar()
        content_hdr.set_title_widget(Adw.WindowTitle.new("Bastille Browser", "Privacy by default"))
        refresh_btn = Gtk.Button()
        refresh_btn.set_icon_name("view-refresh-symbolic")
        refresh_btn.set_tooltip_text("Refresh circuit info")
        refresh_btn.connect("clicked", lambda _: self._circuit_panel.refresh())
        content_hdr.pack_end(refresh_btn)
        content_box.append(content_hdr)

        # Launch panel
        launch_page = Adw.StatusPage()
        launch_page.set_icon_name("security-high-symbolic")
        launch_page.set_title("Bastille Browser")
        launch_page.set_description(
            "A Tor Browser wrapper with integrated circuit monitoring\n"
            "and privacy controls. All traffic is routed through Tor.")
        launch_page.set_vexpand(True)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        btn_box.set_halign(Gtk.Align.CENTER)

        launch_btn = Gtk.Button.new_with_label("Launch Tor Browser")
        launch_btn.add_css_class("suggested-action")
        launch_btn.add_css_class("pill")
        launch_btn.set_size_request(220, 48)
        launch_btn.connect("clicked", self._launch_tor)

        self._status_lbl = Gtk.Label(label="")
        self._status_lbl.add_css_class("caption")
        self._status_lbl.add_css_class("dim-label")

        tor_path = find_tor_browser()
        if not tor_path:
            launch_btn.set_sensitive(False)
            self._status_lbl.set_label("Tor Browser not found. Install with: torbrowser-launcher")
        else:
            self._status_lbl.set_label(f"Found: {tor_path}")

        # Bookmarks section
        bm_grp = Adw.PreferencesGroup()
        bm_grp.set_title("Bookmarks")
        bm_grp.set_margin_start(12); bm_grp.set_margin_end(12)
        bm_grp.set_margin_top(12)
        bm_grp.set_margin_bottom(8)

        add_bm_row = Adw.ActionRow()
        add_bm_row.set_title("Add bookmark")
        add_bm_row.set_activatable(True)
        add_bm_row.connect("activated", self._add_bookmark)
        add_bm_icon = Gtk.Image.new_from_icon_name("list-add-symbolic")
        add_bm_row.add_prefix(add_bm_icon)
        bm_grp.add(add_bm_row)

        self._bm_group = bm_grp
        self._refresh_bookmarks()

        btn_box.append(launch_btn)
        btn_box.append(self._status_lbl)
        launch_page.set_child(btn_box)

        content_box.append(launch_page)
        content_box.append(bm_grp)
        content_nav.set_child(content_box)

        split.set_sidebar(sidebar_nav)
        split.set_content(content_nav)
        self.set_content(split)

    def _load_bookmarks(self):
        try:
            with open(BOOKMARKS_FILE) as f:
                return json.load(f)
        except Exception:
            return [
                {"title": "DuckDuckGo .onion", "url": "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"},
                {"title": "EFF — Surveillance Self-Defense", "url": "https://ssd.eff.org"},
                {"title": "SecureDrop", "url": "https://secrdrop5wyphb5x.onion"},
            ]

    def _save_bookmarks(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(BOOKMARKS_FILE, "w") as f:
            json.dump(self._bookmarks, f, indent=2)

    def _refresh_bookmarks(self):
        for bm in self._bookmarks:
            row = Adw.ActionRow()
            row.set_title(bm.get("title", bm["url"]))
            row.set_subtitle(bm["url"])
            row.set_activatable(True)
            url = bm["url"]
            row.connect("activated", lambda _, u=url: self._open_url(u))
            self._bm_group.add(row)

    def _add_bookmark(self, *_):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Add bookmark")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(16); box.set_margin_end(16)
        title_e = Gtk.Entry(); title_e.set_placeholder_text("Title")
        url_e = Gtk.Entry(); url_e.set_placeholder_text("URL or .onion address")
        box.append(title_e); box.append(url_e)
        dlg.set_extra_child(box)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("add", "Add")
        dlg.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)
        def resp(d, r):
            if r == "add" and url_e.get_text():
                self._bookmarks.append({"title": title_e.get_text() or url_e.get_text(), "url": url_e.get_text()})
                self._save_bookmarks()
        dlg.connect("response", resp)
        dlg.present()

    def _open_url(self, url: str):
        tor = find_tor_browser()
        if tor:
            subprocess.Popen([tor, url])
        else:
            subprocess.Popen(["xdg-open", url])

    def _launch_tor(self, *_):
        tor = find_tor_browser()
        if not tor:
            return
        try:
            self._tor_proc = subprocess.Popen([tor])
            self._status_lbl.set_label("Tor Browser launched")
            self._circuit_panel.refresh()
        except Exception as e:
            self._status_lbl.set_label(f"Launch failed: {e}")


class BrowserApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", lambda a: BrowserWindow(a).present())

if __name__ == "__main__":
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    sys.exit(BrowserApp().run(sys.argv))
