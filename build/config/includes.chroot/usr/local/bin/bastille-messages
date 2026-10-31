#!/usr/bin/env python3
"""bastille-messages — Signal / Session / GPG messaging hub."""
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
import sys, json, os, subprocess, hashlib, datetime
from pathlib import Path
from gi.repository import Gtk, Adw, Gio, GLib

APP_ID = "org.bastilleos.Messages"
DATA_DIR = Path.home() / ".local/share/bastille-messages"
CONV_FILE = DATA_DIR / "conversations.json"
PINS_FILE = DATA_DIR / "pins.json"

BACKENDS = ["Signal", "Session", "GPG"]
BACKEND_ICONS = {"Signal": "security-high-symbolic", "Session": "network-vpn-symbolic", "GPG": "channel-secure-symbolic"}

def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def pin_hash(pin: str) -> str:
    return hashlib.sha256(pin.encode()).hexdigest()

def send_via_backend(backend, recipient, message):
    if backend == "Signal":
        try:
            r = subprocess.run(
                ["signal-cli", "-u", "self", "send", "-m", message, recipient],
                capture_output=True, text=True, timeout=15)
            return r.returncode == 0, r.stderr.strip()
        except FileNotFoundError:
            return False, "signal-cli not installed"
        except subprocess.TimeoutExpired:
            return False, "timed out"
    elif backend == "Session":
        try:
            r = subprocess.run(
                ["session-cli", "send", "--to", recipient, "--message", message],
                capture_output=True, text=True, timeout=15)
            return r.returncode == 0, r.stderr.strip()
        except FileNotFoundError:
            return False, "session-cli not installed"
        except subprocess.TimeoutExpired:
            return False, "timed out"
    elif backend == "GPG":
        try:
            r = subprocess.run(
                ["gpg", "--batch", "--yes", "--sign", "--encrypt", "-r", recipient],
                input=message, capture_output=True, text=True, timeout=15)
            return r.returncode == 0, r.stderr.strip()
        except FileNotFoundError:
            return False, "gpg not installed"
    return False, "unknown backend"


class MessageBubble(Gtk.Box):
    def __init__(self, text, sent=True, timestamp=""):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.set_halign(Gtk.Align.END if sent else Gtk.Align.START)
        self.set_margin_start(8 if sent else 48)
        self.set_margin_end(48 if sent else 8)
        self.set_margin_top(2)

        bubble = Gtk.Label(label=text)
        bubble.set_wrap(True)
        bubble.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        bubble.set_selectable(True)
        bubble.set_max_width_chars(50)
        bubble.set_xalign(0)
        bubble.set_margin_start(10)
        bubble.set_margin_end(10)
        bubble.set_margin_top(6)
        bubble.set_margin_bottom(6)
        if sent:
            bubble.add_css_class("accent")
        bubble.add_css_class("card")
        self.append(bubble)

        if timestamp:
            ts = Gtk.Label(label=timestamp)
            ts.add_css_class("caption")
            ts.add_css_class("dim-label")
            ts.set_halign(Gtk.Align.END if sent else Gtk.Align.START)
            self.append(ts)


class ConvRow(Adw.ActionRow):
    def __init__(self, conv_id, conv_data):
        super().__init__()
        self.conv_id = conv_id
        self.set_title(conv_data.get("name", conv_id))
        backend = conv_data.get("backend", "Signal")
        self.set_subtitle(backend)
        self.set_activatable(True)
        icon = Gtk.Image.new_from_icon_name(BACKEND_ICONS.get(backend, "user-available-symbolic"))
        self.add_prefix(icon)
        if conv_data.get("pin_protected"):
            lock = Gtk.Image.new_from_icon_name("changes-prevent-symbolic")
            lock.set_tooltip_text("PIN protected")
            self.add_suffix(lock)


class MessagesWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("Messages")
        self.set_default_size(860, 580)
        self._convs = load_json(CONV_FILE, {})
        self._pins = load_json(PINS_FILE, {})
        self._active_conv = None

        split = Adw.NavigationSplitView()
        split.set_min_sidebar_width(240)
        split.set_max_sidebar_width(300)

        # --- Sidebar ---
        sidebar_nav = Adw.NavigationPage()
        sidebar_nav.set_title("Messages")
        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        hdr = Adw.HeaderBar()
        hdr.set_title_widget(Adw.WindowTitle.new("Messages", ""))
        new_btn = Gtk.Button()
        new_btn.set_icon_name("list-add-symbolic")
        new_btn.set_tooltip_text("New conversation")
        new_btn.connect("clicked", self._new_conv)
        hdr.pack_end(new_btn)
        sidebar_box.append(hdr)

        self._list = Gtk.ListBox()
        self._list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._list.add_css_class("navigation-sidebar")
        self._list.connect("row-selected", self._on_conv_selected)

        gesture = Gtk.GestureClick()
        gesture.set_button(3)
        gesture.connect("pressed", self._on_right_click)
        self._list.add_controller(gesture)

        scroll = Gtk.ScrolledWindow()
        scroll.set_child(self._list)
        scroll.set_vexpand(True)
        sidebar_box.append(scroll)
        sidebar_nav.set_child(sidebar_box)

        # --- Content ---
        self._content_nav = Adw.NavigationPage()
        self._content_nav.set_title("Chat")
        self._content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        self._chat_hdr = Adw.HeaderBar()
        self._chat_title = Adw.WindowTitle.new("Select a conversation", "")
        self._chat_hdr.set_title_widget(self._chat_title)
        self._content_box.append(self._chat_hdr)

        self._msg_scroll = Gtk.ScrolledWindow()
        self._msg_scroll.set_vexpand(True)
        self._msg_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self._msg_box.set_margin_start(8)
        self._msg_box.set_margin_end(8)
        self._msg_box.set_margin_top(8)
        self._msg_box.set_margin_bottom(8)
        self._msg_scroll.set_child(self._msg_box)
        self._content_box.append(self._msg_scroll)

        # Compose bar
        compose = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        compose.set_margin_start(12)
        compose.set_margin_end(12)
        compose.set_margin_top(8)
        compose.set_margin_bottom(12)
        self._entry = Gtk.Entry()
        self._entry.set_hexpand(True)
        self._entry.set_placeholder_text("Message…")
        self._entry.connect("activate", self._send_message)
        send_btn = Gtk.Button()
        send_btn.set_icon_name("mail-send-symbolic")
        send_btn.add_css_class("suggested-action")
        send_btn.connect("clicked", self._send_message)
        compose.append(self._entry)
        compose.append(send_btn)
        self._content_box.append(compose)

        self._content_nav.set_child(self._content_box)

        split.set_sidebar(sidebar_nav)
        split.set_content(self._content_nav)
        self.set_content(split)

        self._populate_list()

    def _populate_list(self):
        while self._list.get_first_child():
            self._list.remove(self._list.get_first_child())
        for cid, cdata in self._convs.items():
            row = ConvRow(cid, cdata)
            self._list.append(row)

    def _on_conv_selected(self, lb, row):
        if row is None or not isinstance(row, ConvRow):
            return
        cid = row.conv_id
        cdata = self._convs.get(cid, {})
        if cdata.get("pin_protected") and cid not in getattr(self, "_unlocked", set()):
            self._prompt_pin(cid, cdata)
            return
        self._open_conv(cid, cdata)

    def _prompt_pin(self, cid, cdata):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("PIN required")
        dlg.set_body(f'Enter the PIN to view "{cdata.get("name", cid)}".')
        entry = Gtk.PasswordEntry()
        entry.set_show_peek_icon(True)
        entry.set_placeholder_text("PIN")
        entry.set_margin_start(16); entry.set_margin_end(16)
        dlg.set_extra_child(entry)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("ok", "Unlock")
        dlg.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        def resp(d, r):
            if r == "ok":
                entered = entry.get_text()
                stored = self._pins.get(cid)
                if stored is None or pin_hash(entered) == stored:
                    if not hasattr(self, "_unlocked"):
                        self._unlocked = set()
                    self._unlocked.add(cid)
                    self._open_conv(cid, cdata)
                else:
                    self._show_toast("Wrong PIN")
        dlg.connect("response", resp)
        dlg.present()

    def _open_conv(self, cid, cdata):
        self._active_conv = cid
        self._chat_title.set_title(cdata.get("name", cid))
        self._chat_title.set_subtitle(cdata.get("backend", "Signal"))
        while self._msg_box.get_first_child():
            self._msg_box.remove(self._msg_box.get_first_child())
        for msg in cdata.get("messages", []):
            bubble = MessageBubble(msg["text"], msg.get("sent", True), msg.get("time", ""))
            self._msg_box.append(bubble)
        GLib.idle_add(self._scroll_to_bottom)

    def _scroll_to_bottom(self):
        adj = self._msg_scroll.get_vadjustment()
        adj.set_value(adj.get_upper())
        return False

    def _send_message(self, *_):
        if not self._active_conv:
            return
        text = self._entry.get_text().strip()
        if not text:
            return
        cdata = self._convs[self._active_conv]
        backend = cdata.get("backend", "Signal")
        recipient = cdata.get("address", "")
        ok, err = send_via_backend(backend, recipient, text)
        now = datetime.datetime.now().strftime("%H:%M")
        msg = {"text": text, "sent": True, "time": now}
        cdata.setdefault("messages", []).append(msg)
        save_json(CONV_FILE, self._convs)
        bubble = MessageBubble(text, True, now)
        self._msg_box.append(bubble)
        self._entry.set_text("")
        GLib.idle_add(self._scroll_to_bottom)
        if not ok and err:
            self._show_toast(f"Send failed: {err}")

    def _on_right_click(self, gesture, n, x, y):
        row = self._list.get_row_at_y(int(y))
        if row is None or not isinstance(row, ConvRow):
            return
        menu = Gio.Menu()
        menu.append("Require PIN to view", f"win.set_pin::{row.conv_id}")
        menu.append("Remove PIN", f"win.remove_pin::{row.conv_id}")
        menu.append("Delete conversation", f"win.delete_conv::{row.conv_id}")
        popover = Gtk.PopoverMenu.new_from_model(menu)
        popover.set_parent(row)
        popover.set_pointing_to_rect_from_event = lambda _: None

        for cid in [row.conv_id]:
            set_pin = Gio.SimpleAction.new_with_parameter("set_pin", GLib.VariantType("s"))
            set_pin.connect("activate", lambda a, p: self._set_pin_dialog(p.get_string()))
            self.add_action(set_pin)
            rem_pin = Gio.SimpleAction.new_with_parameter("remove_pin", GLib.VariantType("s"))
            rem_pin.connect("activate", lambda a, p: self._remove_pin(p.get_string()))
            self.add_action(rem_pin)
            del_conv = Gio.SimpleAction.new_with_parameter("delete_conv", GLib.VariantType("s"))
            del_conv.connect("activate", lambda a, p: self._delete_conv(p.get_string()))
            self.add_action(del_conv)

        popover.popup()

    def _set_pin_dialog(self, cid):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Set PIN")
        dlg.set_body("Set a PIN to protect this conversation.")
        entry = Gtk.PasswordEntry()
        entry.set_show_peek_icon(True)
        entry.set_placeholder_text("New PIN")
        entry.set_margin_start(16); entry.set_margin_end(16)
        dlg.set_extra_child(entry)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("set", "Set PIN")
        dlg.set_response_appearance("set", Adw.ResponseAppearance.SUGGESTED)
        def resp(d, r):
            if r == "set" and entry.get_text():
                self._convs[cid]["pin_protected"] = True
                self._pins[cid] = pin_hash(entry.get_text())
                save_json(CONV_FILE, self._convs)
                save_json(PINS_FILE, self._pins)
                self._populate_list()
                self._show_toast("PIN set")
        dlg.connect("response", resp)
        dlg.present()

    def _remove_pin(self, cid):
        if cid in self._convs:
            self._convs[cid]["pin_protected"] = False
        self._pins.pop(cid, None)
        save_json(CONV_FILE, self._convs)
        save_json(PINS_FILE, self._pins)
        self._populate_list()
        self._show_toast("PIN removed")

    def _delete_conv(self, cid):
        self._convs.pop(cid, None)
        save_json(CONV_FILE, self._convs)
        if self._active_conv == cid:
            self._active_conv = None
            self._chat_title.set_title("Select a conversation")
            self._chat_title.set_subtitle("")
            while self._msg_box.get_first_child():
                self._msg_box.remove(self._msg_box.get_first_child())
        self._populate_list()

    def _new_conv(self, *_):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("New conversation")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(16); box.set_margin_end(16)

        name_e = Gtk.Entry(); name_e.set_placeholder_text("Contact name")
        addr_e = Gtk.Entry(); addr_e.set_placeholder_text("Phone / Session ID / GPG fingerprint")

        backend_combo = Gtk.DropDown.new_from_strings(BACKENDS)

        box.append(name_e); box.append(addr_e); box.append(backend_combo)
        dlg.set_extra_child(box)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("add", "Add")
        dlg.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)

        def resp(d, r):
            if r == "add" and name_e.get_text():
                cid = name_e.get_text().lower().replace(" ", "_")
                backend = BACKENDS[backend_combo.get_selected()]
                self._convs[cid] = {
                    "name": name_e.get_text(),
                    "address": addr_e.get_text(),
                    "backend": backend,
                    "messages": [],
                }
                save_json(CONV_FILE, self._convs)
                self._populate_list()
        dlg.connect("response", resp)
        dlg.present()

    def _show_toast(self, msg):
        overlay = Adw.ToastOverlay()
        toast = Adw.Toast.new(msg)
        toast.set_timeout(3)
        # Find existing overlay or just use a simple dialog fallback
        print(f"[bastille-messages] {msg}")


class MessagesApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", lambda a: MessagesWindow(a).present())

if __name__ == "__main__":
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    sys.exit(MessagesApp().run(sys.argv))
