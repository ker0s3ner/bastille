#!/usr/bin/env python3
"""bastille-mail — Privacy-first mail client with GPG, notmuch, and disposable addresses."""
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
gi.require_version('Soup', '3.0')
import sys, json, os, subprocess, re, datetime
from pathlib import Path
from gi.repository import Gtk, Adw, Gio, GLib, Soup

APP_ID = "org.bastilleos.Mail"
DATA_DIR = Path.home() / ".local/share/bastille-mail"
ACCOUNTS_FILE = DATA_DIR / "accounts.json"
MESSAGES_FILE = DATA_DIR / "messages.json"
GUERRILLA_API = "https://api.guerrillamail.com/ajax"

EVENT_RE = re.compile(
    r'\b(?:meet(?:ing)?|call|appointment|zoom|event|conference|interview)\b.*?'
    r'(?:on|at|this|next)?\s*'
    r'(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday|'
    r'\d{1,2}[/\-]\d{1,2}|\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec))',
    re.IGNORECASE
)

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

def detect_events(body: str) -> list:
    return EVENT_RE.findall(body)

def gpg_encrypt(text: str, recipient: str) -> tuple:
    try:
        r = subprocess.run(
            ["gpg", "--batch", "--yes", "--encrypt", "--armor", "-r", recipient],
            input=text, capture_output=True, text=True, timeout=15)
        return r.returncode == 0, r.stdout, r.stderr
    except FileNotFoundError:
        return False, "", "gpg not found"

def gpg_sign(text: str) -> tuple:
    try:
        r = subprocess.run(
            ["gpg", "--batch", "--yes", "--clearsign"],
            input=text, capture_output=True, text=True, timeout=15)
        return r.returncode == 0, r.stdout, r.stderr
    except FileNotFoundError:
        return False, "", "gpg not found"


class MessageRow(Adw.ActionRow):
    def __init__(self, msg):
        super().__init__()
        self.msg = msg
        self.set_title(msg.get("subject", "(no subject)"))
        self.set_subtitle(msg.get("from", ""))
        self.set_activatable(True)
        if not msg.get("read"):
            self.add_css_class("bold")
        if msg.get("gpg_signed"):
            lock = Gtk.Image.new_from_icon_name("channel-secure-symbolic")
            lock.set_tooltip_text("GPG signed")
            self.add_suffix(lock)
        ts = Gtk.Label(label=msg.get("date", ""))
        ts.add_css_class("caption")
        ts.add_css_class("dim-label")
        self.add_suffix(ts)


class ComposeWindow(Adw.Window):
    def __init__(self, parent, accounts, reply_to=None):
        super().__init__(transient_for=parent, modal=True)
        self.set_title("Compose")
        self.set_default_size(640, 480)
        self._accounts = accounts
        self._reply_to = reply_to

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        hdr = Adw.HeaderBar()
        send_btn = Gtk.Button.new_with_label("Send")
        send_btn.add_css_class("suggested-action")
        send_btn.connect("clicked", self._send)
        hdr.pack_end(send_btn)
        box.append(hdr)

        grp = Adw.PreferencesGroup()
        grp.set_margin_start(12); grp.set_margin_end(12); grp.set_margin_top(8)

        self._to = Adw.EntryRow(); self._to.set_title("To")
        self._subject = Adw.EntryRow(); self._subject.set_title("Subject")
        if reply_to:
            self._to.set_text(reply_to.get("from", ""))
            self._subject.set_text("Re: " + reply_to.get("subject", ""))

        self._from_row = Adw.ComboRow()
        self._from_row.set_title("From")
        acc_names = Gtk.StringList()
        for a in accounts:
            acc_names.append(a.get("address", ""))
        self._from_row.set_model(acc_names)

        self._gpg_enc = Adw.SwitchRow(); self._gpg_enc.set_title("GPG Encrypt")
        self._gpg_sign_row = Adw.SwitchRow(); self._gpg_sign_row.set_title("GPG Sign")

        for r in [self._to, self._subject, self._from_row, self._gpg_enc, self._gpg_sign_row]:
            grp.add(r)
        box.append(grp)

        self._tv = Gtk.TextView()
        self._tv.set_wrap_mode(Gtk.WrapMode.WORD)
        self._tv.set_left_margin(16); self._tv.set_right_margin(16)
        self._tv.set_top_margin(8); self._tv.set_bottom_margin(8)
        sw = Gtk.ScrolledWindow()
        sw.set_child(self._tv)
        sw.set_vexpand(True)
        sw.set_margin_start(12); sw.set_margin_end(12); sw.set_margin_bottom(12)
        box.append(sw)
        self.set_content(box)

    def _send(self, *_):
        buf = self._tv.get_buffer()
        body = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
        to_addr = self._to.get_text()
        subject = self._subject.get_text()
        if self._gpg_enc.get_active():
            ok, body, err = gpg_encrypt(body, to_addr)
            if not ok:
                self._show_err(f"GPG encrypt failed: {err}")
                return
        elif self._gpg_sign_row.get_active():
            ok, body, err = gpg_sign(body)
            if not ok:
                self._show_err(f"GPG sign failed: {err}")
                return
        try:
            subprocess.run(
                ["msmtp", to_addr],
                input=f"To: {to_addr}\nSubject: {subject}\n\n{body}",
                text=True, timeout=30, check=True)
            self.close()
        except FileNotFoundError:
            self._show_err("msmtp not installed — message not sent")
        except subprocess.CalledProcessError as e:
            self._show_err(f"Send error: {e}")

    def _show_err(self, msg):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Error")
        dlg.set_body(msg)
        dlg.add_response("ok", "OK")
        dlg.present()


class MailWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("Mail")
        self.set_default_size(960, 600)
        self._accounts = load_json(ACCOUNTS_FILE, [])
        self._messages = load_json(MESSAGES_FILE, {"inbox": []})
        self._current_folder = "inbox"
        self._soup = Soup.Session()
        self._guerrilla_email = None

        # 3-pane layout: folder sidebar | message list | message view
        paned_outer = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned_inner = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)

        # Folder sidebar
        folder_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        hdr = Adw.HeaderBar()
        hdr.set_title_widget(Adw.WindowTitle.new("Mail", ""))
        compose_btn = Gtk.Button()
        compose_btn.set_icon_name("mail-send-symbolic")
        compose_btn.set_tooltip_text("Compose")
        compose_btn.connect("clicked", self._compose)
        hdr.pack_end(compose_btn)
        folder_box.append(hdr)

        folder_list = Gtk.ListBox()
        folder_list.add_css_class("navigation-sidebar")
        folder_list.connect("row-selected", self._on_folder_selected)

        folders = [
            ("Inbox", "mail-inbox-symbolic"),
            ("Sent", "mail-sent-symbolic"),
            ("Drafts", "mail-draft-symbolic"),
            ("Trash", "user-trash-symbolic"),
        ]
        self._folder_rows = {}
        for name, icon in folders:
            row = Adw.ActionRow()
            row.set_title(name)
            row.set_activatable(True)
            img = Gtk.Image.new_from_icon_name(icon)
            row.add_prefix(img)
            folder_list.append(row)
            self._folder_rows[name.lower()] = row

        sep = Gtk.Separator()
        sep.set_margin_top(8); sep.set_margin_bottom(4)

        disp_row = Adw.ActionRow()
        disp_row.set_title("Get Disposable Address")
        disp_row.set_subtitle("via Guerrilla Mail")
        disp_row.set_activatable(True)
        disp_img = Gtk.Image.new_from_icon_name("mail-unread-symbolic")
        disp_row.add_prefix(disp_img)
        disp_row.connect("activated", self._get_disposable)

        folder_scroll = Gtk.ScrolledWindow()
        folder_scroll.set_vexpand(True)
        inner_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        inner_box.append(folder_list)
        inner_box.append(sep)
        inner_box.append(disp_row)
        folder_scroll.set_child(inner_box)
        folder_box.append(folder_scroll)

        # Message list
        msg_list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        msg_hdr = Adw.HeaderBar()
        self._folder_title = Adw.WindowTitle.new("Inbox", "")
        msg_hdr.set_title_widget(self._folder_title)
        refresh_btn = Gtk.Button()
        refresh_btn.set_icon_name("view-refresh-symbolic")
        refresh_btn.connect("clicked", self._refresh)
        msg_hdr.pack_end(refresh_btn)
        msg_list_box.append(msg_hdr)

        self._msg_list = Gtk.ListBox()
        self._msg_list.add_css_class("boxed-list")
        self._msg_list.set_margin_start(8); self._msg_list.set_margin_end(8)
        self._msg_list.set_margin_top(8)
        self._msg_list.connect("row-selected", self._on_message_selected)
        msg_scroll = Gtk.ScrolledWindow()
        msg_scroll.set_child(self._msg_list)
        msg_scroll.set_vexpand(True)
        msg_list_box.append(msg_scroll)

        # Message view
        view_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        view_hdr = Adw.HeaderBar()
        reply_btn = Gtk.Button()
        reply_btn.set_icon_name("mail-reply-sender-symbolic")
        reply_btn.set_tooltip_text("Reply")
        reply_btn.connect("clicked", self._reply)
        self._cal_btn = Gtk.Button()
        self._cal_btn.set_icon_name("x-office-calendar-symbolic")
        self._cal_btn.set_tooltip_text("Add detected event to calendar")
        self._cal_btn.set_visible(False)
        self._cal_btn.connect("clicked", self._add_to_calendar)
        view_hdr.pack_end(reply_btn)
        view_hdr.pack_end(self._cal_btn)
        view_box.append(view_hdr)

        self._msg_meta = Adw.PreferencesGroup()
        self._msg_meta.set_margin_start(12); self._msg_meta.set_margin_end(12)
        self._msg_meta.set_margin_top(8); self._msg_meta.set_margin_bottom(0)
        self._from_lbl = Adw.ActionRow(); self._from_lbl.set_title("From")
        self._date_lbl = Adw.ActionRow(); self._date_lbl.set_title("Date")
        self._subj_lbl = Adw.ActionRow(); self._subj_lbl.set_title("Subject")
        self._msg_meta.add(self._from_lbl); self._msg_meta.add(self._date_lbl)
        self._msg_meta.add(self._subj_lbl)
        view_box.append(self._msg_meta)

        self._body_tv = Gtk.TextView()
        self._body_tv.set_editable(False)
        self._body_tv.set_wrap_mode(Gtk.WrapMode.WORD)
        self._body_tv.set_left_margin(16); self._body_tv.set_right_margin(16)
        self._body_tv.set_top_margin(12); self._body_tv.set_bottom_margin(12)
        body_scroll = Gtk.ScrolledWindow()
        body_scroll.set_child(self._body_tv)
        body_scroll.set_vexpand(True)
        view_box.append(body_scroll)

        paned_outer.set_start_child(folder_box)
        paned_outer.set_end_child(paned_inner)
        paned_outer.set_position(200)
        paned_inner.set_start_child(msg_list_box)
        paned_inner.set_end_child(view_box)
        paned_inner.set_position(280)

        self.set_content(paned_outer)
        self._load_folder("inbox")
        self._current_msg = None

    def _on_folder_selected(self, lb, row):
        if row is None:
            return
        for name, r in self._folder_rows.items():
            if r is row:
                self._load_folder(name)
                break

    def _load_folder(self, folder):
        self._current_folder = folder
        self._folder_title.set_title(folder.capitalize())
        while self._msg_list.get_first_child():
            self._msg_list.remove(self._msg_list.get_first_child())
        msgs = self._messages.get(folder, [])
        if not msgs:
            row = Adw.ActionRow()
            row.set_title("No messages")
            self._msg_list.append(row)
            return
        for msg in msgs:
            self._msg_list.append(MessageRow(msg))

    def _on_message_selected(self, lb, row):
        if row is None or not isinstance(row, MessageRow):
            return
        msg = row.msg
        self._current_msg = msg
        msg["read"] = True
        save_json(MESSAGES_FILE, self._messages)
        self._from_lbl.set_subtitle(msg.get("from", ""))
        self._date_lbl.set_subtitle(msg.get("date", ""))
        self._subj_lbl.set_subtitle(msg.get("subject", ""))
        body = msg.get("body", "")
        self._body_tv.get_buffer().set_text(body)
        events = detect_events(body)
        self._cal_btn.set_visible(bool(events))
        if events:
            self._detected_events = events

    def _compose(self, *_):
        w = ComposeWindow(self, self._accounts)
        w.present()

    def _reply(self, *_):
        if not self._current_msg:
            return
        w = ComposeWindow(self, self._accounts, reply_to=self._current_msg)
        w.present()

    def _add_to_calendar(self, *_):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Add to Calendar")
        events = getattr(self, "_detected_events", [])
        body = "Detected events:\n" + "\n".join(f"• {e}" for e in events[:5])
        dlg.set_body(body)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("add", "Add to Calendar")
        dlg.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)
        def resp(d, r):
            if r == "add":
                try:
                    subprocess.Popen(["bastille-calendar"])
                except Exception:
                    pass
        dlg.connect("response", resp)
        dlg.present()

    def _refresh(self, *_):
        try:
            r = subprocess.run(
                ["notmuch", "new"],
                capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                self._load_from_notmuch()
        except FileNotFoundError:
            pass

    def _load_from_notmuch(self):
        try:
            r = subprocess.run(
                ["notmuch", "search", "--format=json", "--output=messages",
                 "tag:inbox", "date:1w.."],
                capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                msg_ids = json.loads(r.stdout)
                msgs = []
                for mid in msg_ids[:50]:
                    show = subprocess.run(
                        ["notmuch", "show", "--format=json", mid],
                        capture_output=True, text=True, timeout=15)
                    if show.returncode == 0:
                        data = json.loads(show.stdout)
                        if data and data[0] and data[0][0]:
                            headers = data[0][0][0].get("headers", {})
                            body_parts = data[0][0][0].get("body", [{}])
                            body = body_parts[0].get("content", "") if body_parts else ""
                            msgs.append({
                                "from": headers.get("From", ""),
                                "subject": headers.get("Subject", ""),
                                "date": headers.get("Date", ""),
                                "body": body,
                                "read": False,
                            })
                self._messages["inbox"] = msgs
                save_json(MESSAGES_FILE, self._messages)
                self._load_folder("inbox")
        except Exception:
            pass

    def _get_disposable(self, *_):
        msg = Soup.Message.new("GET", f"{GUERRILLA_API}?f=get_email_address&lang=en")
        self._soup.send_and_read_async(msg, GLib.PRIORITY_DEFAULT, None, self._on_guerrilla_response)

    def _on_guerrilla_response(self, session, result):
        try:
            data_bytes = session.send_and_read_finish(result)
            data = json.loads(data_bytes.get_data().decode())
            email = data.get("email_addr", "")
            self._guerrilla_email = email
            GLib.idle_add(self._show_disposable_addr, email)
        except Exception as e:
            GLib.idle_add(self._show_disposable_err, str(e))

    def _show_disposable_addr(self, email):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Disposable Address")
        dlg.set_body(f"Your temporary address:\n\n{email}\n\nMessages will appear in your inbox.")
        dlg.add_response("ok", "OK")
        dlg.present()
        return False

    def _show_disposable_err(self, err):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Error")
        dlg.set_body(f"Could not get disposable address:\n{err}")
        dlg.add_response("ok", "OK")
        dlg.present()
        return False


class MailApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", lambda a: MailWindow(a).present())

if __name__ == "__main__":
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    sys.exit(MailApp().run(sys.argv))
