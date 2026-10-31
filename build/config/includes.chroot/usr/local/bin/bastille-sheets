#!/usr/bin/env python3
"""bastille-sheets — Spreadsheet launcher (LibreOffice Calc) with recent files."""
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
import sys, os, subprocess, json
from pathlib import Path
from gi.repository import Gtk, Adw, Gio, GLib

APP_ID = "org.bastilleos.Sheets"
STATE_FILE = Path.home() / ".local/share/bastille-sheets/state.json"
RECENTS_MAX = 20
SHEET_EXTS = {".ods", ".xls", ".xlsx", ".csv", ".fods"}

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"recents": []}

def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def add_recent(path: str):
    state = load_state()
    recents = state.get("recents", [])
    if path in recents:
        recents.remove(path)
    recents.insert(0, path)
    state["recents"] = recents[:RECENTS_MAX]
    save_state(state)

def open_calc(path: str | None = None):
    cmd = ["libreoffice", "--calc"]
    if path:
        cmd.append(path)
        add_recent(path)
    try:
        subprocess.Popen(cmd)
        return True, ""
    except FileNotFoundError:
        try:
            subprocess.Popen(["soffice", "--calc"] + ([path] if path else []))
            return True, ""
        except FileNotFoundError:
            return False, "LibreOffice Calc is not installed"


class RecentRow(Adw.ActionRow):
    def __init__(self, path: str):
        super().__init__()
        self.path = path
        p = Path(path)
        self.set_title(p.name)
        self.set_subtitle(str(p.parent))
        self.set_activatable(True)
        icon = Gtk.Image.new_from_icon_name("x-office-spreadsheet-symbolic")
        self.add_prefix(icon)
        if not p.exists():
            self.add_css_class("dim-label")


class SheetsWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("Sheets")
        self.set_default_size(640, 500)
        self._state = load_state()

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        hdr = Adw.HeaderBar()
        hdr.set_title_widget(Adw.WindowTitle.new("Sheets", ""))
        new_btn = Gtk.Button.new_with_label("New Spreadsheet")
        new_btn.add_css_class("suggested-action")
        new_btn.connect("clicked", self._new_sheet)
        open_btn = Gtk.Button()
        open_btn.set_icon_name("document-open-symbolic")
        open_btn.set_tooltip_text("Open file…")
        open_btn.connect("clicked", self._open_file)
        hdr.pack_end(new_btn)
        hdr.pack_end(open_btn)
        box.append(hdr)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        self._recents_grp = Adw.PreferencesGroup()
        self._recents_grp.set_title("Recent Spreadsheets")
        self._recents_grp.set_margin_start(12); self._recents_grp.set_margin_end(12)
        self._recents_grp.set_margin_top(12)

        self._empty_page = Adw.StatusPage()
        self._empty_page.set_icon_name("x-office-spreadsheet-symbolic")
        self._empty_page.set_title("No recent spreadsheets")
        self._empty_page.set_description("Create a new spreadsheet or open an existing one.")
        self._empty_page.set_vexpand(True)

        content.append(self._recents_grp)
        content.append(self._empty_page)
        scroll.set_child(content)
        box.append(scroll)
        self.set_content(box)
        self._refresh_recents()

    def _refresh_recents(self):
        recents = self._state.get("recents", [])
        self._empty_page.set_visible(not recents)
        self._recents_grp.set_visible(bool(recents))
        for p in recents:
            row = RecentRow(p)
            row.connect("activated", lambda r: self._open_path(r.path))
            self._recents_grp.add(row)

    def _new_sheet(self, *_):
        ok, err = open_calc()
        if not ok:
            self._show_err(err)

    def _open_file(self, *_):
        dialog = Gtk.FileDialog()
        dialog.open(self, None, self._on_file_chosen)

    def _on_file_chosen(self, dialog, result):
        try:
            file = dialog.open_finish(result)
            if file:
                self._open_path(file.get_path())
        except Exception:
            pass

    def _open_path(self, path: str):
        ok, err = open_calc(path)
        if not ok:
            self._show_err(err)
        else:
            self._state = load_state()
            self._refresh_recents()

    def _show_err(self, msg):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Cannot open LibreOffice Calc")
        dlg.set_body(msg + "\n\nInstall with: apt install libreoffice-calc")
        dlg.add_response("ok", "OK")
        dlg.present()


class SheetsApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", lambda a: SheetsWindow(a).present())

if __name__ == "__main__":
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    sys.exit(SheetsApp().run(sys.argv))
