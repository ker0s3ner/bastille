#!/usr/bin/env python3
"""bastille-files — File manager with age/GPG encryption and archive support."""
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
import sys, os, subprocess, shutil, stat
from pathlib import Path
from gi.repository import Gtk, Adw, Gio, GLib

APP_ID = "org.bastilleos.Files"
HOME = Path.home()

MIME_ICONS = {
    "dir":  "folder-symbolic",
    ".py":  "text-x-script-symbolic",
    ".sh":  "text-x-script-symbolic",
    ".md":  "text-x-generic-symbolic",
    ".txt": "text-x-generic-symbolic",
    ".pdf": "x-office-document-symbolic",
    ".png": "image-x-generic-symbolic",
    ".jpg": "image-x-generic-symbolic",
    ".jpeg":"image-x-generic-symbolic",
    ".mp3": "audio-x-generic-symbolic",
    ".flac":"audio-x-generic-symbolic",
    ".ogg": "audio-x-generic-symbolic",
    ".mp4": "video-x-generic-symbolic",
    ".mkv": "video-x-generic-symbolic",
    ".zip": "package-x-generic-symbolic",
    ".tar": "package-x-generic-symbolic",
    ".gz":  "package-x-generic-symbolic",
    ".age": "channel-secure-symbolic",
    ".gpg": "channel-secure-symbolic",
    ".asc": "channel-secure-symbolic",
}

def icon_for(path: Path) -> str:
    if path.is_dir():
        return "folder-symbolic"
    return MIME_ICONS.get(path.suffix.lower(), "text-x-generic-symbolic")

def fmt_size(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class FileRow(Adw.ActionRow):
    def __init__(self, path: Path):
        super().__init__()
        self.path = path
        self.set_title(path.name)
        self.set_activatable(True)

        icon = Gtk.Image.new_from_icon_name(icon_for(path))
        self.add_prefix(icon)

        if path.is_file():
            try:
                size = path.stat().st_size
                self.set_subtitle(fmt_size(size))
            except Exception:
                pass
        elif path.is_dir():
            self.set_subtitle("Folder")

        if path.suffix.lower() in (".age", ".gpg", ".asc"):
            lock = Gtk.Image.new_from_icon_name("changes-prevent-symbolic")
            self.add_suffix(lock)


class FilesWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("Files")
        self.set_default_size(820, 540)
        self._cwd = HOME
        self._history = [HOME]
        self._hist_pos = 0

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # Header
        hdr = Adw.HeaderBar()
        self._path_entry = Adw.EntryRow()
        self._path_entry.set_title("Path")
        self._path_entry.set_text(str(HOME))
        self._path_entry.connect("apply", self._on_path_enter)
        path_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        path_bar.set_hexpand(True)

        self._back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        self._back_btn.connect("clicked", self._go_back)
        self._back_btn.set_sensitive(False)
        self._fwd_btn = Gtk.Button.new_from_icon_name("go-next-symbolic")
        self._fwd_btn.connect("clicked", self._go_forward)
        self._fwd_btn.set_sensitive(False)
        up_btn = Gtk.Button.new_from_icon_name("go-up-symbolic")
        up_btn.connect("clicked", self._go_up)
        home_btn = Gtk.Button.new_from_icon_name("user-home-symbolic")
        home_btn.connect("clicked", lambda _: self._navigate(HOME))

        hdr.pack_start(self._back_btn)
        hdr.pack_start(self._fwd_btn)
        hdr.pack_start(up_btn)
        hdr.pack_start(home_btn)

        # Action menu
        menu_btn = Gtk.MenuButton()
        menu_btn.set_icon_name("open-menu-symbolic")
        menu = Gio.Menu()
        menu.append("New folder", "win.new_folder")
        menu.append("Encrypt selected (age)", "win.encrypt_age")
        menu.append("Decrypt selected", "win.decrypt")
        menu.append("Encrypt selected (GPG)", "win.encrypt_gpg")
        menu.append("Delete selected", "win.delete")
        menu_btn.set_menu_model(menu)
        hdr.pack_end(menu_btn)
        hdr.set_title_widget(Adw.WindowTitle.new("Files", ""))
        main_box.append(hdr)

        # Breadcrumb / path
        self._breadcrumb = Gtk.Label()
        self._breadcrumb.set_halign(Gtk.Align.START)
        self._breadcrumb.set_margin_start(16)
        self._breadcrumb.set_margin_top(6)
        self._breadcrumb.set_margin_bottom(4)
        self._breadcrumb.add_css_class("caption")
        self._breadcrumb.add_css_class("dim-label")
        main_box.append(self._breadcrumb)

        # File list
        self._file_list = Gtk.ListBox()
        self._file_list.set_selection_mode(Gtk.SelectionMode.MULTIPLE)
        self._file_list.add_css_class("boxed-list")
        self._file_list.set_margin_start(12); self._file_list.set_margin_end(12)
        self._file_list.set_margin_bottom(8)
        self._file_list.connect("row-activated", self._on_row_activated)

        # Right-click menu
        gesture = Gtk.GestureClick()
        gesture.set_button(3)
        gesture.connect("pressed", self._on_right_click)
        self._file_list.add_controller(gesture)

        scroll = Gtk.ScrolledWindow()
        scroll.set_child(self._file_list)
        scroll.set_vexpand(True)
        main_box.append(scroll)

        # Status bar
        self._status = Gtk.Label()
        self._status.add_css_class("caption")
        self._status.add_css_class("dim-label")
        self._status.set_halign(Gtk.Align.START)
        self._status.set_margin_start(16)
        self._status.set_margin_bottom(8)
        main_box.append(self._status)

        self.set_content(main_box)

        # Actions
        for name, cb in [
            ("new_folder", self._new_folder),
            ("encrypt_age", self._encrypt_age),
            ("decrypt", self._decrypt),
            ("encrypt_gpg", self._encrypt_gpg),
            ("delete", self._delete_selected),
        ]:
            a = Gio.SimpleAction.new(name, None)
            a.connect("activate", cb)
            self.add_action(a)

        self._navigate(HOME)

    def _navigate(self, path: Path):
        if not path.is_dir():
            return
        self._cwd = path
        # Update history
        if self._hist_pos < len(self._history) - 1:
            self._history = self._history[:self._hist_pos + 1]
        if not self._history or self._history[-1] != path:
            self._history.append(path)
            self._hist_pos = len(self._history) - 1
        self._refresh()

    def _refresh(self):
        while self._file_list.get_first_child():
            self._file_list.remove(self._file_list.get_first_child())

        self._breadcrumb.set_label(str(self._cwd))
        self._back_btn.set_sensitive(self._hist_pos > 0)
        self._fwd_btn.set_sensitive(self._hist_pos < len(self._history) - 1)

        try:
            entries = sorted(self._cwd.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except PermissionError:
            row = Adw.ActionRow()
            row.set_title("Permission denied")
            self._file_list.append(row)
            return

        for entry in entries:
            if entry.name.startswith("."):
                continue
            self._file_list.append(FileRow(entry))

        self._status.set_label(f"{len(entries)} items")

    def _on_row_activated(self, lb, row):
        if isinstance(row, FileRow):
            if row.path.is_dir():
                self._navigate(row.path)
            else:
                self._open_file(row.path)

    def _open_file(self, path: Path):
        if path.suffix.lower() in (".age", ".gpg"):
            self._decrypt_file(path)
            return
        try:
            subprocess.Popen(["xdg-open", str(path)])
        except Exception:
            pass

    def _go_back(self, *_):
        if self._hist_pos > 0:
            self._hist_pos -= 1
            self._cwd = self._history[self._hist_pos]
            self._refresh()

    def _go_forward(self, *_):
        if self._hist_pos < len(self._history) - 1:
            self._hist_pos += 1
            self._cwd = self._history[self._hist_pos]
            self._refresh()

    def _go_up(self, *_):
        parent = self._cwd.parent
        if parent != self._cwd:
            self._navigate(parent)

    def _on_path_enter(self, entry):
        p = Path(entry.get_text())
        if p.is_dir():
            self._navigate(p)

    def _selected_paths(self):
        rows = []
        row = self._file_list.get_first_child()
        while row:
            if isinstance(row, FileRow) and row.is_selected():
                rows.append(row.path)
            row = row.get_next_sibling()
        return rows

    def _on_right_click(self, gesture, n, x, y):
        row = self._file_list.get_row_at_y(int(y))
        if row and isinstance(row, FileRow):
            self._file_list.select_row(row)

    def _new_folder(self, *_):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("New folder")
        entry = Gtk.Entry(); entry.set_placeholder_text("Folder name")
        entry.set_margin_start(16); entry.set_margin_end(16)
        dlg.set_extra_child(entry)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("ok", "Create")
        dlg.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        def resp(d, r):
            if r == "ok" and entry.get_text():
                (self._cwd / entry.get_text()).mkdir(exist_ok=True)
                self._refresh()
        dlg.connect("response", resp)
        dlg.present()

    def _encrypt_age(self, *_):
        paths = self._selected_paths()
        if not paths:
            return
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Encrypt with age")
        entry = Gtk.PasswordEntry()
        entry.set_show_peek_icon(True)
        entry.set_placeholder_text("Passphrase")
        entry.set_margin_start(16); entry.set_margin_end(16)
        dlg.set_extra_child(entry)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("ok", "Encrypt")
        dlg.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        def resp(d, r):
            if r == "ok" and entry.get_text():
                for p in paths:
                    out = p.with_suffix(p.suffix + ".age")
                    try:
                        subprocess.run(
                            ["age", "-p", "-o", str(out)],
                            input=entry.get_text() + "\n" + entry.get_text() + "\n",
                            stdin=subprocess.PIPE, text=True, timeout=30)
                    except Exception as e:
                        print(f"[bastille-files] age encrypt error: {e}")
                self._refresh()
        dlg.connect("response", resp)
        dlg.present()

    def _decrypt_file(self, path: Path):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Decrypt file")
        dlg.set_body(f"Enter passphrase to decrypt {path.name}")
        entry = Gtk.PasswordEntry()
        entry.set_show_peek_icon(True)
        entry.set_placeholder_text("Passphrase")
        entry.set_margin_start(16); entry.set_margin_end(16)
        dlg.set_extra_child(entry)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("ok", "Decrypt")
        dlg.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        def resp(d, r):
            if r == "ok":
                out = path.with_suffix("")
                try:
                    if path.suffix == ".age":
                        subprocess.run(
                            ["age", "-d", "-o", str(out), str(path)],
                            input=entry.get_text(), text=True, timeout=30)
                    else:
                        subprocess.run(
                            ["gpg", "--batch", "--yes", "--passphrase", entry.get_text(),
                             "-o", str(out), "--decrypt", str(path)],
                            text=True, timeout=30)
                    self._refresh()
                except Exception as e:
                    print(f"[bastille-files] decrypt error: {e}")
        dlg.connect("response", resp)
        dlg.present()

    def _decrypt(self, *_):
        paths = self._selected_paths()
        for p in paths:
            if p.suffix.lower() in (".age", ".gpg"):
                self._decrypt_file(p)

    def _encrypt_gpg(self, *_):
        paths = self._selected_paths()
        if not paths:
            return
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Encrypt with GPG")
        entry = Gtk.Entry(); entry.set_placeholder_text("Recipient key ID or email")
        entry.set_margin_start(16); entry.set_margin_end(16)
        dlg.set_extra_child(entry)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("ok", "Encrypt")
        dlg.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        def resp(d, r):
            if r == "ok" and entry.get_text():
                for p in paths:
                    try:
                        subprocess.run(
                            ["gpg", "--batch", "--yes", "--encrypt",
                             "-r", entry.get_text(), str(p)],
                            text=True, timeout=30)
                    except Exception as e:
                        print(f"[bastille-files] gpg encrypt error: {e}")
                self._refresh()
        dlg.connect("response", resp)
        dlg.present()

    def _delete_selected(self, *_):
        paths = self._selected_paths()
        if not paths:
            return
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Delete files?")
        dlg.set_body(f"Permanently delete {len(paths)} item(s)?")
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("delete", "Delete")
        dlg.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        def resp(d, r):
            if r == "delete":
                for p in paths:
                    try:
                        if p.is_dir():
                            shutil.rmtree(p)
                        else:
                            p.unlink()
                    except Exception as e:
                        print(f"[bastille-files] delete error: {e}")
                self._refresh()
        dlg.connect("response", resp)
        dlg.present()


class FilesApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", lambda a: FilesWindow(a).present())

if __name__ == "__main__":
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    sys.exit(FilesApp().run(sys.argv))
