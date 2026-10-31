#!/usr/bin/env python3
"""bastille-notes — Encrypted notes app with PIN lock, markdown preview, and tags."""
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
import os, sys, json, subprocess, hashlib, re
from pathlib import Path
from gi.repository import Gtk, Adw, Gio, GLib

APP_ID = "org.bastilleos.Notes"
NOTES_DIR = Path.home() / ".local" / "share" / "bastille-notes"
META_FILE = NOTES_DIR / "meta.json"


def encrypt_note(content: str, passphrase: str, path: Path):
    NOTES_DIR.mkdir(parents=True, exist_ok=True)
    try:
        r = subprocess.run(
            ["age", "-p", "-o", str(path)],
            input=passphrase + "\n" + passphrase + "\n" + content,
            text=True, capture_output=True)
        return r.returncode == 0
    except FileNotFoundError:
        r = subprocess.run(
            ["gpg", "--batch", "--yes", "--symmetric", "--passphrase", passphrase,
             "--output", str(path)],
            input=content, text=True, capture_output=True)
        return r.returncode == 0


def decrypt_note(passphrase: str, path: Path) -> str | None:
    try:
        r = subprocess.run(["age", "-d", str(path)], input=passphrase, text=True, capture_output=True)
        if r.returncode == 0:
            return r.stdout
    except FileNotFoundError:
        pass
    try:
        r = subprocess.run(["gpg", "--batch", "--yes", "--decrypt", "--passphrase", passphrase, str(path)],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout
    except Exception:
        pass
    return None


def pin_hash(pin: str) -> str:
    return hashlib.sha256(pin.encode()).hexdigest()


def load_meta():
    try:
        with open(META_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_meta(meta):
    NOTES_DIR.mkdir(parents=True, exist_ok=True)
    with open(META_FILE, "w") as f:
        json.dump(meta, f, indent=2)


def render_markdown(text: str) -> str:
    """Very lightweight markdown → Pango markup conversion."""
    lines = text.split("\n")
    out = []
    in_code = False
    for line in lines:
        if line.startswith("```"):
            in_code = not in_code
            if in_code:
                out.append('<span font_family="monospace" background="#1a1a19">')
            else:
                out.append("</span>")
            continue
        if in_code:
            out.append(GLib.markup_escape_text(line))
            continue
        if line.startswith("### "):
            out.append(f'<b><span size="medium">{GLib.markup_escape_text(line[4:])}</span></b>')
        elif line.startswith("## "):
            out.append(f'<b><span size="large">{GLib.markup_escape_text(line[3:])}</span></b>')
        elif line.startswith("# "):
            out.append(f'<b><span size="x-large">{GLib.markup_escape_text(line[2:])}</span></b>')
        elif line.startswith("> "):
            out.append(f'<span foreground="#898781">│ {GLib.markup_escape_text(line[2:])}</span>')
        elif line.startswith("- ") or line.startswith("* "):
            out.append(f'  • {GLib.markup_escape_text(line[2:])}')
        else:
            escaped = GLib.markup_escape_text(line)
            # inline bold/italic/code
            escaped = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', escaped)
            escaped = re.sub(r'\*(.+?)\*', r'<i>\1</i>', escaped)
            escaped = re.sub(r'`(.+?)`', r'<span font_family="monospace" background="#1a1a19">\1</span>', escaped)
            out.append(escaped)
    return "\n".join(out)


class NoteRow(Gtk.ListBoxRow):
    def __init__(self, path: Path, meta: dict):
        super().__init__()
        self.path = path
        self.meta = meta
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.set_margin_start(12); box.set_margin_end(8)
        box.set_margin_top(8); box.set_margin_bottom(8)

        title_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        title_lbl = Gtk.Label(label=path.stem)
        title_lbl.set_halign(Gtk.Align.START)
        title_lbl.set_hexpand(True)
        title_lbl.set_ellipsize(3)
        title_row.append(title_lbl)

        if meta.get("pin_protected"):
            lock = Gtk.Image.new_from_icon_name("changes-prevent-symbolic")
            lock.set_pixel_size(12)
            title_row.append(lock)

        box.append(title_row)

        tags = meta.get("tags", [])
        is_md = path.suffix.lower() == ".md" or meta.get("is_md")
        tag_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        if is_md:
            t = Gtk.Label(label="MD")
            t.add_css_class("caption"); t.add_css_class("accent")
            tag_row.append(t)
        for tag in tags[:3]:
            t = Gtk.Label(label=tag)
            t.add_css_class("caption"); t.add_css_class("dim-label")
            tag_row.append(t)
        box.append(tag_row)
        self.set_child(box)


class NotesWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("Notes")
        self.set_default_size(860, 580)
        self._passphrase = None
        self._current_path = None
        self._unsaved = False
        self._preview_mode = False
        self._meta = load_meta()
        self._unlocked_pins = set()

        split = Adw.NavigationSplitView()
        split.set_min_sidebar_width(200)
        split.set_max_sidebar_width(260)

        # ── Sidebar ──
        sidebar_nav = Adw.NavigationPage()
        sidebar_nav.set_title("Notes")
        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        sidebar_header = Adw.HeaderBar()
        new_btn = Gtk.Button()
        new_btn.set_icon_name("list-add-symbolic")
        new_btn.set_tooltip_text("New note")
        new_btn.connect("clicked", self._new_note)
        sidebar_header.pack_end(new_btn)
        sidebar_box.append(sidebar_header)

        self._list = Gtk.ListBox()
        self._list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._list.add_css_class("navigation-sidebar")
        self._list.connect("row-selected", self._on_select)

        gesture = Gtk.GestureClick()
        gesture.set_button(3)
        gesture.connect("pressed", self._on_right_click)
        self._list.add_controller(gesture)

        scroll = Gtk.ScrolledWindow()
        scroll.set_child(self._list)
        scroll.set_vexpand(True)
        sidebar_box.append(scroll)
        sidebar_nav.set_child(sidebar_box)

        # ── Content ──
        content_nav = Adw.NavigationPage()
        content_nav.set_title("Note")
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content_header = Adw.HeaderBar()

        save_btn = Gtk.Button.new_with_label("Save")
        save_btn.add_css_class("suggested-action")
        save_btn.connect("clicked", self._save_note)

        del_btn = Gtk.Button()
        del_btn.set_icon_name("user-trash-symbolic")
        del_btn.add_css_class("destructive-action")
        del_btn.connect("clicked", self._delete_note)

        self._preview_btn = Gtk.ToggleButton()
        self._preview_btn.set_icon_name("view-reveal-symbolic")
        self._preview_btn.set_tooltip_text("Toggle markdown preview")
        self._preview_btn.connect("toggled", self._toggle_preview)

        tag_btn = Gtk.Button()
        tag_btn.set_icon_name("tag-symbolic")
        tag_btn.set_tooltip_text("Edit tags")
        tag_btn.connect("clicked", self._edit_tags)

        pin_btn = Gtk.Button()
        pin_btn.set_icon_name("changes-prevent-symbolic")
        pin_btn.set_tooltip_text("Set/remove PIN protection")
        pin_btn.connect("clicked", self._toggle_pin)

        content_header.pack_end(save_btn)
        content_header.pack_end(del_btn)
        content_header.pack_end(self._preview_btn)
        content_header.pack_end(tag_btn)
        content_header.pack_end(pin_btn)
        content_box.append(content_header)

        # Title entry
        self._title_entry = Adw.EntryRow()
        self._title_entry.set_title("Title")
        title_group = Adw.PreferencesGroup()
        title_group.add(self._title_entry)
        title_group.set_margin_start(16); title_group.set_margin_end(16)
        title_group.set_margin_top(8)
        content_box.append(title_group)

        # Editor stack: edit mode / preview mode
        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)

        # Edit view
        tv = Gtk.TextView()
        tv.set_monospace(False)
        tv.set_wrap_mode(Gtk.WrapMode.WORD)
        tv.set_left_margin(16); tv.set_right_margin(16)
        tv.set_top_margin(16); tv.set_bottom_margin(16)
        tv.get_buffer().connect("changed", lambda _: setattr(self, "_unsaved", True))
        self._tv = tv
        sw = Gtk.ScrolledWindow()
        sw.set_child(tv)
        sw.set_vexpand(True)

        # Preview view
        self._preview_lbl = Gtk.Label()
        self._preview_lbl.set_use_markup(True)
        self._preview_lbl.set_wrap(True)
        self._preview_lbl.set_xalign(0)
        self._preview_lbl.set_yalign(0)
        self._preview_lbl.set_selectable(True)
        self._preview_lbl.set_margin_start(16); self._preview_lbl.set_margin_end(16)
        self._preview_lbl.set_margin_top(16); self._preview_lbl.set_margin_bottom(16)
        preview_sw = Gtk.ScrolledWindow()
        preview_sw.set_child(self._preview_lbl)
        preview_sw.set_vexpand(True)

        self._stack.add_named(sw, "edit")
        self._stack.add_named(preview_sw, "preview")
        self._stack.set_visible_child_name("edit")
        content_box.append(self._stack)

        content_nav.set_child(content_box)
        split.set_sidebar(sidebar_nav)
        split.set_content(content_nav)
        self.set_content(split)

        self._prompt_passphrase()

    def _prompt_passphrase(self):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Notes passphrase")
        dlg.set_body("Enter your notes passphrase to unlock encrypted notes.")
        entry = Gtk.PasswordEntry()
        entry.set_show_peek_icon(True)
        entry.set_placeholder_text("Passphrase")
        entry.set_margin_start(16); entry.set_margin_end(16)
        dlg.set_extra_child(entry)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("ok", "Unlock")
        dlg.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        def resp(d, r):
            if r == "ok":
                self._passphrase = entry.get_text()
                self._load_notes()
            else:
                self.close()
        dlg.connect("response", resp)
        dlg.present()

    def _load_notes(self):
        NOTES_DIR.mkdir(parents=True, exist_ok=True)
        while self._list.get_first_child():
            self._list.remove(self._list.get_first_child())
        paths = sorted(NOTES_DIR.glob("*.age")) + sorted(NOTES_DIR.glob("*.gpg")) + sorted(NOTES_DIR.glob("*.md"))
        for path in paths:
            if path == META_FILE:
                continue
            meta = self._meta.get(path.name, {})
            row = NoteRow(path, meta)
            self._list.append(row)

    def _on_select(self, lb, row):
        if row is None or not isinstance(row, NoteRow):
            return
        meta = self._meta.get(row.path.name, {})
        if meta.get("pin_protected") and row.path.name not in self._unlocked_pins:
            self._prompt_note_pin(row)
            return
        self._open_note(row)

    def _prompt_note_pin(self, row: NoteRow):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("PIN required")
        dlg.set_body(f'Enter PIN to view "{row.path.stem}".')
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
                meta = self._meta.get(row.path.name, {})
                stored_pin = meta.get("pin_hash")
                if stored_pin is None or pin_hash(entry.get_text()) == stored_pin:
                    self._unlocked_pins.add(row.path.name)
                    self._open_note(row)
                else:
                    err = Adw.MessageDialog.new(self)
                    err.set_heading("Wrong PIN")
                    err.add_response("ok", "OK")
                    err.present()
        dlg.connect("response", resp)
        dlg.present()

    def _open_note(self, row: NoteRow):
        self._current_path = row.path
        self._title_entry.set_text(row.path.stem)
        if row.path.suffix.lower() == ".md":
            try:
                content = row.path.read_text()
            except Exception:
                content = ""
        else:
            content = decrypt_note(self._passphrase, row.path) or ""
        self._tv.get_buffer().set_text(content)
        self._unsaved = False
        if self._preview_mode:
            self._update_preview(content)

    def _toggle_preview(self, btn):
        self._preview_mode = btn.get_active()
        if self._preview_mode:
            buf = self._tv.get_buffer()
            text = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
            self._update_preview(text)
            self._stack.set_visible_child_name("preview")
        else:
            self._stack.set_visible_child_name("edit")

    def _update_preview(self, text: str):
        try:
            markup = render_markdown(text)
            self._preview_lbl.set_markup(markup)
        except Exception as e:
            self._preview_lbl.set_text(text)

    def _new_note(self, *_):
        name = f"Note-{len(list(NOTES_DIR.glob('*.age'))) + 1}"
        path = NOTES_DIR / f"{name}.age"
        self._current_path = path
        self._title_entry.set_text(name)
        self._tv.get_buffer().set_text("")
        row = NoteRow(path, {})
        self._list.append(row)
        self._list.select_row(row)

    def _save_note(self, *_):
        if not self._current_path:
            return
        buf = self._tv.get_buffer()
        content = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
        new_title = self._title_entry.get_text().strip()
        if new_title and new_title != self._current_path.stem:
            new_path = self._current_path.with_name(new_title + self._current_path.suffix)
            self._meta[new_path.name] = self._meta.pop(self._current_path.name, {})
            self._current_path = new_path

        if self._current_path.suffix.lower() == ".md":
            self._current_path.write_text(content)
        else:
            encrypt_note(content, self._passphrase, self._current_path)
        save_meta(self._meta)
        self._unsaved = False
        self._load_notes()

    def _delete_note(self, *_):
        if self._current_path and self._current_path.exists():
            self._current_path.unlink()
            self._meta.pop(self._current_path.name, None)
            save_meta(self._meta)
            sel = self._list.get_selected_row()
            if sel:
                self._list.remove(sel)
            self._current_path = None
            self._title_entry.set_text("")
            self._tv.get_buffer().set_text("")

    def _toggle_pin(self, *_):
        if not self._current_path:
            return
        meta = self._meta.setdefault(self._current_path.name, {})
        if meta.get("pin_protected"):
            meta["pin_protected"] = False
            meta.pop("pin_hash", None)
            save_meta(self._meta)
        else:
            dlg = Adw.MessageDialog.new(self)
            dlg.set_heading("Set PIN for this note")
            entry = Gtk.PasswordEntry()
            entry.set_show_peek_icon(True)
            entry.set_placeholder_text("PIN")
            entry.set_margin_start(16); entry.set_margin_end(16)
            dlg.set_extra_child(entry)
            dlg.add_response("cancel", "Cancel")
            dlg.add_response("set", "Set PIN")
            dlg.set_response_appearance("set", Adw.ResponseAppearance.SUGGESTED)
            def resp(d, r):
                if r == "set" and entry.get_text():
                    meta["pin_protected"] = True
                    meta["pin_hash"] = pin_hash(entry.get_text())
                    save_meta(self._meta)
                    self._load_notes()
            dlg.connect("response", resp)
            dlg.present()

    def _edit_tags(self, *_):
        if not self._current_path:
            return
        meta = self._meta.setdefault(self._current_path.name, {})
        current_tags = ", ".join(meta.get("tags", []))
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Edit tags")
        dlg.set_body("Comma-separated tags (e.g. security, opsec, keys)")
        entry = Gtk.Entry()
        entry.set_text(current_tags)
        entry.set_margin_start(16); entry.set_margin_end(16)
        dlg.set_extra_child(entry)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("save", "Save")
        dlg.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        def resp(d, r):
            if r == "save":
                tags = [t.strip() for t in entry.get_text().split(",") if t.strip()]
                meta["tags"] = tags
                save_meta(self._meta)
                self._load_notes()
        dlg.connect("response", resp)
        dlg.present()

    def _on_right_click(self, gesture, n, x, y):
        row = self._list.get_row_at_y(int(y))
        if isinstance(row, NoteRow):
            self._list.select_row(row)


class NotesApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", lambda a: NotesWindow(a).present())

if __name__ == "__main__":
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    sys.exit(NotesApp().run(sys.argv))
