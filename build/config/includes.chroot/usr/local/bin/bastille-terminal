#!/usr/bin/env python3
"""bastille-terminal — VTE-based terminal emulator with tabs."""
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
try:
    gi.require_version('Vte', '2.91')
    from gi.repository import Vte
    HAS_VTE = True
except (ValueError, ImportError):
    HAS_VTE = False
import sys, os
from gi.repository import Gtk, Adw, Gio, GLib, Gdk

APP_ID = "org.bastilleos.Terminal"
SHELL = os.environ.get("SHELL", "/bin/bash")

TERM_CSS = """
window { background-color: #0b0b0b; }
"""


class TerminalTab(Gtk.Box):
    def __init__(self, on_title_changed=None, on_exit=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self._on_title_changed = on_title_changed
        self._on_exit = on_exit

        if HAS_VTE:
            self._vte = Vte.Terminal()
            self._vte.set_scrollback_lines(10000)
            self._vte.set_mouse_autohide(True)
            self._vte.set_audible_bell(False)

            # Dark theme palette matching Bastille
            fg = Gdk.RGBA(); fg.parse("#f0efec")
            bg = Gdk.RGBA(); bg.parse("#0b0b0b")
            palette = [Gdk.RGBA() for _ in range(16)]
            colors = [
                "#1a1a19", "#d03b3b", "#009300", "#fab219",
                "#2a78d6", "#7c3aed", "#2a78d6", "#c3c2b7",
                "#898781", "#f87171", "#3fb950", "#fbbf24",
                "#7ab8f5", "#a78bfa", "#67e8f9", "#f0efec",
            ]
            for i, c in enumerate(colors):
                palette[i].parse(c)

            self._vte.set_colors(fg, bg, palette)
            self._vte.set_font_from_string("monospace 12")
            self._vte.connect("child-exited", lambda t, s: self._on_exit and self._on_exit(self))
            self._vte.connect("window-title-changed", lambda t: self._on_title_changed and
                              self._on_title_changed(self, t.get_window_title()))

            sw = Gtk.ScrolledWindow()
            sw.set_child(self._vte)
            sw.set_vexpand(True)
            sw.set_hexpand(True)
            self.append(sw)

            self._vte.spawn_async(
                Vte.PtyFlags.DEFAULT, None,
                [SHELL], None,
                GLib.SpawnFlags.DO_NOT_REAP_CHILD,
                None, None, -1, None, self._on_spawn, None)
        else:
            status = Adw.StatusPage()
            status.set_icon_name("utilities-terminal-symbolic")
            status.set_title("VTE not installed")
            status.set_description(
                "Install python3-vte to enable the terminal:\n\napt install python3-vte2.91")
            self.append(status)

    def _on_spawn(self, terminal, pid, err):
        if err:
            print(f"[bastille-terminal] spawn error: {err}")

    def feed(self, text: str):
        if HAS_VTE:
            self._vte.feed_child(text.encode())

    def copy(self):
        if HAS_VTE:
            self._vte.copy_clipboard_format(Vte.Format.TEXT)

    def paste(self):
        if HAS_VTE:
            self._vte.paste_clipboard()


class TerminalWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("Terminal")
        self.set_default_size(860, 540)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        hdr = Adw.HeaderBar()
        hdr.set_title_widget(Adw.WindowTitle.new("Terminal", ""))

        new_tab_btn = Gtk.Button()
        new_tab_btn.set_icon_name("list-add-symbolic")
        new_tab_btn.set_tooltip_text("New tab")
        new_tab_btn.connect("clicked", self._new_tab)
        hdr.pack_end(new_tab_btn)

        # Menu button
        menu_btn = Gtk.MenuButton()
        menu_btn.set_icon_name("open-menu-symbolic")
        menu = Gio.Menu()
        menu.append("Copy", "win.copy")
        menu.append("Paste", "win.paste")
        menu.append("Clear scrollback", "win.clear")
        menu_btn.set_menu_model(menu)
        hdr.pack_end(menu_btn)

        box.append(hdr)

        # Tab bar + notebook
        self._notebook = Adw.TabView()
        self._notebook.connect("close-page", self._on_close_page)
        tab_bar = Adw.TabBar()
        tab_bar.set_view(self._notebook)
        tab_bar.set_autohide(False)
        box.append(tab_bar)
        box.append(self._notebook)

        self.set_content(box)

        # Actions
        for name, cb in [("copy", self._copy), ("paste", self._paste), ("clear", self._clear)]:
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", cb)
            self.add_action(action)

        # Keyboard shortcuts
        ctrl = Gtk.ShortcutController()
        ctrl.set_scope(Gtk.ShortcutScope.LOCAL)
        new_tab_sc = Gtk.Shortcut.new(
            Gtk.KeyvalTrigger.new(ord("t"), Gdk.ModifierType.CONTROL_MASK | Gdk.ModifierType.SHIFT_MASK),
            Gtk.CallbackAction.new(lambda *_: self._new_tab()))
        ctrl.add_shortcut(new_tab_sc)
        self.add_controller(ctrl)

        self._new_tab()

    def _new_tab(self, *_):
        tab_content = TerminalTab(
            on_title_changed=self._on_title_changed,
            on_exit=self._on_tab_exit)
        page = self._notebook.append(tab_content)
        page.set_title("Terminal")
        self._notebook.set_selected_page(page)
        return page

    def _on_close_page(self, view, page):
        view.close_page_finish(page, True)
        if view.get_n_pages() == 0:
            self.close()
        return True

    def _on_title_changed(self, tab, title):
        for i in range(self._notebook.get_n_pages()):
            page = self._notebook.get_nth_page(i)
            if page.get_child() is tab:
                page.set_title(title or "Terminal")
                break

    def _on_tab_exit(self, tab):
        for i in range(self._notebook.get_n_pages()):
            page = self._notebook.get_nth_page(i)
            if page.get_child() is tab:
                self._notebook.close_page(page)
                break

    def _active_tab(self):
        page = self._notebook.get_selected_page()
        if page:
            child = page.get_child()
            if isinstance(child, TerminalTab):
                return child
        return None

    def _copy(self, *_):
        t = self._active_tab()
        if t:
            t.copy()

    def _paste(self, *_):
        t = self._active_tab()
        if t:
            t.paste()

    def _clear(self, *_):
        if HAS_VTE:
            t = self._active_tab()
            if t and hasattr(t, "_vte"):
                t._vte.reset(True, True)


class TerminalApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", lambda a: TerminalWindow(a).present())

if __name__ == "__main__":
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    sys.exit(TerminalApp().run(sys.argv))
