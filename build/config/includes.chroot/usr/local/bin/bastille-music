#!/usr/bin/env python3
"""bastille-music — GStreamer music player with library management."""
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
gi.require_version('Gst', '1.0')
import sys, os, json
from pathlib import Path
from gi.repository import Gtk, Adw, Gio, GLib, Gst

APP_ID = "org.bastilleos.Music"
MUSIC_DIRS = [Path.home() / "Music", Path("/media")]
SUPPORTED = {".mp3", ".flac", ".ogg", ".opus", ".m4a", ".wav", ".aac"}
STATE_FILE = Path.home() / ".local/share/bastille-music/state.json"

Gst.init(None)


def scan_library(dirs):
    tracks = []
    for d in dirs:
        if not d.exists():
            continue
        for p in d.rglob("*"):
            if p.suffix.lower() in SUPPORTED:
                tracks.append(str(p))
    return sorted(tracks)


def track_name(path: str) -> str:
    return Path(path).stem

def track_artist(path: str) -> str:
    parts = Path(path).parts
    if len(parts) >= 2:
        return parts[-2]
    return "Unknown Artist"

def fmt_time(secs: int) -> str:
    m, s = divmod(int(secs), 60)
    return f"{m}:{s:02d}"


class TrackRow(Gtk.ListBoxRow):
    def __init__(self, path: str, idx: int):
        super().__init__()
        self.path = path
        self.idx = idx
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        box.set_margin_start(12); box.set_margin_end(12)
        box.set_margin_top(8); box.set_margin_bottom(8)

        num = Gtk.Label(label=str(idx + 1))
        num.set_width_chars(3)
        num.add_css_class("dim-label")
        num.add_css_class("caption")
        num.set_xalign(1)

        info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        title_lbl = Gtk.Label(label=track_name(path))
        title_lbl.set_halign(Gtk.Align.START)
        title_lbl.set_ellipsize(3)  # PANGO_ELLIPSIZE_END
        artist_lbl = Gtk.Label(label=track_artist(path))
        artist_lbl.set_halign(Gtk.Align.START)
        artist_lbl.add_css_class("caption")
        artist_lbl.add_css_class("dim-label")
        info.append(title_lbl); info.append(artist_lbl)
        info.set_hexpand(True)

        box.append(num); box.append(info)
        self.append(box)
        self._title_lbl = title_lbl


class MusicWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("Music")
        self.set_default_size(700, 520)
        self._tracks = []
        self._current = -1
        self._playing = False
        self._duration = 0
        self._seek_update = True

        # GStreamer playbin
        self._player = Gst.ElementFactory.make("playbin", "player")
        if self._player:
            bus = self._player.get_bus()
            bus.add_signal_watch()
            bus.connect("message", self._on_gst_message)

        # Layout
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        hdr = Adw.HeaderBar()
        hdr.set_title_widget(Adw.WindowTitle.new("Music", ""))
        add_btn = Gtk.Button()
        add_btn.set_icon_name("folder-music-symbolic")
        add_btn.set_tooltip_text("Add folder")
        add_btn.connect("clicked", self._add_folder)
        scan_btn = Gtk.Button()
        scan_btn.set_icon_name("view-refresh-symbolic")
        scan_btn.set_tooltip_text("Scan library")
        scan_btn.connect("clicked", self._scan)
        hdr.pack_end(add_btn)
        hdr.pack_end(scan_btn)
        main_box.append(hdr)

        # Now playing bar
        now_playing = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        now_playing.set_margin_start(16); now_playing.set_margin_end(16)
        now_playing.set_margin_top(12); now_playing.set_margin_bottom(8)

        self._art_icon = Gtk.Image.new_from_icon_name("audio-x-generic-symbolic")
        self._art_icon.set_pixel_size(64)
        self._title_lbl = Gtk.Label(label="Nothing playing")
        self._title_lbl.add_css_class("title-2")
        self._artist_lbl = Gtk.Label(label="")
        self._artist_lbl.add_css_class("dim-label")

        top_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        top_row.set_halign(Gtk.Align.CENTER)
        top_row.append(self._art_icon)
        meta_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        meta_box.set_valign(Gtk.Align.CENTER)
        meta_box.append(self._title_lbl); meta_box.append(self._artist_lbl)
        top_row.append(meta_box)
        now_playing.append(top_row)

        # Progress
        time_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._pos_lbl = Gtk.Label(label="0:00"); self._pos_lbl.add_css_class("caption")
        self._dur_lbl = Gtk.Label(label="0:00"); self._dur_lbl.add_css_class("caption")
        self._seek = Gtk.Scale(orientation=Gtk.Orientation.HORIZONTAL)
        self._seek.set_hexpand(True)
        self._seek.set_draw_value(False)
        self._seek.set_range(0, 100)
        self._seek.connect("change-value", self._on_seek)
        time_row.append(self._pos_lbl); time_row.append(self._seek); time_row.append(self._dur_lbl)
        now_playing.append(time_row)

        # Controls
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        controls.set_halign(Gtk.Align.CENTER)
        self._prev_btn = Gtk.Button.new_from_icon_name("media-skip-backward-symbolic")
        self._prev_btn.connect("clicked", self._prev)
        self._play_btn = Gtk.Button.new_from_icon_name("media-playback-start-symbolic")
        self._play_btn.add_css_class("suggested-action")
        self._play_btn.set_size_request(54, 54)
        self._play_btn.connect("clicked", self._play_pause)
        self._next_btn = Gtk.Button.new_from_icon_name("media-skip-forward-symbolic")
        self._next_btn.connect("clicked", self._next)
        self._vol = Gtk.Scale(orientation=Gtk.Orientation.HORIZONTAL)
        self._vol.set_size_request(100, -1)
        self._vol.set_range(0, 1)
        self._vol.set_value(0.8)
        self._vol.connect("value-changed", self._on_volume)
        vol_icon = Gtk.Image.new_from_icon_name("audio-volume-medium-symbolic")
        controls.append(self._prev_btn)
        controls.append(self._play_btn)
        controls.append(self._next_btn)
        controls.append(vol_icon)
        controls.append(self._vol)
        now_playing.append(controls)

        main_box.append(now_playing)
        main_box.append(Gtk.Separator())

        # Track list
        self._track_list = Gtk.ListBox()
        self._track_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._track_list.add_css_class("boxed-list")
        self._track_list.set_margin_start(12); self._track_list.set_margin_end(12)
        self._track_list.set_margin_top(8); self._track_list.set_margin_bottom(8)
        self._track_list.connect("row-activated", self._on_track_activated)
        scroll = Gtk.ScrolledWindow()
        scroll.set_child(self._track_list)
        scroll.set_vexpand(True)
        main_box.append(scroll)

        self.set_content(main_box)

        # Position update timer
        GLib.timeout_add(500, self._update_position)
        self._scan(None)

    def _scan(self, *_):
        GLib.timeout_add(100, self._do_scan)

    def _do_scan(self):
        self._tracks = scan_library(MUSIC_DIRS)
        while self._track_list.get_first_child():
            self._track_list.remove(self._track_list.get_first_child())
        for i, t in enumerate(self._tracks):
            self._track_list.append(TrackRow(t, i))
        return False

    def _add_folder(self, *_):
        dialog = Gtk.FileDialog()
        dialog.select_folder(self, None, self._on_folder_chosen)

    def _on_folder_chosen(self, dialog, result):
        try:
            folder = dialog.select_folder_finish(result)
            if folder:
                MUSIC_DIRS.append(Path(folder.get_path()))
                self._scan(None)
        except Exception:
            pass

    def _on_track_activated(self, lb, row):
        if isinstance(row, TrackRow):
            self._play_track(row.idx)

    def _play_track(self, idx):
        if idx < 0 or idx >= len(self._tracks):
            return
        self._current = idx
        path = self._tracks[idx]
        if self._player:
            self._player.set_state(Gst.State.NULL)
            self._player.set_property("uri", f"file://{path}")
            self._player.set_state(Gst.State.PLAYING)
        self._playing = True
        self._play_btn.set_icon_name("media-playback-pause-symbolic")
        self._title_lbl.set_label(track_name(path))
        self._artist_lbl.set_label(track_artist(path))

    def _play_pause(self, *_):
        if not self._tracks:
            return
        if self._current == -1:
            self._play_track(0)
            return
        if self._playing:
            if self._player:
                self._player.set_state(Gst.State.PAUSED)
            self._playing = False
            self._play_btn.set_icon_name("media-playback-start-symbolic")
        else:
            if self._player:
                self._player.set_state(Gst.State.PLAYING)
            self._playing = True
            self._play_btn.set_icon_name("media-playback-pause-symbolic")

    def _prev(self, *_):
        if self._current > 0:
            self._play_track(self._current - 1)

    def _next(self, *_):
        if self._current < len(self._tracks) - 1:
            self._play_track(self._current + 1)

    def _on_seek(self, scale, scroll_type, value):
        if self._player and self._duration > 0:
            pos = int(value / 100 * self._duration * Gst.SECOND)
            self._player.seek_simple(Gst.Format.TIME, Gst.SeekFlags.FLUSH, pos)

    def _on_volume(self, scale):
        if self._player:
            self._player.set_property("volume", scale.get_value())

    def _update_position(self):
        if self._player and self._playing:
            ok, pos = self._player.query_position(Gst.Format.TIME)
            ok2, dur = self._player.query_duration(Gst.Format.TIME)
            if ok and ok2 and dur > 0:
                secs = pos / Gst.SECOND
                total = dur / Gst.SECOND
                self._duration = total
                self._pos_lbl.set_label(fmt_time(secs))
                self._dur_lbl.set_label(fmt_time(total))
                self._seek.set_value(secs / total * 100)
        return True

    def _on_gst_message(self, bus, message):
        if message.type == Gst.MessageType.EOS:
            GLib.idle_add(self._next)
        elif message.type == Gst.MessageType.ERROR:
            err, _ = message.parse_error()
            print(f"[bastille-music] GStreamer error: {err}")


class MusicApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", lambda a: MusicWindow(a).present())

if __name__ == "__main__":
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    sys.exit(MusicApp().run(sys.argv))
