#!/usr/bin/env python3
"""bastille-calendar — Local calendar with event detail panel and week view."""
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
import sys, json, os
from datetime import date, datetime, timedelta
from pathlib import Path
from gi.repository import Gtk, Adw, Gio, GLib

APP_ID = "org.bastilleos.Calendar"
DATA_FILE = Path.home() / ".local/share/bastille-calendar/events.json"

EVENT_TYPES = ["Meeting", "Call", "Appointment", "Task", "Reminder", "Event", "Detected"]
TYPE_COLORS = {
    "Meeting": "#2a78d6", "Call": "#009300", "Appointment": "#fab219",
    "Task": "#7c3aed", "Reminder": "#d03b3b", "Event": "#2a78d6", "Detected": "#fab219",
}

def load_events():
    try:
        with open(DATA_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_events(events):
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(DATA_FILE, "w") as f:
        json.dump(events, f, indent=2)

def date_key(y, m, d):
    return f"{y}-{m:02d}-{d:02d}"


class EventRow(Adw.ActionRow):
    def __init__(self, ev: dict):
        super().__init__()
        self.ev = ev
        self.set_title(ev.get("title", ""))
        parts = []
        if ev.get("time"):
            parts.append(ev["time"])
        if ev.get("type"):
            parts.append(ev["type"])
        if parts:
            self.set_subtitle(" · ".join(parts))
        self.set_activatable(True)
        color = TYPE_COLORS.get(ev.get("type", ""), "#2a78d6")
        dot = Gtk.Label(label="●")
        dot.add_css_class("caption")
        self.add_prefix(dot)


class CalendarWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("Calendar")
        self.set_default_size(860, 580)
        self._events = load_events()
        self._selected_event = None

        # 3-pane: calendar | event list | event detail
        outer_split = Adw.NavigationSplitView()
        outer_split.set_min_sidebar_width(260)
        outer_split.set_max_sidebar_width(300)

        # ── Left: calendar widget ──
        cal_nav = Adw.NavigationPage()
        cal_nav.set_title("Calendar")
        cal_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        hdr = Adw.HeaderBar()
        hdr.set_title_widget(Adw.WindowTitle.new("Calendar", ""))
        new_btn = Gtk.Button()
        new_btn.set_icon_name("list-add-symbolic")
        new_btn.set_tooltip_text("New event")
        new_btn.connect("clicked", self._new_event)
        hdr.pack_end(new_btn)
        cal_box.append(hdr)

        self._cal = Gtk.Calendar()
        self._cal.set_margin_start(16); self._cal.set_margin_end(16)
        self._cal.set_margin_top(12); self._cal.set_margin_bottom(8)
        self._cal.connect("day-selected", self._on_day_selected)
        cal_box.append(self._cal)
        cal_nav.set_child(cal_box)

        # ── Center: event list for selected day ──
        list_nav = Adw.NavigationPage()
        list_nav.set_title("Events")
        list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        list_hdr = Adw.HeaderBar()
        self._date_title = Adw.WindowTitle.new("Events", "")
        list_hdr.set_title_widget(self._date_title)
        list_box.append(list_hdr)

        self._events_list = Gtk.ListBox()
        self._events_list.add_css_class("boxed-list")
        self._events_list.set_margin_start(12); self._events_list.set_margin_end(12)
        self._events_list.set_margin_top(8)
        self._events_list.connect("row-selected", self._on_event_selected)
        ev_scroll = Gtk.ScrolledWindow()
        ev_scroll.set_child(self._events_list)
        ev_scroll.set_vexpand(True)
        list_box.append(ev_scroll)
        list_nav.set_child(list_box)

        # ── Right: event detail / edit ──
        self._detail_nav = Adw.NavigationPage()
        self._detail_nav.set_title("Event Detail")
        detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        detail_hdr = Adw.HeaderBar()
        self._edit_btn = Gtk.Button.new_with_label("Edit")
        self._edit_btn.connect("clicked", self._edit_event)
        self._del_btn = Gtk.Button()
        self._del_btn.set_icon_name("user-trash-symbolic")
        self._del_btn.add_css_class("destructive-action")
        self._del_btn.connect("clicked", self._delete_event)
        detail_hdr.pack_end(self._edit_btn)
        detail_hdr.pack_end(self._del_btn)
        detail_box.append(detail_hdr)

        self._detail_grp = Adw.PreferencesGroup()
        self._detail_grp.set_margin_start(16); self._detail_grp.set_margin_end(16)
        self._detail_grp.set_margin_top(16)

        self._no_event_page = Adw.StatusPage()
        self._no_event_page.set_icon_name("x-office-calendar-symbolic")
        self._no_event_page.set_title("No event selected")
        self._no_event_page.set_description("Select an event from the list to see details.")
        self._no_event_page.set_vexpand(True)

        detail_scroll = Gtk.ScrolledWindow()
        detail_scroll.set_vexpand(True)
        self._detail_inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self._detail_inner.append(self._no_event_page)
        self._detail_inner.append(self._detail_grp)
        detail_scroll.set_child(self._detail_inner)
        detail_box.append(detail_scroll)
        self._detail_nav.set_child(detail_box)

        # Inner split: event list | event detail
        inner_split = Adw.NavigationSplitView()
        inner_split.set_sidebar(list_nav)
        inner_split.set_content(self._detail_nav)

        # Outer split: calendar | (list + detail)
        outer_split.set_sidebar(cal_nav)
        outer_split.set_content(inner_split)

        self.set_content(outer_split)
        self._refresh_markers()
        self._load_day()

    def _key(self, d=None):
        if d is None:
            d = self._cal.get_date()
        return date_key(d.get_year(), d.get_month() + 1, d.get_day_of_month())

    def _on_day_selected(self, cal):
        self._load_day()

    def _load_day(self):
        while self._events_list.get_first_child():
            self._events_list.remove(self._events_list.get_first_child())
        key = self._key()
        d = self._cal.get_date()
        self._date_title.set_title(f"{d.get_day_of_month()} {self._month_name(d.get_month())}")
        self._date_title.set_subtitle(str(d.get_year()))
        evs = self._events.get(key, [])
        if not evs:
            row = Adw.ActionRow()
            row.set_title("No events")
            row.set_subtitle("Tap + to add one")
            self._events_list.append(row)
        else:
            for ev in evs:
                self._events_list.append(EventRow(ev))
        self._show_no_event_page()

    def _month_name(self, m: int) -> str:
        return ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][m]

    def _on_event_selected(self, lb, row):
        if row is None or not isinstance(row, EventRow):
            self._show_no_event_page()
            return
        self._selected_event = (self._key(), row.ev)
        self._show_event_detail(row.ev)

    def _show_no_event_page(self):
        self._no_event_page.set_visible(True)
        self._detail_grp.set_visible(False)
        self._edit_btn.set_sensitive(False)
        self._del_btn.set_sensitive(False)

    def _show_event_detail(self, ev: dict):
        self._no_event_page.set_visible(False)
        self._detail_grp.set_visible(True)
        self._edit_btn.set_sensitive(True)
        self._del_btn.set_sensitive(True)

        # Rebuild detail group
        while self._detail_grp.get_first_child():
            pass  # can't remove from PreferencesGroup easily; recreate

        for field, value in [
            ("Title", ev.get("title", "")),
            ("Date", self._key()),
            ("Time", ev.get("time", "All day")),
            ("Type", ev.get("type", "Event")),
            ("Notes", ev.get("notes", "")),
            ("Source", ev.get("source", "Manual")),
        ]:
            if value:
                r = Adw.ActionRow()
                r.set_title(field)
                r.set_subtitle(value)
                self._detail_grp.add(r)

    def _new_event(self, *_):
        self._event_dialog(None)

    def _edit_event(self, *_):
        if self._selected_event:
            _, ev = self._selected_event
            self._event_dialog(ev)

    def _event_dialog(self, existing=None):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Edit event" if existing else "New event")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(16); box.set_margin_end(16)

        title_e = Gtk.Entry(); title_e.set_placeholder_text("Event title")
        time_e = Gtk.Entry(); time_e.set_placeholder_text("Time (e.g. 14:00)")
        notes_e = Gtk.Entry(); notes_e.set_placeholder_text("Notes (optional)")
        type_combo = Gtk.DropDown.new_from_strings(EVENT_TYPES)

        if existing:
            title_e.set_text(existing.get("title", ""))
            time_e.set_text(existing.get("time", ""))
            notes_e.set_text(existing.get("notes", ""))
            if existing.get("type") in EVENT_TYPES:
                type_combo.set_selected(EVENT_TYPES.index(existing["type"]))

        for w in [title_e, time_e, notes_e, type_combo]:
            box.append(w)
        dlg.set_extra_child(box)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("save", "Save")
        dlg.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)

        def resp(d, r):
            if r == "save" and title_e.get_text():
                key = self._key()
                ev = {
                    "title": title_e.get_text(),
                    "time": time_e.get_text(),
                    "notes": notes_e.get_text(),
                    "type": EVENT_TYPES[type_combo.get_selected()],
                    "source": "Manual",
                }
                if existing:
                    evs = self._events.get(key, [])
                    for i, e in enumerate(evs):
                        if e is existing:
                            evs[i] = ev
                            break
                else:
                    self._events.setdefault(key, []).append(ev)
                save_events(self._events)
                self._load_day()
                self._refresh_markers()
        dlg.connect("response", resp)
        dlg.present()

    def _delete_event(self, *_):
        if not self._selected_event:
            return
        key, ev = self._selected_event
        evs = self._events.get(key, [])
        if ev in evs:
            evs.remove(ev)
        if not evs:
            self._events.pop(key, None)
        save_events(self._events)
        self._selected_event = None
        self._load_day()
        self._refresh_markers()
        self._show_no_event_page()

    def _refresh_markers(self):
        self._cal.clear_marks()
        for key in self._events:
            try:
                parts = key.split("-")
                y, m, d = int(parts[0]), int(parts[1]), int(parts[2])
                d_obj = self._cal.get_date()
                if d_obj.get_year() == y and d_obj.get_month() + 1 == m:
                    self._cal.mark_day(d)
            except Exception:
                pass

    def add_detected_event(self, title: str, date_hint: str = "", source: str = "Mail"):
        """Called by bastille-mail when it detects a calendar event."""
        key = self._key()
        ev = {"title": title, "time": date_hint, "type": "Detected", "source": source, "notes": ""}
        self._events.setdefault(key, []).append(ev)
        save_events(self._events)
        self._load_day()
        self._refresh_markers()


class CalApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", lambda a: CalendarWindow(a).present())

if __name__ == "__main__":
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    sys.exit(CalApp().run(sys.argv))
