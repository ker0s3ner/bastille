#!/usr/bin/env python3
"""bastille-weather — Privacy-first weather app (wttr.in, no account required)."""
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
gi.require_version('Soup', '3.0')
import sys, json
from pathlib import Path
from gi.repository import Gtk, Adw, Gio, GLib, Soup

APP_ID = "org.bastilleos.Weather"
STATE_FILE = Path.home() / ".local/share/bastille-weather/state.json"

WMO_ICONS = {
    0: "weather-clear-symbolic", 1: "weather-few-clouds-symbolic",
    2: "weather-few-clouds-symbolic", 3: "weather-overcast-symbolic",
    45: "weather-fog-symbolic", 48: "weather-fog-symbolic",
    51: "weather-showers-scattered-symbolic", 53: "weather-showers-scattered-symbolic",
    55: "weather-showers-symbolic", 61: "weather-showers-symbolic",
    63: "weather-showers-symbolic", 65: "weather-storm-symbolic",
    71: "weather-snow-symbolic", 73: "weather-snow-symbolic",
    75: "weather-storm-symbolic", 77: "weather-snow-symbolic",
    80: "weather-showers-symbolic", 81: "weather-showers-symbolic",
    82: "weather-storm-symbolic", 85: "weather-snow-symbolic",
    95: "weather-storm-symbolic", 96: "weather-storm-symbolic",
    99: "weather-storm-symbolic",
}

WMO_DESC = {
    0: "Clear sky", 1: "Mostly clear", 2: "Partly cloudy", 3: "Overcast",
    45: "Foggy", 48: "Icy fog", 51: "Light drizzle", 53: "Drizzle",
    55: "Heavy drizzle", 61: "Light rain", 63: "Rain", 65: "Heavy rain",
    71: "Light snow", 73: "Snow", 75: "Heavy snow", 77: "Snow grains",
    80: "Showers", 81: "Heavy showers", 82: "Violent showers",
    85: "Snow showers", 95: "Thunderstorm", 96: "Thunderstorm + hail",
    99: "Heavy thunderstorm + hail",
}

DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"cities": ["London", "Berlin", "Tokyo"], "last_city": "London"}

def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


class CityRow(Adw.ActionRow):
    def __init__(self, city: str, temp: str = "–"):
        super().__init__()
        self.city = city
        self.set_title(city)
        self.set_subtitle(temp)
        self.set_activatable(True)
        icon = Gtk.Image.new_from_icon_name("weather-clear-symbolic")
        self.add_prefix(icon)
        self._icon_widget = icon

    def update(self, temp: str, wmo: int):
        self.set_subtitle(temp)
        self._icon_widget.set_from_icon_name(WMO_ICONS.get(wmo, "weather-clear-symbolic"))


class StatCard(Gtk.Box):
    def __init__(self, label: str, value: str, icon: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.add_css_class("card")
        self.set_margin_start(4); self.set_margin_end(4)
        self.set_margin_top(4); self.set_margin_bottom(4)
        self.set_size_request(120, 80)
        img = Gtk.Image.new_from_icon_name(icon)
        img.set_pixel_size(20)
        img.set_margin_top(12)
        lbl = Gtk.Label(label=label)
        lbl.add_css_class("caption"); lbl.add_css_class("dim-label")
        val = Gtk.Label(label=value)
        val.add_css_class("title-3")
        self.append(img); self.append(val); self.append(lbl)
        self._val_lbl = val

    def set_value(self, v: str):
        self._val_lbl.set_label(v)


class ForecastDay(Gtk.Box):
    def __init__(self, day: str, high: str, low: str, wmo: int):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.add_css_class("card")
        self.set_margin_start(3); self.set_margin_end(3)
        self.set_margin_top(4); self.set_margin_bottom(4)
        self.set_size_request(80, 100)
        day_lbl = Gtk.Label(label=day)
        day_lbl.add_css_class("caption"); day_lbl.add_css_class("dim-label")
        day_lbl.set_margin_top(8)
        icon = Gtk.Image.new_from_icon_name(WMO_ICONS.get(wmo, "weather-clear-symbolic"))
        icon.set_pixel_size(24)
        hi = Gtk.Label(label=high); hi.add_css_class("heading")
        lo = Gtk.Label(label=low); lo.add_css_class("caption"); lo.add_css_class("dim-label")
        lo.set_margin_bottom(8)
        self.append(day_lbl); self.append(icon); self.append(hi); self.append(lo)


class WeatherWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("Weather")
        self.set_default_size(860, 580)
        self._state = load_state()
        self._soup = Soup.Session()
        self._city_rows = {}

        split = Adw.NavigationSplitView()
        split.set_min_sidebar_width(200)
        split.set_max_sidebar_width(240)

        # ── Sidebar: city list ──
        sidebar_nav = Adw.NavigationPage()
        sidebar_nav.set_title("Weather")
        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        hdr = Adw.HeaderBar()
        hdr.set_title_widget(Adw.WindowTitle.new("Weather", ""))
        add_btn = Gtk.Button()
        add_btn.set_icon_name("list-add-symbolic")
        add_btn.set_tooltip_text("Add city")
        add_btn.connect("clicked", self._add_city)
        hdr.pack_end(add_btn)
        sidebar_box.append(hdr)

        self._city_list = Gtk.ListBox()
        self._city_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._city_list.add_css_class("navigation-sidebar")
        self._city_list.connect("row-selected", self._on_city_selected)

        city_scroll = Gtk.ScrolledWindow()
        city_scroll.set_child(self._city_list)
        city_scroll.set_vexpand(True)
        sidebar_box.append(city_scroll)
        sidebar_nav.set_child(sidebar_box)

        # ── Content: hero + cards ──
        content_nav = Adw.NavigationPage()
        content_nav.set_title("Forecast")
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        content_hdr = Adw.HeaderBar()
        self._city_title = Adw.WindowTitle.new("Select a city", "")
        content_hdr.set_title_widget(self._city_title)
        refresh_btn = Gtk.Button()
        refresh_btn.set_icon_name("view-refresh-symbolic")
        refresh_btn.set_tooltip_text("Refresh")
        refresh_btn.connect("clicked", lambda _: self._fetch_current())
        content_hdr.pack_end(refresh_btn)
        content_box.append(content_hdr)

        main_scroll = Gtk.ScrolledWindow()
        main_scroll.set_vexpand(True)
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        inner.set_margin_start(20); inner.set_margin_end(20)
        inner.set_margin_top(16); inner.set_margin_bottom(20)

        # Hero: current temp + description
        hero = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=24)
        hero.set_halign(Gtk.Align.CENTER)
        self._hero_icon = Gtk.Image.new_from_icon_name("weather-clear-symbolic")
        self._hero_icon.set_pixel_size(80)
        hero_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        hero_text.set_valign(Gtk.Align.CENTER)
        self._temp_lbl = Gtk.Label(label="–°C")
        self._temp_lbl.add_css_class("title-1")
        self._desc_lbl = Gtk.Label(label="Select a city to load weather")
        self._desc_lbl.add_css_class("title-3")
        self._feels_lbl = Gtk.Label(label="")
        self._feels_lbl.add_css_class("dim-label")
        hero_text.append(self._temp_lbl)
        hero_text.append(self._desc_lbl)
        hero_text.append(self._feels_lbl)
        hero.append(self._hero_icon)
        hero.append(hero_text)
        inner.append(hero)

        # Stat cards row
        cards_scroll = Gtk.ScrolledWindow()
        cards_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER)
        cards_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        cards_row.set_halign(Gtk.Align.CENTER)
        self._cards = {
            "humidity":    StatCard("Humidity", "–%", "weather-overcast-symbolic"),
            "wind":        StatCard("Wind", "– km/h", "weather-windy-symbolic"),
            "pressure":    StatCard("Pressure", "– hPa", "appointment-symbolic"),
            "uv":          StatCard("UV Index", "–", "weather-clear-symbolic"),
            "visibility":  StatCard("Visibility", "– km", "find-location-symbolic"),
            "precip":      StatCard("Precipitation", "– mm", "weather-showers-symbolic"),
        }
        for card in self._cards.values():
            cards_row.append(card)
        cards_scroll.set_child(cards_row)
        inner.append(cards_scroll)

        # 7-day forecast
        forecast_lbl = Gtk.Label(label="7-Day Forecast")
        forecast_lbl.add_css_class("heading")
        forecast_lbl.set_halign(Gtk.Align.START)
        inner.append(forecast_lbl)

        self._forecast_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self._forecast_row.set_halign(Gtk.Align.CENTER)
        inner.append(self._forecast_row)

        main_scroll.set_child(inner)
        content_box.append(main_scroll)
        content_nav.set_child(content_box)

        split.set_sidebar(sidebar_nav)
        split.set_content(content_nav)
        self.set_content(split)

        self._populate_cities()

    def _populate_cities(self):
        while self._city_list.get_first_child():
            self._city_list.remove(self._city_list.get_first_child())
        self._city_rows = {}
        for city in self._state.get("cities", []):
            row = CityRow(city)
            self._city_list.append(row)
            self._city_rows[city] = row

        # Select last city
        last = self._state.get("last_city", "")
        if last in self._city_rows:
            self._city_list.select_row(self._city_rows[last])
        elif self._city_rows:
            first_row = self._city_list.get_first_child()
            if first_row:
                self._city_list.select_row(first_row)

    def _on_city_selected(self, lb, row):
        if row is None or not isinstance(row, CityRow):
            return
        self._current_city = row.city
        self._city_title.set_title(row.city)
        self._state["last_city"] = row.city
        save_state(self._state)
        self._fetch_current()

    def _fetch_current(self):
        city = getattr(self, "_current_city", None)
        if not city:
            return
        url = f"https://wttr.in/{city}?format=j1"
        msg = Soup.Message.new("GET", url)
        self._soup.send_and_read_async(msg, GLib.PRIORITY_DEFAULT, None, self._on_response)

    def _on_response(self, session, result):
        try:
            data_bytes = session.send_and_read_finish(result)
            data = json.loads(data_bytes.get_data().decode())
            GLib.idle_add(self._update_ui, data)
        except Exception as e:
            GLib.idle_add(self._set_error, str(e))

    def _update_ui(self, data):
        try:
            current = data["current_condition"][0]
            temp = current.get("temp_C", "–")
            feels = current.get("FeelsLikeC", "–")
            desc = current.get("weatherDesc", [{}])[0].get("value", "")
            humidity = current.get("humidity", "–")
            wind = current.get("windspeedKmph", "–")
            pressure = current.get("pressure", "–")
            uv = current.get("uvIndex", "–")
            visibility = current.get("visibility", "–")
            precip = current.get("precipMM", "–")
            wmo = int(current.get("weatherCode", 0))

            self._temp_lbl.set_label(f"{temp}°C")
            self._desc_lbl.set_label(desc)
            self._feels_lbl.set_label(f"Feels like {feels}°C")
            self._hero_icon.set_from_icon_name(WMO_ICONS.get(wmo, "weather-clear-symbolic"))

            self._cards["humidity"].set_value(f"{humidity}%")
            self._cards["wind"].set_value(f"{wind} km/h")
            self._cards["pressure"].set_value(f"{pressure} hPa")
            self._cards["uv"].set_value(str(uv))
            self._cards["visibility"].set_value(f"{visibility} km")
            self._cards["precip"].set_value(f"{precip} mm")

            city = getattr(self, "_current_city", "")
            if city in self._city_rows:
                self._city_rows[city].update(f"{temp}°C", wmo)

            # Update 7-day forecast
            while self._forecast_row.get_first_child():
                self._forecast_row.remove(self._forecast_row.get_first_child())

            for i, day_data in enumerate(data.get("weather", [])[:7]):
                hi = day_data.get("maxtempC", "–")
                lo = day_data.get("mintempC", "–")
                d_wmo = int(day_data.get("hourly", [{}])[3].get("weatherCode", 0))
                day_name = DAYS[i] if i < len(DAYS) else f"Day {i+1}"
                self._forecast_row.append(ForecastDay(day_name, f"{hi}°", f"{lo}°", d_wmo))

        except Exception as e:
            self._set_error(str(e))
        return False

    def _set_error(self, msg):
        self._desc_lbl.set_label(f"Error: {msg}")
        return False

    def _add_city(self, *_):
        dlg = Adw.MessageDialog.new(self)
        dlg.set_heading("Add city")
        entry = Gtk.Entry()
        entry.set_placeholder_text("City name (e.g. Paris)")
        entry.set_margin_start(16); entry.set_margin_end(16)
        dlg.set_extra_child(entry)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("add", "Add")
        dlg.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)
        def resp(d, r):
            if r == "add" and entry.get_text():
                city = entry.get_text().strip()
                if city not in self._state["cities"]:
                    self._state["cities"].append(city)
                    save_state(self._state)
                    self._populate_cities()
        dlg.connect("response", resp)
        dlg.present()


class WeatherApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", lambda a: WeatherWindow(a).present())

if __name__ == "__main__":
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    sys.exit(WeatherApp().run(sys.argv))
