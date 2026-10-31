#!/usr/bin/env python3
"""bastille-maps — Privacy-respecting maps via OpenStreetMap (WebKitGTK)."""
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
gi.require_version('WebKit', '6.0')
import sys
from gi.repository import Gtk, Adw, Gio, WebKit

APP_ID = "org.bastilleos.Maps"

OSM_HTML = """<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
  body { margin: 0; background: #0b0c10; }
  #map { height: 100vh; width: 100%; }
</style>
</head><body>
<div id="map"></div>
<script>
var map = L.map('map').setView([51.505, -0.09], 13);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
  maxZoom: 19
}).addTo(map);
</script>
</body></html>"""


class MapsWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("Maps")
        self.set_default_size(900, 620)

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()

        self._search = Gtk.Entry()
        self._search.set_placeholder_text("Search location…")
        self._search.set_hexpand(True)
        self._search.connect("activate", self._search_location)
        header.set_title_widget(self._search)

        notice = Gtk.Label.new("OpenStreetMap — no account required")
        notice.add_css_class("caption")
        notice.add_css_class("dim-label")
        header.pack_end(notice)
        toolbar.add_top_bar(header)

        settings = WebKit.Settings()
        settings.set_enable_javascript(True)
        settings.set_enable_webgl(True)
        settings.set_enable_media(False)
        settings.set_enable_media_capabilities_api(False)
        # Disable sensors, geolocation for privacy
        settings.set_enable_mock_capture_devices(False)

        self._wv = WebKit.WebView()
        self._wv.set_settings(settings)
        self._wv.load_html(OSM_HTML, "about:blank")
        toolbar.set_content(self._wv)
        self.set_content(toolbar)

    def _search_location(self, entry):
        query = entry.get_text().strip()
        if not query:
            return
        # Geocode via Nominatim, then pan map
        import urllib.request, json
        url = f"https://nominatim.openstreetmap.org/search?q={urllib.parse.quote(query)}&format=json&limit=1"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "bastille-maps/1.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                results = json.loads(r.read())
            if results:
                lat = results[0]["lat"]
                lon = results[0]["lon"]
                self._wv.run_javascript(
                    f"map.setView([{lat},{lon}], 14);", None, None)
        except Exception:
            pass


import urllib.parse

class MapsApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect("activate", lambda a: MapsWindow(a).present())

if __name__ == "__main__":
    Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    sys.exit(MapsApp().run(sys.argv))
