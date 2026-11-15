"""Render the site's share picture: src/share.html -> static/share.png, 1200 x 630.

    cd hashfun/web && npm run share        (python3 src/share.py; needs Playwright with Chromium)

The picture is committed: the site serves it as the og:image / twitter:image of every page that is
not a coin with a picture of its own (hashfun/web.py Site.preview). Render it again when the words
(static/pitch.json) or the page's look (static/style.css) change."""
import functools
import http.server
import os
import threading

from playwright.sync_api import sync_playwright

WEB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=WEB))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    out = os.path.join(WEB, "static", "share.png")
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_context(viewport={"width": 1200, "height": 630}, device_scale_factor=1).new_page()
        page.goto(f"http://127.0.0.1:{srv.server_address[1]}/src/share.html")
        page.wait_for_selector("body[data-ready]")
        page.screenshot(path=out, clip={"x": 0, "y": 0, "width": 1200, "height": 630})
        browser.close()
    srv.shutdown()
    print(f"{out}: {os.path.getsize(out)} bytes")


if __name__ == "__main__":
    main()
