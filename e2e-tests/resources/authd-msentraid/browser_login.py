#!/usr/bin/env python3
import cairo
import subprocess

from robot.api import logger

import gi, os, sys

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("WebKit2", "4.1")

from gi.repository import Gdk, Gtk  # type: ignore # The interpreter usually does not recognize imports from gi.repository

# The import will be resolved at runtime, which means that the directory structure will be something like:
# test_run_dir/
#   resources/
#     authd/
#       browser_window.py <- the dependency
#     authd-msentraid/
#       browser_login.py  <- this file
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "authd")))
from browser_window import BrowserWindow, ascii_string_to_key_events  # type: ignore # This is resolved at runtime


def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <username> <password> <code> [<output-dir>]")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]
    device_code = sys.argv[3]
    output_dir = sys.argv[4] if len(sys.argv) > 4 else "."
    screenshot_dir = os.path.join(output_dir, "webview")
    os.makedirs(screenshot_dir, exist_ok=True)

    try:
        login(username, password, device_code, screenshot_dir)
    finally:
        write_video(screenshot_dir, os.path.join(output_dir, "webview_recording.webm"))


def login(username: str, password: str, device_code: str, screenshot_dir: str = "."):
    Gtk.init(None)
    browser = BrowserWindow()
    browser.show_all()

    browser.web_view.load_uri("https://microsoft.com/devicelogin")

    browser.wait_for_stable_page()
    screenshot_window(browser, os.path.join(screenshot_dir, "01-device-login.png"))
    browser.send_key_taps(
        ascii_string_to_key_events(device_code) + [Gdk.KEY_Return])

    browser.wait_for_stable_page()
    screenshot_window(browser, os.path.join(screenshot_dir, "02-device-login-enter-code.png"))
    browser.send_key_taps(
        ascii_string_to_key_events(username) + [Gdk.KEY_Return])

    browser.wait_for_stable_page()
    screenshot_window(browser, os.path.join(screenshot_dir, "03-device-login-enter-username.png"))
    browser.send_key_taps(
        ascii_string_to_key_events(password) + [Gdk.KEY_Return])

    browser.wait_for_stable_page()
    screenshot_window(browser, os.path.join(screenshot_dir, "04-device-login-enter-password.png"))
    browser.send_key_taps([Gdk.KEY_Return])

    browser.wait_for_stable_page()
    screenshot_window(browser, os.path.join(screenshot_dir, "05-device-login-success.png"))


def screenshot_window(window: Gtk.Window, filename: str):
    # Get widget allocation (size)
    alloc = window.get_allocation()
    width, height = alloc.width, alloc.height

    # Create an offscreen surface
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, width, height)
    ctx = cairo.Context(surface)

    # Render the window contents onto the Cairo surface
    window.draw(ctx)

    # Write to file (PNG)
    surface.write_to_png(filename)


def write_video(screenshot_dir: str, video_path: str):
    logger.warn(f"XXX: Writing video to {video_path}")
    subprocess.check_call([
        "ffmpeg",
        "-y",
        "-framerate", "1",
        "-pattern_type", "glob",
        "-i", f"{screenshot_dir}/*.png",
        video_path,
    ])


if __name__ == "__main__":
    main()
