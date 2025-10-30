#!/usr/bin/env python3
import argparse
import locale

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
from browser_window import (
    BrowserWindow,
    ascii_string_to_key_events,
)  # type: ignore # This is resolved at runtime

from generate_totp import generate_totp # type: ignore # This is resolved at runtime

SNAPSHOT_INDEX = 0


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("username")
    parser.add_argument("password")
    parser.add_argument("device_code")
    parser.add_argument("totp_secret")
    parser.add_argument("--output-dir", required=False, default=os.path.realpath(os.curdir))
    parser.add_argument("--show-webview", action="store_true")
    args = parser.parse_args()

    locale.setlocale(locale.LC_ALL, "C")

    screenshot_dir = os.path.join(args.output_dir, "webview-snapshots")
    os.makedirs(screenshot_dir, exist_ok=True)

    Gtk.init(None)
    browser = BrowserWindow()
    browser.show_all()

    browser.start_recording()

    try:
        login(browser, args.username, args.password, args.device_code, args.totp_secret, screenshot_dir)
    finally:
        if browser.get_mapped():
            browser.capture_snapshot(screenshot_dir, "failure")
        browser.stop_recording(os.path.join(args.output_dir, "webview_recording.webm"))
        browser.destroy()


def login(browser, username: str, password: str, device_code: str, totp_secret: str, screenshot_dir: str = "."):
    browser.web_view.load_uri("https://microsoft.com/devicelogin")
    browser.wait_for_stable_page()
    browser.capture_snapshot(screenshot_dir, "page-loaded")

    browser.wait_for_text_visible("Enter code to allow access")
    browser.wait_for_stable_page()
    browser.capture_snapshot(screenshot_dir, "device-login-enter-code")
    browser.send_key_taps(
        ascii_string_to_key_events(device_code) + [Gdk.KEY_Return])

    browser.wait_for_text_visible("Sign in")
    browser.wait_for_stable_page()
    browser.capture_snapshot(screenshot_dir, "device-login-enter-username")
    browser.send_key_taps(
        ascii_string_to_key_events(username) + [Gdk.KEY_Return])

    browser.wait_for_stable_page()
    browser.wait_for_text_visible("Enter password")
    browser.capture_snapshot(screenshot_dir, "device-login-enter-password")
    browser.send_key_taps(
        ascii_string_to_key_events(password) + [Gdk.KEY_Return])

    # browser.wait_for_stable_page()
    # browser.wait_for_text_visible("Enter code")
    # browser.capture_snapshot(screenshot_dir, "device-login-enter-totp-code")
    # browser.send_key_taps(
    #     ascii_string_to_key_events(generate_totp(totp_secret)) + [Gdk.KEY_Return])

    browser.wait_for_text_visible("Are you trying to sign in")
    browser.wait_for_stable_page()
    browser.capture_snapshot(screenshot_dir, "device-login-confirm-signin")
    browser.send_key_taps([Gdk.KEY_Return])

    browser.wait_for_text_visible("You have signed in")
    browser.wait_for_stable_page()
    browser.capture_snapshot(screenshot_dir, "device-login-success")


if __name__ == "__main__":
    main()
