"""Opt-in real X11 prompt smoke tests on a private Xvfb display.

Run under dbus-run-session with --binary pointing to a built rosec-prompt.
Requires Xvfb, libX11, libXtst and ImageMagick's import. Uses fixture values only.
"""
import argparse
import ctypes as c
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    x = c.CDLL('libX11.so.6')
    xt = c.CDLL('libXtst.so.6')
    pointer = c.c_void_p
    window = c.c_ulong
    errors = []
    error_handler_type = c.CFUNCTYPE(c.c_int, pointer, pointer)

    @error_handler_type
    def handle_x_error(_display, _event):
        # Keep Python's finally cleanup reachable even if a fixture window exits.
        errors.append('X11 protocol error')
        return 0

    x.XSetErrorHandler.argtypes = [error_handler_type]
    x.XSetErrorHandler(handle_x_error)
    x.XOpenDisplay.argtypes = [c.c_char_p]
    x.XOpenDisplay.restype = pointer
    x.XDefaultRootWindow.argtypes = [pointer]
    x.XDefaultRootWindow.restype = window
    x.XQueryTree.argtypes = [pointer, window, c.POINTER(window), c.POINTER(window), c.POINTER(c.POINTER(window)), c.POINTER(c.c_uint)]
    x.XFetchName.argtypes = [pointer, window, c.POINTER(pointer)]
    class Attributes(c.Structure):
        _fields_ = [('x', c.c_int), ('y', c.c_int), ('width', c.c_int), ('height', c.c_int), ('border_width', c.c_int), ('depth', c.c_int), ('visual', pointer), ('root', window), ('window_class', c.c_int), ('bit_gravity', c.c_int), ('win_gravity', c.c_int), ('backing_store', c.c_int), ('backing_planes', c.c_ulong), ('backing_pixel', c.c_ulong), ('save_under', c.c_int), ('colormap', c.c_ulong), ('map_installed', c.c_int), ('map_state', c.c_int), ('all_event_masks', c.c_long), ('your_event_mask', c.c_long), ('do_not_propagate_mask', c.c_long), ('override_redirect', c.c_int), ('screen', pointer)]
    x.XGetWindowAttributes.argtypes = [pointer, window, c.POINTER(Attributes)]
    x.XFree.argtypes = [pointer]
    x.XSetInputFocus.argtypes = [pointer, window, c.c_int, c.c_ulong]
    x.XStringToKeysym.argtypes = [c.c_char_p]
    x.XStringToKeysym.restype = c.c_ulong
    x.XKeysymToKeycode.argtypes = [pointer, c.c_ulong]
    x.XKeysymToKeycode.restype = c.c_uint
    x.XSync.argtypes = [pointer, c.c_int]
    x.XCloseDisplay.argtypes = [pointer]
    xt.XTestFakeKeyEvent.argtypes = [pointer, c.c_uint, c.c_int, c.c_ulong]
    with tempfile.TemporaryDirectory(prefix='rosec-gui-') as runtime:
        read_fd, write_fd = os.pipe()
        with (args.output / 'xvfb.log').open('w') as log:
            server = subprocess.Popen(['Xvfb', '-displayfd', str(write_fd), '-screen', '0', '1024x768x24', '-nolisten', 'tcp'], pass_fds=[write_fd], stdout=subprocess.DEVNULL, stderr=log)
        os.close(write_fd)
        display = None
        child = None
        try:
            with os.fdopen(read_fd) as output:
                display_name = ':' + output.readline().strip()
            assert display_name != ':', 'Xvfb did not allocate a display'
            display = x.XOpenDisplay(display_name.encode())
            assert display, 'cannot connect to private display'
            root = x.XDefaultRootWindow(display)
            env = dict(os.environ, DISPLAY=display_name, XDG_RUNTIME_DIR=runtime, WINIT_UNIX_BACKEND='x11')
            env.pop('WAYLAND_DISPLAY', None)

            def windows():
                root_return, parent = window(), window()
                children, count = c.POINTER(window)(), c.c_uint()
                x.XQueryTree(display, root, c.byref(root_return), c.byref(parent), c.byref(children), c.byref(count))
                found = []
                try:
                    for i in range(count.value):
                        name = pointer()
                        if x.XFetchName(display, children[i], c.byref(name)) and name.value:
                            attrs = Attributes()
                            x.XGetWindowAttributes(display, children[i], c.byref(attrs))
                            if attrs.map_state == 2 and attrs.width > 100 and attrs.height > 100:
                                found.append(int(children[i]))
                            x.XFree(name)
                finally:
                    if children:
                        x.XFree(children)
                return found

            def key(name):
                code = x.XKeysymToKeycode(display, x.XStringToKeysym(name.encode()))
                assert code, name
                xt.XTestFakeKeyEvent(display, code, 1, 0)
                xt.XTestFakeKeyEvent(display, code, 0, 0)
                x.XSync(display, 0)
                assert not errors, errors
                time.sleep(0.035)

            cases = [
                ('password', {'title': 'Fixture password'}, list('fixture123') + ['Return'], 0, {'password': 'fixture123'}),
                ('fields', {'title': 'Fixture credentials', 'fields': [{'id': 'username', 'kind': 'text', 'label': 'Username'}, {'id': 'password', 'kind': 'password', 'label': 'Password'}]}, list('alice') + ['Tab'] + list('fixture123') + ['Return'], 0, {'username': 'alice', 'password': 'fixture123'}),
                ('cancel', {'title': 'Fixture cancellation'}, ['Escape'], 1, None),
                ('confirm', {'title': 'Fixture confirmation', 'confirm_mode': True}, ['Return'], 0, {}),
                ('otp', {'title': 'Fixture OTP', 'fields': [{'id': 'otp', 'kind': 'totp', 'label': 'Code'}]}, list('123456') + ['Return'], 0, {'otp': '123456'}),
                ('otp_short', {'title': 'Fixture OTP validation', 'fields': [{'id': 'otp', 'kind': 'totp', 'label': 'Code'}]}, list('123') + ['Return', 'ASSERT_OPEN'] + list('456') + ['Return'], 0, {'otp': '123456'}),
                ('select', {'title': 'Fixture passkey selection', 'select': {'options': [{'id': 'alice', 'primary': 'alice@example.test'}, {'id': 'bob', 'primary': 'bob@example.test'}]}}, ['Down', 'Return'], 0, {'selected': 'bob'}),
            ]
            results = []
            for name, request, keys, expected_status, expected_json in cases:
                child = subprocess.Popen([str(args.binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
                child.stdin.write(json.dumps(request).encode())
                child.stdin.close()
                child.stdin = None
                deadline = time.monotonic() + 15
                found = []
                while time.monotonic() < deadline and child.poll() is None:
                    found = windows()
                    if found:
                        break
                    time.sleep(0.05)
                if not found:
                    out, err = child.communicate(timeout=3)
                    raise AssertionError(f'{name}: no window: {child.returncode}: {err.decode()}')
                x.XSetInputFocus(display, found[-1], 2, 0)
                x.XSync(display, 0)
                assert not errors, errors
                time.sleep(0.5)
                subprocess.run(['import', '-display', display_name, '-window', 'root', str(args.output / f'{name}.png')], check=True, timeout=10)
                for index, value in enumerate(keys):
                    if value == 'ASSERT_OPEN':
                        assert child.poll() is None, f'{name}: incomplete OTP was accepted'
                        continue
                    if index == len(keys) - 1 and value == 'Return':
                        time.sleep(0.15)
                        subprocess.run(['import', '-display', display_name, '-window', 'root', str(args.output / f'{name}-entered.png')], check=True, timeout=10)
                    key(value)
                out, err = child.communicate(timeout=10)
                (args.output / f'{name}.stderr').write_bytes(err)
                assert child.returncode == expected_status, (name, child.returncode, err.decode())
                if expected_json is None:
                    assert not out.strip(), (name, out)
                else:
                    assert json.loads(out) == expected_json, (name, out)
                results.append({'case': name, 'status': child.returncode, 'passed': True})
                print(f'PASS {name}', flush=True)
                child = None
            (args.output / 'results.json').write_text(json.dumps(results, indent=2))
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.communicate()
            if display:
                x.XCloseDisplay(display)
            server.terminate()
            server.wait(timeout=5)


if __name__ == '__main__':
    main()
