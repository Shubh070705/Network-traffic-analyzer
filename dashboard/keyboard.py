"""Non-blocking keyboard shortcuts for the Rich dashboard."""

from __future__ import annotations

import os
import select
import sys
import threading
import time
from typing import TextIO

from dashboard.filtering import DashboardFilterState


class KeyboardController:
    """Reads dashboard shortcuts without blocking packet capture or analysis."""

    def __init__(self, state: DashboardFilterState, input_stream: TextIO | None = None) -> None:
        self.state = state
        self.input_stream = input_stream or sys.stdin
        self.enabled = bool(getattr(self.input_stream, "isatty", lambda: False)())
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._old_termios = None

    def start(self) -> None:
        if not self.enabled or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="KeyboardController", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None
        self._restore_terminal()

    def _run(self) -> None:
        try:
            if sys.platform.startswith("win"):
                self._run_windows()
            else:
                self._run_posix()
        except Exception:
            self.enabled = False
            self._restore_terminal()

    def _run_posix(self) -> None:
        import termios
        import tty

        fd = self.input_stream.fileno()
        self._old_termios = termios.tcgetattr(fd)
        tty.setcbreak(fd)
        try:
            while not self._stop_event.is_set():
                readable, _, _ = select.select([fd], [], [], 0.1)
                if readable:
                    data = os.read(fd, 32)
                    self.apply_input_bytes(data)
        finally:
            self._restore_terminal()

    def apply_input_bytes(self, data: bytes) -> None:
        for char in data.decode(errors="ignore"):
            self.state.apply_shortcut(char)

    def _run_windows(self) -> None:
        import msvcrt

        while not self._stop_event.is_set():
            if msvcrt.kbhit():
                char = msvcrt.getwch()
                self.state.apply_shortcut(char)
            time.sleep(0.05)

    def _restore_terminal(self) -> None:
        if self._old_termios is None:
            return
        try:
            import termios

            termios.tcsetattr(self.input_stream.fileno(), termios.TCSADRAIN, self._old_termios)
        except Exception:
            pass
        self._old_termios = None
