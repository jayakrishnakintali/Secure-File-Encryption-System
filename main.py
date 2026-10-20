"""
Secure File Encryption and Decryption System - desktop application (GUI).

This file contains ONLY the user interface. All cryptography lives in
crypto_manager.py. Long-running work (key derivation, reading, encrypting,
writing) runs in a background thread; the thread talks to the GUI through a
queue that the main Tkinter loop polls, so the window never freezes and
Tkinter is only ever touched from the main thread.

Run with:  python main.py
"""

from __future__ import annotations

import errno
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont
from typing import Callable, Dict, Optional, Tuple

import crypto_manager as cm

APP_NAME = "Secure File Encryption System"
APP_STANDARD = "AES-256-GCM  \u00b7  Scrypt key derivation"
MIN_PASSWORD_LENGTH = 8
RECOMMENDED_PASSWORD_LENGTH = 12


# ==========================================================================
# Theme, scaling and small helpers
# ==========================================================================
class T:
    """Colour palette (cybersecurity-inspired: midnight navy + electric blue)."""
    NAVY = "#0B1437"
    NAVY_HOVER = "#16234E"
    NAVY_ACTIVE = "#1F2F68"
    NAVY_TEXT = "#C9D3F2"
    NAVY_MUTED = "#8A97C4"
    NAVY_ACCENT = "#5B8DFF"

    BLUE = "#2F6BFF"
    BLUE_HOVER = "#1F55E0"
    BLUE_PRESSED = "#1744B8"
    BLUE_SOFT = "#E6EEFF"
    BLUE_SOFT_HOVER = "#D5E3FF"
    BLUE_SOFT_PRESSED = "#C3D6FF"

    TEAL = "#0FB38A"
    TEAL_DARK = "#0A7F62"
    TEAL_SOFT = "#E3F8F1"

    RED = "#E5484D"
    RED_DARK = "#B42327"
    RED_SOFT = "#FDECEC"

    BG = "#F2F4FD"
    CARD = "#FFFFFF"
    SOFT = "#F5F7FF"
    BORDER = "#DCE2F5"
    TEXT = "#101937"
    MUTED = "#5A6487"
    DISABLED_BG = "#BCC6E6"
    DISABLED_FG = "#F4F6FD"


_scale = 1.0           # set once the window exists (high-DPI support)
FONT_FAMILY = "Segoe UI"


def dp(value: float) -> int:
    """Scale a pixel size for the current display DPI."""
    return int(round(value * _scale))


def font(size: int, weight: str = "normal") -> Tuple[str, int, str]:
    return (FONT_FAMILY, size, weight)


def enable_high_dpi() -> None:
    """Ask Windows not to bitmap-stretch the window (keeps text crisp)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def format_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} bytes"
    size = float(num_bytes)
    for unit in ("KB", "MB", "GB", "TB"):
        size /= 1024
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}  ({num_bytes:,} bytes)"
    return f"{num_bytes:,} bytes"


def shorten(text: str, limit: int = 60) -> str:
    """Shorten long paths in the middle: 'C:\\Users\\...\\folder'."""
    if len(text) <= limit:
        return text
    keep = (limit - 3) // 2
    return text[:keep] + "\u2026" + text[-(limit - keep - 1):]


def friendly_error(exc: BaseException) -> str:
    """Turn any exception into a clear message without leaking internals."""
    if isinstance(exc, cm.CryptoError):
        return str(exc)
    if isinstance(exc, PermissionError):
        return ("Windows denied access. Close the file in other programs, or choose "
                "a folder where you are allowed to save files.")
    if isinstance(exc, FileNotFoundError):
        return "The file or folder no longer exists. Please select the file again."
    if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
        return "There is not enough free disk space for the output file."
    if isinstance(exc, OSError):
        return f"A file-system error occurred: {exc.strerror or exc}"
    if isinstance(exc, MemoryError):
        return "The computer ran out of memory. Close other programs and try again."
    return f"An unexpected error occurred ({type(exc).__name__}). No output file was kept."


def make_card(master: tk.Misc) -> tk.Frame:
    """A white 'card' with a thin border (closest stable look to a rounded card)."""
    return tk.Frame(master, bg=T.CARD, bd=0, highlightthickness=1,
                    highlightbackground=T.BORDER, highlightcolor=T.BORDER)


def rounded_rect(canvas: tk.Canvas, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


# ==========================================================================
# Reusable widgets
# ==========================================================================
class WrapLabel(tk.Label):
    """A label whose text re-wraps when the available width changes."""

    def __init__(self, master, **kw):
        kw.setdefault("justify", "left")
        kw.setdefault("anchor", "w")
        kw.setdefault("wraplength", dp(280))
        super().__init__(master, **kw)
        self._wrap = kw["wraplength"]
        self.bind("<Configure>", self._rewrap)

    def _rewrap(self, event) -> None:
        wrap = max(event.width - dp(4), dp(80))
        if wrap != self._wrap:
            self._wrap = wrap
            self.configure(wraplength=wrap)


class FlatButton(tk.Label):
    """
    Flat button with hover / pressed / disabled / keyboard-focus states.
    (tk.Button cannot be styled consistently on Windows, so we draw our own.)
    """

    STYLES = {
        "primary": dict(bg=T.BLUE, fg="#FFFFFF", hover=T.BLUE_HOVER, press=T.BLUE_PRESSED),
        "secondary": dict(bg=T.BLUE_SOFT, fg=T.BLUE_PRESSED, hover=T.BLUE_SOFT_HOVER,
                          press=T.BLUE_SOFT_PRESSED),
    }

    def __init__(self, master, text: str, command: Callable[[], None], kind: str = "primary",
                 surface: str = T.CARD, size: int = 10, padx: int = 18, pady: int = 9):
        self._palette = self.STYLES[kind]
        super().__init__(master, text=text, bg=self._palette["bg"], fg=self._palette["fg"],
                         font=font(size, "bold"), cursor="hand2", padx=dp(padx), pady=dp(pady),
                         takefocus=True, highlightthickness=dp(2),
                         highlightbackground=surface, highlightcolor=T.NAVY)
        self._callback = command
        self._enabled = True
        self._hover = False
        self._pressed = False
        self.bind("<Enter>", lambda e: self._set_hover(True))
        self.bind("<Leave>", lambda e: self._set_hover(False))
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Return>", self._on_key)
        self.bind("<space>", self._on_key)

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self._refresh()

    def set_text(self, text: str) -> None:
        self.configure(text=text)

    def _set_hover(self, value: bool) -> None:
        self._hover = value
        self._refresh()

    def _on_press(self, _event) -> None:
        if self._enabled:
            self._pressed = True
            self._refresh()

    def _on_release(self, event) -> None:
        was_pressed, self._pressed = self._pressed, False
        self._refresh()
        inside = 0 <= event.x < self.winfo_width() and 0 <= event.y < self.winfo_height()
        if self._enabled and was_pressed and inside:
            self._callback()

    def _on_key(self, _event) -> str:
        if self._enabled:
            self._callback()
        return "break"

    def _refresh(self) -> None:
        if not self._enabled:
            self.configure(bg=T.DISABLED_BG, fg=T.DISABLED_FG, cursor="arrow")
            return
        if self._pressed:
            bg = self._palette["press"]
        elif self._hover:
            bg = self._palette["hover"]
        else:
            bg = self._palette["bg"]
        self.configure(bg=bg, fg=self._palette["fg"], cursor="hand2")


class NavItem(tk.Frame):
    """Sidebar navigation entry with hover, active and keyboard-focus states."""

    def __init__(self, master, text: str, command: Callable[[], None]):
        super().__init__(master, bg=T.NAVY, takefocus=True, highlightthickness=dp(2),
                         highlightbackground=T.NAVY, highlightcolor=T.NAVY_ACCENT, cursor="hand2")
        self._callback = command
        self._active = False
        self._hover = False
        self.bar = tk.Frame(self, width=dp(4), bg=T.NAVY)
        self.bar.pack(side="left", fill="y")
        self.label = tk.Label(self, text=text, anchor="w", font=font(11), bg=T.NAVY,
                              fg=T.NAVY_TEXT, cursor="hand2")
        self.label.pack(side="left", fill="both", expand=True, padx=dp(16), pady=dp(11))
        for widget in (self, self.label, self.bar):
            widget.bind("<Enter>", lambda e: self._set_hover(True))
            widget.bind("<Leave>", lambda e: self._set_hover(False))
            widget.bind("<ButtonRelease-1>", lambda e: self._callback())
        self.bind("<Return>", lambda e: self._callback())
        self.bind("<space>", lambda e: self._callback())

    def set_active(self, active: bool) -> None:
        self._active = active
        self._paint()

    def _set_hover(self, value: bool) -> None:
        self._hover = value
        self._paint()

    def _paint(self) -> None:
        bg = T.NAVY_ACTIVE if self._active else (T.NAVY_HOVER if self._hover else T.NAVY)
        self.configure(bg=bg)
        self.label.configure(bg=bg, fg="#FFFFFF" if self._active else T.NAVY_TEXT,
                             font=font(11, "bold" if self._active else "normal"))
        self.bar.configure(bg=T.NAVY_ACCENT if self._active else bg)


class ScrollableFrame(tk.Frame):
    """A frame whose content scrolls vertically only when it does not fit."""

    def __init__(self, master, bg: str):
        super().__init__(master, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview,
                                  style="App.Vertical.TScrollbar")
        self.canvas.configure(yscrollcommand=self.vbar.set)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.pack(side="left", fill="both", expand=True)
        self._bar_visible = False
        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        self.bind_all("<MouseWheel>", self._on_wheel)
        self.bind_all("<Button-4>", lambda e: self._scroll_units(-3))
        self.bind_all("<Button-5>", lambda e: self._scroll_units(3))

    def _needs_scroll(self) -> bool:
        return self.inner.winfo_reqheight() > self.canvas.winfo_height() + 1

    def _on_inner_configure(self, _event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.after_idle(self._update_bar)

    def _on_canvas_configure(self, event) -> None:
        self.canvas.itemconfigure(self._window, width=event.width)
        self.after_idle(self._update_bar)

    def _update_bar(self) -> None:
        need = self._needs_scroll()
        if need and not self._bar_visible:
            self.vbar.pack(side="right", fill="y")
            self._bar_visible = True
        elif not need and self._bar_visible:
            self.vbar.pack_forget()
            self._bar_visible = False
            self.canvas.yview_moveto(0)

    def _scroll_units(self, units: int) -> None:
        if self._needs_scroll():
            self.canvas.yview_scroll(units, "units")

    def _on_wheel(self, event) -> None:
        self._scroll_units(int(-event.delta / 120) or (-1 if event.delta > 0 else 1))

    def scroll_to_top(self) -> None:
        self.canvas.yview_moveto(0)


# ==========================================================================
# Encrypt / Decrypt page
# ==========================================================================
class OperationPage(tk.Frame):
    """One page that works in 'encrypt' or 'decrypt' mode."""

    def __init__(self, master, app: "App", mode: str):
        super().__init__(master, bg=T.BG)
        assert mode in ("encrypt", "decrypt")
        self.app = app
        self.mode = mode
        self.path: Optional[Path] = None
        self.info: Optional[cm.EncryptedFileInfo] = None
        self.busy = False
        self._queue: Optional[queue.Queue] = None
        self._determinate = False
        self._last_output: Optional[Path] = None
        self.pw_var = tk.StringVar()
        self.confirm_var = tk.StringVar()
        self.password_visible = False
        self._build()
        self.pw_var.trace_add("write", lambda *_: self._update_state())
        self.confirm_var.trace_add("write", lambda *_: self._update_state())
        self._update_state()

    # ---- construction ----------------------------------------------------
    def _build(self) -> None:
        self.columnconfigure(0, weight=1, uniform="cols")
        self.columnconfigure(1, weight=1, uniform="cols")
        self._build_file_card().grid(row=0, column=0, sticky="nsew", padx=(0, dp(10)))
        self._build_password_card().grid(row=0, column=1, sticky="nsew", padx=(dp(10), 0))
        self._build_action_row().grid(row=1, column=0, columnspan=2, sticky="ew", pady=(dp(12), 0))
        self._build_status_card().grid(row=2, column=0, columnspan=2, sticky="ew", pady=(dp(10), 0))

    def _heading(self, parent, step: str, title: str) -> None:
        tk.Label(parent, text=step, font=font(8, "bold"), fg=T.BLUE, bg=T.CARD,
                 anchor="w").pack(fill="x")
        tk.Label(parent, text=title, font=font(14, "bold"), fg=T.TEXT, bg=T.CARD,
                 anchor="w").pack(fill="x", pady=(0, dp(8)))

    @staticmethod
    def _body(card: tk.Frame) -> tk.Frame:
        body = tk.Frame(card, bg=T.CARD)
        body.pack(fill="both", expand=True, padx=dp(20), pady=dp(14))
        return body

    def _build_file_card(self) -> tk.Frame:
        card = make_card(self)
        body = self._body(card)
        encrypt = self.mode == "encrypt"
        self._heading(body, "STEP 1", "Select the file to encrypt" if encrypt
                      else "Select the encrypted file")

        holder = tk.Frame(body, bg=T.CARD)
        holder.pack(fill="x")
        holder.columnconfigure(0, weight=1)

        # Empty state
        self.empty_box = tk.Frame(holder, bg=T.SOFT, highlightthickness=1,
                                  highlightbackground=T.BORDER)
        tk.Label(self.empty_box, text="No file selected", font=font(11, "bold"), fg=T.TEXT,
                 bg=T.SOFT).pack(pady=(dp(18), dp(2)))
        WrapLabel(self.empty_box, bg=T.SOFT, fg=T.MUTED, font=font(9), justify="center",
                  anchor="center",
                  text=("Click Browse (or press Ctrl+O) to choose any file: PDF, DOCX, TXT, "
                        "images, ZIP, CSV and more." if encrypt else
                        "Click Browse (or press Ctrl+O) to choose a .enc file that was "
                        "created by this application.")
                  ).pack(fill="x", padx=dp(14), pady=(0, dp(18)))
        self.empty_box.grid(row=0, column=0, sticky="ew")

        # Details state
        self.info_box = tk.Frame(holder, bg=T.CARD)
        self.info_box.columnconfigure(1, weight=1)
        rows = ([("name", "File name"), ("type", "Type"), ("size", "Size"), ("where", "Folder")]
                if encrypt else
                [("name", "Encrypted file"), ("original", "Restores as"), ("size", "Size"),
                 ("where", "Folder")])
        self.values: Dict[str, WrapLabel] = {}
        for i, (key, label) in enumerate(rows):
            tk.Label(self.info_box, text=label, font=font(9), fg=T.MUTED, bg=T.CARD,
                     anchor="nw").grid(row=i, column=0, sticky="nw", padx=(0, dp(14)), pady=dp(3))
            value = WrapLabel(self.info_box, text="", font=font(10, "bold" if key in ("name", "original") else "normal"),
                              fg=T.TEXT, bg=T.CARD)
            value.grid(row=i, column=1, sticky="ew", pady=dp(3))
            self.values[key] = value
        self.info_box.grid(row=0, column=0, sticky="ew")
        self.info_box.grid_remove()

        self.notice = WrapLabel(body, text="", font=font(9), fg=T.RED_DARK, bg=T.CARD)
        self.notice.pack(fill="x", pady=(dp(6), 0))

        FlatButton(body, "Browse\u2026", self.browse, kind="secondary", surface=T.CARD
                   ).pack(anchor="w", pady=(dp(10), 0))
        return card

    def _build_password_card(self) -> tk.Frame:
        card = make_card(self)
        body = self._body(card)
        encrypt = self.mode == "encrypt"
        self._heading(body, "STEP 2", "Choose a password" if encrypt else "Enter the password")

        tk.Label(body, text="Password", font=font(9, "bold"), fg=T.TEXT, bg=T.CARD,
                 anchor="w").pack(fill="x")
        row = tk.Frame(body, bg=T.CARD)
        row.pack(fill="x", pady=(dp(4), 0))
        self.pw_entry = ttk.Entry(row, textvariable=self.pw_var, show="\u2022",
                                  style="App.TEntry", font=font(11))
        self.pw_entry.pack(side="left", fill="x", expand=True)
        self.toggle_btn = FlatButton(row, "Show", self.toggle_password, kind="secondary",
                                     size=9, padx=12, pady=6)
        self.toggle_btn.pack(side="left", padx=(dp(8), 0))
        self.pw_entry.bind("<Return>", self._start)

        self.confirm_entry: Optional[ttk.Entry] = None
        self.checks: Dict[str, tk.Label] = {}
        if encrypt:
            tk.Label(body, text="Confirm password", font=font(9, "bold"), fg=T.TEXT, bg=T.CARD,
                     anchor="w").pack(fill="x", pady=(dp(8), 0))
            self.confirm_entry = ttk.Entry(body, textvariable=self.confirm_var, show="\u2022",
                                           style="App.TEntry", font=font(11))
            self.confirm_entry.pack(fill="x", pady=(dp(4), 0))
            self.confirm_entry.bind("<Return>", self._start)

            checklist = tk.Frame(body, bg=T.CARD)
            checklist.pack(fill="x", pady=(dp(8), 0))
            for key, text in (("min", f"At least {MIN_PASSWORD_LENGTH} characters (required)"),
                              ("rec", f"{RECOMMENDED_PASSWORD_LENGTH}+ characters (recommended)"),
                              ("match", "Both passwords match")):
                label = tk.Label(checklist, text="\u25cf  " + text, font=font(9), anchor="w",
                                 bg=T.CARD, fg=T.MUTED)
                label.pack(fill="x")
                self.checks[key] = label

        WrapLabel(body, font=font(9), fg=T.MUTED, bg=T.CARD,
                  text=("Tip: use a passphrase of several unrelated words. If you forget "
                        "the password, nobody can recover the file." if encrypt else
                        "Use the exact password that was set when the file was encrypted. "
                        "A wrong password never produces a recovered file.")
                  ).pack(fill="x", pady=(dp(8), 0))
        return card

    def _build_action_row(self) -> tk.Frame:
        row = tk.Frame(self, bg=T.BG)
        label = "Encrypt File" if self.mode == "encrypt" else "Decrypt File"
        self.action_btn = FlatButton(row, label, self._start, kind="primary", surface=T.BG,
                                     size=12, padx=34, pady=10)
        self.action_btn.pack(side="left")
        self.hint = WrapLabel(row, text="", font=font(9), fg=T.MUTED, bg=T.BG)
        self.hint.pack(side="left", fill="x", expand=True, padx=(dp(16), 0))
        return row

    def _build_status_card(self) -> tk.Frame:
        self.status_card = make_card(self)
        self.status_bar = tk.Frame(self.status_card, width=dp(5), bg=T.BORDER)
        self.status_bar.pack(side="left", fill="y")
        self.status_body = tk.Frame(self.status_card, bg=T.CARD)
        self.status_body.pack(side="left", fill="both", expand=True, padx=dp(18), pady=dp(10))
        self.status_head = tk.Frame(self.status_body, bg=T.CARD)
        self.status_head.pack(fill="x")
        self.status_actions = tk.Frame(self.status_head, bg=T.CARD)
        self.status_actions.pack(side="right")
        self.status_title = tk.Label(self.status_head, text="", font=font(11, "bold"),
                                     anchor="w", bg=T.CARD, fg=T.TEXT)
        self.status_title.pack(side="left", fill="x", expand=True)
        self.status_msg = WrapLabel(self.status_body, text="", font=font(10), bg=T.CARD, fg=T.MUTED)
        self.status_msg.pack(fill="x", pady=(dp(3), 0))
        self.progress = ttk.Progressbar(self.status_body, style="App.Horizontal.TProgressbar",
                                        mode="determinate", maximum=100)
        self.reset_status()
        return self.status_card

    # ---- status area -----------------------------------------------------
    def _paint_status(self, bar: str, tint: str, title_fg: str) -> None:
        self.status_bar.configure(bg=bar)
        for widget in (self.status_card, self.status_body, self.status_head, self.status_title,
                       self.status_msg, self.status_actions):
            widget.configure(bg=tint)
        self.status_title.configure(fg=title_fg)
        self.status_msg.configure(fg=T.TEXT if tint != T.CARD else T.MUTED)

    def _clear_actions(self) -> None:
        for child in self.status_actions.winfo_children():
            child.destroy()

    def reset_status(self) -> None:
        self.progress.stop()
        self.progress.pack_forget()
        self._clear_actions()
        self._paint_status(T.BORDER, T.CARD, T.TEXT)
        self.status_title.configure(text="Ready")
        self.status_msg.configure(text=(
            "Your original is never modified. The encrypted copy is saved next to it as .enc." if self.mode == "encrypt" else
            "The recovered file is saved as a new file. The .enc file is kept."))
        self.app.set_pill("Ready", "ready")

    def _show_working(self) -> None:
        self._clear_actions()
        self._paint_status(T.BLUE, T.BLUE_SOFT, T.BLUE_PRESSED)
        verb = "Encrypting" if self.mode == "encrypt" else "Decrypting"
        self.status_title.configure(text=f"{verb}\u2026")
        self.status_msg.configure(text="Deriving the key from your password. This takes a moment "
                                       "by design. Please do not close the window.")
        self._determinate = False
        self.progress.configure(mode="indeterminate", value=0)
        self.progress.pack(fill="x", pady=(dp(10), 0))
        self.progress.start(12)
        self.app.set_pill("Working\u2026", "working")

    def _show_success(self, output: Path) -> None:
        self.progress.stop()
        self.progress.pack_forget()
        self._clear_actions()
        self._paint_status(T.TEAL, T.TEAL_SOFT, T.TEAL_DARK)
        self._last_output = output
        if self.mode == "encrypt":
            self.status_title.configure(text="Encryption complete")
            self.status_msg.configure(text=f"Saved: {output}\nYour original file was not modified. "
                                           "Keep the password safe; it cannot be recovered.")
        else:
            self.status_title.configure(text="Decryption complete")
            self.status_msg.configure(text=f"Recovered file saved: {output}\n"
                                           "The encrypted file was kept unchanged.")
        FlatButton(self.status_actions, "Show in folder", self._show_in_folder, kind="secondary",
                   surface=T.TEAL_SOFT, size=9, padx=14, pady=4).pack()
        self.app.set_pill("Completed", "success")

    def _show_error(self, message: str) -> None:
        self.progress.stop()
        self.progress.pack_forget()
        self._clear_actions()
        self._paint_status(T.RED, T.RED_SOFT, T.RED_DARK)
        self.status_title.configure(
            text="Encryption failed" if self.mode == "encrypt" else "Decryption failed")
        self.status_msg.configure(text=message)
        self.app.set_pill("Failed", "error")

    def _show_in_folder(self) -> None:
        if not self._last_output:
            return
        try:
            if sys.platform == "win32":
                subprocess.Popen(["explorer", "/select,", os.path.normpath(str(self._last_output))])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", str(self._last_output)])
            else:
                subprocess.Popen(["xdg-open", str(self._last_output.parent)])
        except OSError:
            pass

    # ---- file selection --------------------------------------------------
    def browse(self) -> None:
        if self.busy:
            return
        parent = self.winfo_toplevel()
        if self.mode == "encrypt":
            chosen = filedialog.askopenfilename(parent=parent, title="Select a file to encrypt")
        else:
            chosen = filedialog.askopenfilename(
                parent=parent, title="Select an encrypted file",
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
        if chosen:
            self.set_file(Path(chosen))

    def set_file(self, path: Path) -> None:
        self.path, self.info = path, None
        self.reset_status()
        self.notice.configure(text="", fg=T.RED_DARK)
        try:
            size = path.stat().st_size
        except OSError as exc:
            self.path = None
            self._show_file_details(None)
            self.notice.configure(text=friendly_error(exc))
            self._update_state()
            return

        if self.mode == "encrypt":
            suffix = path.suffix.lstrip(".").upper()
            details = {"name": path.name,
                       "type": f"{suffix} file" if suffix else "File without extension",
                       "size": format_size(size), "where": shorten(str(path.parent))}
            if cm.looks_like_encrypted(path):
                self.notice.configure(
                    fg=T.MUTED,
                    text="Note: this file was already encrypted by this application. "
                         "You will be asked to confirm before encrypting it again.")
        else:
            details = {"name": path.name, "original": "\u2014", "size": format_size(size),
                       "where": shorten(str(path.parent))}
            try:
                self.info = cm.inspect_encrypted_file(path)
                details["original"] = self.info.original_name
            except cm.CryptoError as exc:
                self.notice.configure(text=str(exc))
                details["original"] = "Cannot be read"
            except OSError as exc:
                self.notice.configure(text=friendly_error(exc))
        self._show_file_details(details)
        self._update_state()

    def _show_file_details(self, details: Optional[Dict[str, str]]) -> None:
        if details is None:
            self.info_box.grid_remove()
            self.empty_box.grid()
            return
        for key, value in details.items():
            self.values[key].configure(text=value)
        self.empty_box.grid_remove()
        self.info_box.grid()

    # ---- password controls ----------------------------------------------
    def toggle_password(self) -> None:
        self.password_visible = not self.password_visible
        show = "" if self.password_visible else "\u2022"
        self.pw_entry.configure(show=show)
        if self.confirm_entry is not None:
            self.confirm_entry.configure(show=show)
        self.toggle_btn.set_text("Hide" if self.password_visible else "Show")

    def _blocking_reason(self) -> Optional[str]:
        if self.path is None:
            return "Select a file to continue."
        if self.mode == "decrypt" and self.info is None:
            return "Select a valid encrypted (.enc) file to continue."
        password = self.pw_var.get()
        if not password:
            return "Enter a password to continue."
        if self.mode == "encrypt":
            if len(password) < MIN_PASSWORD_LENGTH:
                return f"The password must have at least {MIN_PASSWORD_LENGTH} characters."
            if password != self.confirm_var.get():
                return "The two passwords do not match."
        return None

    def _update_state(self) -> None:
        reason = self._blocking_reason()
        ready = reason is None and not self.busy
        self.action_btn.set_enabled(ready)
        self.hint.configure(text="Working\u2026" if self.busy else
                            ("Ready. Press the button or Enter." if reason is None else reason))
        if self.mode == "encrypt":
            pw, confirm = self.pw_var.get(), self.confirm_var.get()
            states = {"min": len(pw) >= MIN_PASSWORD_LENGTH,
                      "rec": len(pw) >= RECOMMENDED_PASSWORD_LENGTH,
                      "match": bool(pw) and pw == confirm}
            for key, ok in states.items():
                self.checks[key].configure(fg=T.TEAL_DARK if ok else T.MUTED)

    def _set_inputs_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.pw_entry.configure(state=state)
        if self.confirm_entry is not None:
            self.confirm_entry.configure(state=state)

    # ---- running an operation -------------------------------------------
    def _resolve_output(self, proposed: Path) -> Optional[Tuple[Path, bool]]:
        """Return (path, overwrite_approved) or None if the user cancelled."""
        if not proposed.exists():
            return proposed, False
        alternative = cm.suggest_unique_path(proposed)
        answer = messagebox.askyesnocancel(
            "File already exists",
            f"\u201c{proposed.name}\u201d already exists in this folder.\n\n"
            f"Yes \u2013 save as \u201c{alternative.name}\u201d\n"
            "No \u2013 choose another name or location\n"
            "Cancel \u2013 stop\n\n"
            "Existing files are never overwritten unless you approve it.",
            icon="warning", parent=self.winfo_toplevel())
        if answer is None:
            return None
        if answer:
            return alternative, False
        chosen = filedialog.asksaveasfilename(
            parent=self.winfo_toplevel(), title="Choose where to save",
            initialdir=str(proposed.parent), initialfile=proposed.name,
            defaultextension=proposed.suffix, confirmoverwrite=True)
        if not chosen:
            return None
        chosen_path = Path(chosen)
        return chosen_path, chosen_path.exists()  # the save dialog already asked the user

    def _start(self, *_args) -> None:
        if self.busy or self._blocking_reason() is not None:
            return
        assert self.path is not None
        source, password = self.path, self.pw_var.get()
        parent = self.winfo_toplevel()

        if self.mode == "encrypt":
            allow_again = False
            if cm.looks_like_encrypted(source):
                if not messagebox.askyesno(
                        "Already encrypted",
                        "This file was already encrypted by this application.\n\n"
                        "Encrypting it again adds a second layer and is usually a mistake. "
                        "Continue anyway?", icon="warning", parent=parent):
                    return
                allow_again = True
            choice = self._resolve_output(cm.default_encrypted_path(source))
            if choice is None:
                return
            dest, overwrite = choice

            def job(progress):
                return cm.encrypt_file(source, password, dest, overwrite=overwrite,
                                       allow_reencrypt=allow_again, progress=progress)
        else:
            assert self.info is not None
            choice = self._resolve_output(cm.default_decrypted_path(source, self.info))
            if choice is None:
                return
            dest, overwrite = choice

            def job(progress):
                return cm.decrypt_file(source, password, dest, overwrite=overwrite,
                                       progress=progress)

        self._run_in_background(job)

    def _run_in_background(self, job: Callable[[cm.ProgressCallback], Path]) -> None:
        self.busy = True
        self.app.set_busy(True)
        self._set_inputs_enabled(False)
        self._update_state()
        self._show_working()
        results: "queue.Queue" = queue.Queue()
        self._queue = results

        def progress(done: int, total: int) -> None:
            results.put(("progress", done, total))

        def worker() -> None:
            try:
                results.put(("done", job(progress)))
            except BaseException as exc:  # reported to the GUI, never swallowed
                results.put(("error", exc))

        threading.Thread(target=worker, daemon=True).start()
        self.after(50, self._poll)

    def _poll(self) -> None:
        assert self._queue is not None
        finished = False
        while not finished:
            try:
                message = self._queue.get_nowait()
            except queue.Empty:
                break
            kind = message[0]
            if kind == "progress":
                self._on_progress(message[1], message[2])
            elif kind == "done":
                finished = True
                self._finish()
                self.pw_var.set("")          # do not keep the password around
                self.confirm_var.set("")
                self._show_success(message[1])
            elif kind == "error":
                finished = True
                self._finish()
                self._show_error(friendly_error(message[1]))
        if not finished:
            self.after(50, self._poll)

    def _on_progress(self, done: int, total: int) -> None:
        if not self._determinate:
            self._determinate = True
            self.progress.stop()
            self.progress.configure(mode="determinate")
        percent = 100 if total <= 0 else min(100, int(done * 100 / total))
        self.progress['value'] = percent
        verb = "Encrypting" if self.mode == "encrypt" else "Decrypting"
        self.status_title.configure(text=f"{verb}\u2026 {percent}%")
        self.status_msg.configure(text="Please do not close the window.")

    def _finish(self) -> None:
        self.busy = False
        self._queue = None
        self.app.set_busy(False)
        self._set_inputs_enabled(True)
        self._update_state()


# ==========================================================================
# About page
# ==========================================================================
class AboutPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=T.BG)
        params = cm.DEFAULT_KDF_PARAMS
        sections = [
            ("What this application does",
             [("", "Encrypts any file with a password and restores it later with the same "
                   "password. It works with PDF, DOCX, TXT, JPG, PNG, ZIP, CSV and any other "
                   "binary file. Your original file is never changed: an encrypted copy with a "
                   ".enc extension is created next to it.")]),
            ("How your files are protected",
             [("AES-256-GCM", "A standard encryption algorithm with a 256-bit key. GCM mode also "
                              "detects any modification of the data."),
              ("Scrypt", f"Turns your password into the key. It is deliberately slow and "
                         f"memory-hungry (N=2^{params.n_log2}, r={params.r}, p={params.p}) to make "
                         "password guessing expensive."),
              ("Random salt and nonce", "New random values are generated for every file, so the "
                                        "same file and password never produce the same output."),
              ("Authenticated header", "The stored filename and settings are covered by the "
                                       "authentication, so tampering is detected.")]),
            ("Know the limits",
             [("", "A forgotten password cannot be recovered. A weak password can be guessed "
                   "no matter how strong the algorithm is. The encrypted file still reveals "
                   "its approximate size and that it was made by this application. This is a "
                   "student project and has not been independently audited.")]),
        ]
        for index, (title, items) in enumerate(sections):
            card = make_card(self)
            card.pack(fill="x", pady=(0 if index == 0 else dp(14), 0))
            body = tk.Frame(card, bg=T.CARD)
            body.pack(fill="x", padx=dp(20), pady=dp(16))
            tk.Label(body, text=title, font=font(13, "bold"), fg=T.TEXT, bg=T.CARD,
                     anchor="w").pack(fill="x", pady=(0, dp(8)))
            for lead, text in items:
                row = tk.Frame(body, bg=T.CARD)
                row.pack(fill="x", pady=dp(3))
                if lead:
                    tk.Label(row, text=lead, font=font(10, "bold"), fg=T.BLUE_PRESSED, bg=T.CARD,
                             anchor="nw", width=20, justify="left").pack(side="left", anchor="n")
                WrapLabel(row, text=text, font=font(10), fg=T.TEXT, bg=T.CARD
                          ).pack(side="left", fill="x", expand=True)


# ==========================================================================
# Main window
# ==========================================================================
class App(tk.Tk):
    PAGES = {
        "encrypt": ("Encrypt a file", "Protect any file with a password. The original stays untouched."),
        "decrypt": ("Decrypt a file", "Restore a file that was encrypted with this application."),
        "about": ("About", "What this application does and how it protects your files."),
    }
    PILLS = {"ready": (T.BLUE_SOFT, T.BLUE_PRESSED), "working": (T.BLUE, "#FFFFFF"),
             "success": (T.TEAL_SOFT, T.TEAL_DARK), "error": (T.RED_SOFT, T.RED_DARK)}

    def __init__(self):
        super().__init__()
        global _scale, FONT_FAMILY
        _scale = max(1.0, self.winfo_fpixels("1i") / 96.0)
        families = set(tkfont.families(self))
        FONT_FAMILY = "Segoe UI" if "Segoe UI" in families else \
            tkfont.nametofont("TkDefaultFont").actual("family")

        self.title(APP_NAME)
        self.configure(bg=T.BG)
        self.busy = False
        self._current = ""
        self._configure_geometry()
        self._configure_styles()
        self._build_layout()

        self.pages: Dict[str, tk.Frame] = {
            "encrypt": OperationPage(self.scroll.inner, self, "encrypt"),
            "decrypt": OperationPage(self.scroll.inner, self, "decrypt"),
            "about": AboutPage(self.scroll.inner),
        }
        self.show_page("encrypt")
        self.bind("<Control-o>", self._on_ctrl_o)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---- window and style setup ----------------------------------------
    def _configure_geometry(self) -> None:
        screen_w, screen_h = self.winfo_screenwidth(), self.winfo_screenheight()
        # Leave room for the Windows taskbar and the title bar (matters on 1366x768).
        width = min(dp(1050), screen_w - 40)
        height = min(dp(700), screen_h - 130)
        x = max(0, (screen_w - width) // 2)
        y = max(0, (screen_h - height) // 2 - 20)
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.minsize(min(dp(860), width), min(dp(540), height))

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("App.TEntry", fieldbackground="#FFFFFF", foreground=T.TEXT,
                        bordercolor=T.BORDER, lightcolor=T.BORDER, darkcolor=T.BORDER,
                        insertcolor=T.TEXT, padding=(dp(8), dp(7)), borderwidth=1)
        style.map("App.TEntry",
                  bordercolor=[("focus", T.BLUE)], lightcolor=[("focus", T.BLUE)],
                  darkcolor=[("focus", T.BLUE)], fieldbackground=[("disabled", T.SOFT)],
                  foreground=[("disabled", T.MUTED)])
        style.configure("App.Horizontal.TProgressbar", troughcolor="#FFFFFF", background=T.BLUE,
                        bordercolor=T.BORDER, lightcolor=T.BLUE, darkcolor=T.BLUE,
                        thickness=dp(8))
        style.configure("App.Vertical.TScrollbar", troughcolor=T.BG, background=T.BORDER,
                        bordercolor=T.BG, lightcolor=T.BORDER, darkcolor=T.BORDER,
                        arrowcolor=T.MUTED, relief="flat", arrowsize=dp(14))
        style.map("App.Vertical.TScrollbar", background=[("active", T.NAVY_MUTED)])

    def _build_layout(self) -> None:
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # Sidebar -----------------------------------------------------------
        sidebar = tk.Frame(self, bg=T.NAVY, width=dp(232))
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)
        sidebar.pack_propagate(False)

        brand = tk.Frame(sidebar, bg=T.NAVY)
        brand.pack(fill="x", padx=dp(20), pady=(dp(26), dp(22)))
        logo = tk.Canvas(brand, width=dp(44), height=dp(44), bg=T.NAVY, highlightthickness=0)
        logo.pack(side="left")
        rounded_rect(logo, dp(2), dp(2), dp(42), dp(42), dp(11), fill=T.BLUE, outline="")
        logo.create_arc(dp(14), dp(8), dp(30), dp(28), start=0, extent=180, style="arc",
                        outline="#FFFFFF", width=dp(3))
        logo.create_rectangle(dp(11), dp(19), dp(33), dp(34), fill="#FFFFFF", outline="")
        logo.create_oval(dp(20), dp(24), dp(24), dp(28), fill=T.BLUE, outline="")
        titles = tk.Frame(brand, bg=T.NAVY)
        titles.pack(side="left", padx=(dp(12), 0))
        tk.Label(titles, text="Secure File", font=font(13, "bold"), fg="#FFFFFF", bg=T.NAVY,
                 anchor="w").pack(fill="x")
        tk.Label(titles, text="Encryption System", font=font(9), fg=T.NAVY_MUTED, bg=T.NAVY,
                 anchor="w").pack(fill="x")

        tk.Label(sidebar, text="MENU", font=font(8, "bold"), fg=T.NAVY_MUTED, bg=T.NAVY,
                 anchor="w").pack(fill="x", padx=dp(24), pady=(0, dp(6)))
        self.nav: Dict[str, NavItem] = {}
        for key, label in (("encrypt", "Encrypt"), ("decrypt", "Decrypt"), ("about", "About")):
            item = NavItem(sidebar, label, lambda k=key: self.show_page(k))
            item.pack(fill="x", padx=(0, 0), pady=1)
            self.nav[key] = item

        tk.Label(sidebar, text="Files are processed locally\non this computer.\nNothing is uploaded.",
                 font=font(9), fg=T.NAVY_MUTED, bg=T.NAVY, justify="left", anchor="w"
                 ).pack(side="bottom", fill="x", padx=dp(24), pady=dp(22))

        # Main column ---------------------------------------------------------
        main = tk.Frame(self, bg=T.BG)
        main.grid(row=0, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=1)

        header = tk.Frame(main, bg=T.CARD)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        text_box = tk.Frame(header, bg=T.CARD)
        text_box.grid(row=0, column=0, sticky="ew", padx=dp(28), pady=dp(12))
        self.title_label = tk.Label(text_box, font=font(19, "bold"), fg=T.TEXT, bg=T.CARD, anchor="w")
        self.title_label.pack(fill="x")
        self.desc_label = WrapLabel(text_box, font=font(10), fg=T.MUTED, bg=T.CARD)
        self.desc_label.pack(fill="x", pady=(dp(2), 0))
        self.pill = tk.Label(header, text="Ready", font=font(9, "bold"), padx=dp(14), pady=dp(5))
        self.pill.grid(row=0, column=1, padx=(0, dp(28)))
        self.set_pill("Ready", "ready")
        tk.Frame(header, height=1, bg=T.BORDER).grid(row=1, column=0, columnspan=2, sticky="ew")

        self.scroll = ScrollableFrame(main, T.BG)
        self.scroll.grid(row=1, column=0, sticky="nsew")

        footer = tk.Frame(main, bg=T.BG)
        footer.grid(row=2, column=0, sticky="ew")
        tk.Frame(footer, height=1, bg=T.BORDER).pack(fill="x")
        tk.Label(footer, text=f"{APP_NAME}   \u00b7   {APP_STANDARD}", font=font(8), fg=T.MUTED,
                 bg=T.BG).pack(pady=dp(7))

    # ---- behaviour -----------------------------------------------------------
    def set_pill(self, text: str, kind: str) -> None:
        bg, fg = self.PILLS[kind]
        self.pill.configure(text=text, bg=bg, fg=fg)

    def set_busy(self, busy: bool) -> None:
        self.busy = busy

    def show_page(self, key: str) -> None:
        if self.busy or key == self._current:
            return
        if self._current:
            self.pages[self._current].pack_forget()
        self._current = key
        page = self.pages[key]
        page.pack(fill="x", padx=dp(28), pady=(dp(16), dp(4)), anchor="n")
        title, description = self.PAGES[key]
        self.title_label.configure(text=title)
        self.desc_label.configure(text=description)
        for name, item in self.nav.items():
            item.set_active(name == key)
        if key == "about":
            self.pill.grid_remove()
        else:
            self.pill.grid()
            self.pill.configure(text="Ready")
            self.set_pill("Ready", "ready")
        self.scroll.scroll_to_top()

    def _on_ctrl_o(self, _event) -> None:
        page = self.pages.get(self._current)
        if isinstance(page, OperationPage):
            page.browse()

    def _on_close(self) -> None:
        if self.busy:
            messagebox.showinfo("Operation in progress",
                                "Please wait until the current operation has finished.",
                                parent=self)
            return
        self.destroy()


def main() -> None:
    enable_high_dpi()
    App().mainloop()


if __name__ == "__main__":
    main()
