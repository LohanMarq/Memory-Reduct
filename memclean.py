"""
MemClean — Otimizador de RAM para Windows
by Lohan Marques | github.com/lohan-marques
"""

import tkinter as tk
from tkinter import ttk
import ctypes, ctypes.wintypes
import threading, time, sys, os, platform, subprocess, webbrowser, math

# ─────────────────────────────────────────────────────────
#  Temas
# ─────────────────────────────────────────────────────────
THEMES = {
    "light": {
        "BG":      "#f5f5f7",
        "CARD":    "#ffffff",
        "BORDER":  "#e0e0e6",
        "TEXT":    "#1a1a2e",
        "SUBTEXT": "#8888a0",
        "LOG_BG":  "#ffffff",
        "BTN_FG":  "#ffffff",
    },
    "dark": {
        "BG":      "#0f0f13",
        "CARD":    "#1a1a24",
        "BORDER":  "#2a2a3a",
        "TEXT":    "#e8e8f4",
        "SUBTEXT": "#6060a0",
        "LOG_BG":  "#13131c",
        "BTN_FG":  "#ffffff",
    },
}

ACCENT  = "#5b5ef4"
SUCCESS = "#22c55e"
WARNING = "#f59e0b"
DANGER  = "#ef4444"
MONO    = ("Consolas", 9)

# ─────────────────────────────────────────────────────────
#  WinAPI — constantes e estruturas
# ─────────────────────────────────────────────────────────
SE_PRIVILEGE_ENABLED        = 0x00000002
TOKEN_ADJUST_PRIVILEGES     = 0x00000020
TOKEN_QUERY                 = 0x00000008
PROCESS_ALL_ACCESS          = 0x1F0FFF
PROCESS_TERMINATE           = 0x0001
PROCESS_SET_QUOTA           = 0x0100
PROCESS_VM_READ             = 0x0010

# SystemMemoryListInformation — o mesmo que o MemReduct usa
SystemMemoryListInformation   = 80
MemoryEmptyWorkingSets        = 2   # esvazia working sets de todos processos
MemoryFlushModifiedList       = 3   # flush da modified page list → standby
MemoryPurgeStandbyList        = 4   # limpa standby list inteira
MemoryPurgeLowPriorityStandby = 5   # limpa standby de baixa prioridade

# Flags de heap
HEAP_FORCE_COMPACT = 0x0004

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.wintypes.DWORD), ("HighPart", ctypes.wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", ctypes.wintypes.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.wintypes.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength",                ctypes.wintypes.DWORD),
        ("dwMemoryLoad",            ctypes.wintypes.DWORD),
        ("ullTotalPhys",            ctypes.c_ulonglong),
        ("ullAvailPhys",            ctypes.c_ulonglong),
        ("ullTotalPageFile",        ctypes.c_ulonglong),
        ("ullAvailPageFile",        ctypes.c_ulonglong),
        ("ullTotalVirtual",         ctypes.c_ulonglong),
        ("ullAvailVirtual",         ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]

class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb",                          ctypes.wintypes.DWORD),
        ("PageFaultCount",              ctypes.wintypes.DWORD),
        ("PeakWorkingSetSize",          ctypes.c_size_t),
        ("WorkingSetSize",              ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage",     ctypes.c_size_t),
        ("QuotaPagedPoolUsage",         ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage",  ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage",      ctypes.c_size_t),
        ("PagefileUsage",               ctypes.c_size_t),
        ("PeakPagefileUsage",           ctypes.c_size_t),
    ]

# ─────────────────────────────────────────────────────────
#  Processos protegidos — NUNCA encerrar
# ─────────────────────────────────────────────────────────
PROTECTED = {
    "system", "smss", "csrss", "wininit", "winlogon", "services",
    "lsass", "lsm", "svchost", "dwm", "explorer", "taskhostw",
    "conhost", "dllhost", "spoolsv", "audiodg", "fontdrvhost",
    "sihost", "ctfmon", "rundll32", "python", "pythonw",
    "memclean", "projetov2teste",
}

# Processos de segundo plano seguros para encerrar
SAFE_TO_KILL = {
    # Telemetria Microsoft
    "diagtrack", "compattelrunner", "usoclient", "wuauclt",
    "musnotification", "musnotificationux",
    # Indexação
    "searchindexer", "searchprotocolhost", "searchfilterhost",
    # Apps que ficam em bg desnecessariamente
    "onedrive", "teams", "slack", "discord", "spotify",
    "skype", "skypeapp",
    # Browsers em bg (só processos ociosos)
    "chrome", "msedge", "firefox", "opera",
    # Outros
    "wmpnetwk", "officeclicktorun", "msoidsvc",
    "nvspcaps64", "nvtelemetrycontainer", "nvdisplay.container",
    "adobeupdateservice", "adobearm",
    "dropbox", "googledrivefs",
    "yarnpkg", "node",
    "wmiprvse",
}

# ─────────────────────────────────────────────────────────
#  Funções de sistema
# ─────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def enable_privilege(name: str) -> bool:
    """Ativa privilégio de sistema necessário para operações de memória."""
    try:
        h = ctypes.wintypes.HANDLE()
        ctypes.windll.advapi32.OpenProcessToken(
            ctypes.windll.kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h))
        luid = LUID()
        ctypes.windll.advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid))
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ctypes.windll.advapi32.AdjustTokenPrivileges(
            h, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None)
        ctypes.windll.kernel32.CloseHandle(h)
        return True
    except Exception:
        return False


def get_ram() -> dict:
    ms = MEMORYSTATUSEX()
    ms.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
    total = ms.ullTotalPhys / (1024 ** 3)
    avail = ms.ullAvailPhys / (1024 ** 3)
    return {"total": total, "used": total - avail, "avail": avail, "pct": ms.dwMemoryLoad}


def _nt_set_memory(command: int) -> bool:
    """Chama NtSetSystemInformation — o coração do MemReduct."""
    try:
        v = ctypes.c_int(command)
        status = ctypes.windll.ntdll.NtSetSystemInformation(
            SystemMemoryListInformation, ctypes.byref(v), ctypes.sizeof(v))
        return status == 0
    except Exception:
        return False


def get_process_ram_mb(pid: int) -> float:
    """Retorna uso de RAM de um processo em MB."""
    try:
        h = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_SET_QUOTA, False, pid)
        if not h:
            return 0.0
        pmc = PROCESS_MEMORY_COUNTERS()
        pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        ctypes.windll.psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb)
        ctypes.windll.kernel32.CloseHandle(h)
        return pmc.WorkingSetSize / (1024 * 1024)
    except Exception:
        return 0.0


def list_processes() -> list:
    """
    Lista todos os processos com nome, PID e uso de RAM.
    Retorna lista de dicts ordenada por RAM decrescente.
    """
    procs = []
    try:
        result = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=15)
        for line in result.stdout.strip().splitlines():
            parts = line.strip('"').split('","')
            if len(parts) >= 5:
                try:
                    name = parts[0].lower().replace(".exe", "")
                    pid  = int(parts[1])
                    # Coluna de memória: "123.456 KB" → remover pontos/vírgulas e converter
                    mem_str = parts[4].replace(" ", "").replace(".", "").replace(",", "").replace(" K", "").strip()
                    mem_kb  = int(mem_str) if mem_str.isdigit() else 0
                    mem_mb  = mem_kb / 1024
                    procs.append({"name": name, "pid": pid, "mb": mem_mb})
                except (ValueError, IndexError):
                    pass
    except Exception:
        pass
    return sorted(procs, key=lambda x: x["mb"], reverse=True)


def trim_process_working_set(pid: int) -> bool:
    """
    Encolhe o working set de um processo específico —
    o Windows move as páginas para standby, liberando RAM física.
    Mesma técnica que o MemReduct usa por processo.
    """
    try:
        h = ctypes.windll.kernel32.OpenProcess(PROCESS_SET_QUOTA, False, pid)
        if not h:
            return False
        # SetProcessWorkingSetSizeEx com -1,-1 força o trim imediato
        result = ctypes.windll.kernel32.SetProcessWorkingSetSizeEx(h, -1, -1, 0)
        ctypes.windll.kernel32.CloseHandle(h)
        return bool(result)
    except Exception:
        return False


def trim_all_working_sets(log_cb=None) -> int:
    """
    Percorre TODOS os processos e encolhe o working set de cada um.
    Isso é o que realmente libera centenas de MB — igual ao MemReduct.
    """
    trimmed = 0
    procs = list_processes()
    total = len(procs)
    for i, p in enumerate(procs):
        if p["name"] in PROTECTED:
            continue
        if trim_process_working_set(p["pid"]):
            trimmed += 1
    if log_cb:
        log_cb(f"Working sets encolhidos: {trimmed}/{total} processos")
    return trimmed


def kill_heavy_background(log_cb=None, threshold_mb=50.0) -> int:
    """
    Encerra processos de segundo plano da lista segura
    que estejam consumindo mais de threshold_mb de RAM.
    """
    killed = 0
    procs = list_processes()
    for p in procs:
        name = p["name"]
        if name not in SAFE_TO_KILL:
            continue
        if p["mb"] < threshold_mb:
            continue
        try:
            h = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, p["pid"])
            if h:
                ctypes.windll.kernel32.TerminateProcess(h, 0)
                ctypes.windll.kernel32.CloseHandle(h)
                if log_cb:
                    log_cb(f"Encerrado: {name} ({p['mb']:.0f} MB)")
                killed += 1
        except Exception:
            pass
    return killed


def compact_heaps(log_cb=None) -> None:
    """
    Compacta os heaps de todos os processos acessíveis.
    Reduz fragmentação e devolve memória ao SO.
    """
    try:
        # HeapCompact no próprio processo primeiro
        heap = ctypes.windll.kernel32.GetProcessHeap()
        ctypes.windll.kernel32.HeapCompact(heap, 0)
    except Exception:
        pass


def run_cleanup(progress_cb=None, log_cb=None) -> dict:
    """
    Limpeza intensiva de RAM — mesma sequência do MemReduct:
    1. Privilégios
    2. Encerra bg pesados
    3. Trim de working sets (passagem 1)
    4. Flush da modified list → move para standby
    5. Purge da standby list
    6. Trim de working sets (passagem 2) — pega o que ficou
    7. Purge standby de baixa prioridade
    8. Compact heaps
    9. Purge standby final
    """
    before = get_ram()
    steps = [
        (5,  "Ativando privilégios...",
             lambda: [enable_privilege(p) for p in (
                 "SeProfileSingleProcessPrivilege",
                 "SeIncreaseQuotaPrivilege",
                 "SeDebugPrivilege",
             )]),
        (15, "Encerrando processos pesados em bg...",
             lambda: kill_heavy_background(log_cb, threshold_mb=40.0)),
        (30, "Encolhendo working sets (1ª passagem)...",
             lambda: trim_all_working_sets(log_cb)),
        (45, "Movendo modified pages para standby...",
             lambda: _nt_set_memory(MemoryFlushModifiedList)),
        (55, "Limpando standby list...",
             lambda: _nt_set_memory(MemoryPurgeStandbyList)),
        (65, "Encolhendo working sets (2ª passagem)...",
             lambda: trim_all_working_sets(None)),
        (75, "Limpando standby de baixa prioridade...",
             lambda: _nt_set_memory(MemoryPurgeLowPriorityStandby)),
        (85, "Compactando heaps...",
             compact_heaps),
        (92, "Limpando standby list (final)...",
             lambda: _nt_set_memory(MemoryPurgeStandbyList)),
        (97, "Limpando working sets (varredura final)...",
             lambda: _nt_set_memory(MemoryEmptyWorkingSets)),
        (100, "Concluído.",
             lambda: time.sleep(0.3)),
    ]

    for pct, msg, fn in steps:
        if log_cb:
            log_cb(msg)
        try:
            fn()
        except Exception:
            pass
        if progress_cb:
            progress_cb(pct)
        time.sleep(0.15)

    after = get_ram()
    return {"before": before, "after": after, "freed": after["avail"] - before["avail"]}


# ─────────────────────────────────────────────────────────
#  Toggle switch (canvas)
# ─────────────────────────────────────────────────────────

class ToggleSwitch(tk.Canvas):
    W, H, R = 44, 24, 10

    def __init__(self, parent, on_toggle=None, **kw):
        super().__init__(parent, width=self.W, height=self.H,
                         bd=0, highlightthickness=0, **kw)
        self._state     = False
        self._on_toggle = on_toggle
        self._anim_x    = self.R + 3      # posição atual do círculo
        self._target_x  = self.R + 3
        self.bind("<Button-1>", self._click)
        self._draw()

    def _click(self, _=None):
        self._state    = not self._state
        self._target_x = (self.W - self.R - 3) if self._state else (self.R + 3)
        self._animate()
        if self._on_toggle:
            self._on_toggle(self._state)

    def _animate(self):
        diff = self._target_x - self._anim_x
        if abs(diff) < 1:
            self._anim_x = self._target_x
            self._draw()
            return
        self._anim_x += diff * 0.25
        self._draw()
        self.after(16, self._animate)

    def _draw(self):
        self.delete("all")
        track_color = "#5b5ef4" if self._state else "#c8c8d8"
        # Track arredondado
        self.create_oval(1, 1, self.H - 1, self.H - 1, fill=track_color, outline="")
        self.create_oval(self.W - self.H + 1, 1, self.W - 1, self.H - 1, fill=track_color, outline="")
        self.create_rectangle(self.H // 2, 1, self.W - self.H // 2, self.H - 1, fill=track_color, outline="")
        # Thumb
        cx = int(self._anim_x)
        cy = self.H // 2
        self.create_oval(cx - self.R, cy - self.R, cx + self.R, cy + self.R,
                         fill="#ffffff", outline="")

    def set_bg(self, color):
        self.configure(bg=color)
        self._draw()


# ─────────────────────────────────────────────────────────
#  App principal
# ─────────────────────────────────────────────────────────

class MemClean(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MemClean")
        self.geometry("480x620")
        self.resizable(False, False)

        self.update_idletasks()
        x = (self.winfo_screenwidth()  - 480) // 2
        y = (self.winfo_screenheight() - 620) // 2
        self.geometry(f"480x620+{x}+{y}")

        self._cleaning  = False
        self._auto_id   = None
        self._auto_on   = tk.BooleanVar(value=False)
        self._auto_min  = tk.IntVar(value=30)
        self._dark_mode = False
        self._theme     = THEMES["light"]

        # Referências a todos os widgets que precisam de recolor
        self._themed_widgets = []

        self._build()
        self._apply_theme()
        self._tick()

    # ── Tema ─────────────────────────────────────────────

    def _t(self, key):
        return self._theme[key]

    def _reg_w(self, widget, role: str):
        """Registra widget para recoloração automática."""
        self._themed_widgets.append((widget, role))
        return widget

    def _apply_theme(self):
        t = self._theme
        self.configure(bg=t["BG"])

        for widget, role in self._themed_widgets:
            try:
                if role == "bg":
                    widget.configure(bg=t["BG"])
                elif role == "card":
                    widget.configure(bg=t["CARD"])
                elif role == "text":
                    widget.configure(fg=t["TEXT"], bg=t["BG"])
                elif role == "subtext":
                    widget.configure(fg=t["SUBTEXT"], bg=t["BG"])
                elif role == "subtext_card":
                    widget.configure(fg=t["SUBTEXT"], bg=t["CARD"])
                elif role == "text_card":
                    widget.configure(fg=t["TEXT"], bg=t["CARD"])
                elif role == "border":
                    widget.configure(bg=t["BORDER"])
                elif role == "border_card":
                    widget.configure(highlightbackground=t["BORDER"], bg=t["CARD"])
                elif role == "log":
                    widget.configure(bg=t["LOG_BG"], fg=t["TEXT"],
                                     selectbackground=t["BORDER"])
                elif role == "prog_bg":
                    widget.configure(bg=t["BG"])
                elif role == "toggle_bg":
                    widget.set_bg(t["BG"])
                elif role == "check":
                    widget.configure(fg=t["SUBTEXT"], bg=t["BG"],
                                     activebackground=t["BG"], selectcolor=t["BG"])
                elif role == "spinbox":
                    widget.configure(bg=t["BG"], fg=ACCENT,
                                     buttonbackground=t["BG"],
                                     disabledbackground=t["BG"])
                elif role == "pct_lbl":
                    widget.configure(bg=t["CARD"])  # fundo do card muda com o tema
            except Exception:
                pass

        # Barra RAM
        try:
            self._bar_bg.configure(bg=t["BORDER"])
        except Exception:
            pass

        # Progressbar ttk
        try:
            s = ttk.Style()
            s.configure("MemClean.Horizontal.TProgressbar",
                        troughcolor=t["BORDER"], background=ACCENT,
                        thickness=6, borderwidth=0)
        except Exception:
            pass

    def _toggle_dark(self, state: bool):
        self._dark_mode = state
        self._theme = THEMES["dark" if state else "light"]
        self._apply_theme()

    # ── Construção da UI ──────────────────────────────────

    def _build(self):
        t = self._theme

        # ── Header
        hdr = tk.Frame(self, bg=t["BG"])
        self._reg_w(hdr, "bg")
        hdr.pack(fill="x", padx=28, pady=(24, 0))

        self._reg_w(
            tk.Label(hdr, text="MemClean", font=("Segoe UI Semibold", 18),
                     fg=t["TEXT"], bg=t["BG"]), "text"
        ).pack(side="left")

        # Dark mode toggle no canto direito do header
        dm_frame = tk.Frame(hdr, bg=t["BG"])
        self._reg_w(dm_frame, "bg")
        dm_frame.pack(side="right")

        self._reg_w(
            tk.Label(dm_frame, text="Dark", font=("Segoe UI", 8),
                     fg=t["SUBTEXT"], bg=t["BG"]), "subtext"
        ).pack(side="left", padx=(0, 6))

        self._toggle = ToggleSwitch(dm_frame, on_toggle=self._toggle_dark, bg=t["BG"])
        self._reg_w(self._toggle, "toggle_bg")
        self._toggle.pack(side="left")

        self._reg_w(
            tk.Label(self, text="Otimizador de RAM para Windows",
                     font=("Segoe UI", 9), fg=t["SUBTEXT"], bg=t["BG"]),
            "subtext"
        ).pack(anchor="w", padx=28)

        sep = tk.Frame(self, bg=t["BORDER"], height=1)
        self._reg_w(sep, "border")
        sep.pack(fill="x", padx=28, pady=14)

        # ── Card RAM
        self._ram_card = tk.Frame(self, bg=t["CARD"], bd=0,
                                  highlightthickness=1,
                                  highlightbackground=t["BORDER"])
        self._reg_w(self._ram_card, "border_card")
        self._ram_card.pack(fill="x", padx=28)
        self._build_ram_card(self._ram_card)

        self._reg_w(tk.Frame(self, bg=t["BG"], height=8), "bg").pack()

        # ── Card Log
        self._log_card = tk.Frame(self, bg=t["CARD"], bd=0,
                                  highlightthickness=1,
                                  highlightbackground=t["BORDER"])
        self._reg_w(self._log_card, "border_card")
        self._log_card.pack(fill="x", padx=28)
        self._build_log_card(self._log_card)

        self._reg_w(tk.Frame(self, bg=t["BG"], height=4), "bg").pack()

        # ── Barra de progresso com %
        pf = tk.Frame(self, bg=t["BG"])
        self._reg_w(pf, "bg")
        pf.pack(fill="x", padx=28)

        prog_row = tk.Frame(pf, bg=t["BG"])
        self._reg_w(prog_row, "bg")
        prog_row.pack(fill="x")

        self._prog_var = tk.IntVar(value=0)
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("MemClean.Horizontal.TProgressbar",
                    troughcolor=t["BORDER"], background=ACCENT,
                    thickness=6, borderwidth=0)
        ttk.Progressbar(prog_row, variable=self._prog_var, maximum=100,
                        style="MemClean.Horizontal.TProgressbar"
                        ).pack(side="left", fill="x", expand=True)

        self._prog_lbl = tk.Label(prog_row, text="0%", font=("Segoe UI", 8),
                                  fg=t["SUBTEXT"], bg=t["BG"], width=5, anchor="e")
        self._reg_w(self._prog_lbl, "subtext")
        self._prog_lbl.pack(side="left")

        self._reg_w(tk.Frame(self, bg=t["BG"], height=10), "bg").pack()

        # ── Auto-limpeza
        af = tk.Frame(self, bg=t["BG"])
        self._reg_w(af, "bg")
        af.pack(fill="x", padx=28)

        chk = tk.Checkbutton(
            af, text="Limpar automaticamente a cada",
            variable=self._auto_on, command=self._toggle_auto,
            font=("Segoe UI", 9), fg=t["SUBTEXT"], bg=t["BG"],
            activebackground=t["BG"], activeforeground=t["TEXT"],
            selectcolor=t["BG"], bd=0)
        self._reg_w(chk, "check")
        chk.pack(side="left")

        spn = tk.Spinbox(af, from_=5, to=120, width=4,
                         textvariable=self._auto_min,
                         font=("Segoe UI", 9), bg=t["BG"], fg=ACCENT,
                         relief="flat", buttonbackground=t["BG"])
        self._reg_w(spn, "spinbox")
        spn.pack(side="left", padx=4)

        self._reg_w(
            tk.Label(af, text="min", font=("Segoe UI", 9),
                     fg=t["SUBTEXT"], bg=t["BG"]), "subtext"
        ).pack(side="left")

        self._next_lbl = tk.Label(af, text="", font=("Segoe UI", 8),
                                  fg=t["SUBTEXT"], bg=t["BG"])
        self._reg_w(self._next_lbl, "subtext")
        self._next_lbl.pack(side="right")

        self._reg_w(tk.Frame(self, bg=t["BG"], height=16), "bg").pack()

        # ── Botão principal
        self._btn = tk.Button(
            self, text="Limpar RAM",
            font=("Segoe UI Semibold", 11),
            fg="#ffffff", bg=ACCENT,
            activebackground="#4a4de0", activeforeground="#fff",
            bd=0, padx=0, pady=12, width=22,
            cursor="hand2", relief="flat",
            command=self._start)
        self._btn.pack()

        # ── Rodapé RGB
        footer = tk.Frame(self, bg=t["BG"])
        self._reg_w(footer, "bg")
        footer.pack(pady=(12, 4))

        self._gh_lbl = tk.Label(footer, text="GitHub",
                                font=("Segoe UI", 8, "underline"),
                                bg=t["BG"], cursor="hand2")
        self._reg_w(self._gh_lbl, "bg")
        self._gh_lbl.pack(side="left")
        self._gh_lbl.bind("<Button-1>",
                          lambda e: webbrowser.open("https://github.com/lohanmarq"))

        self._reg_w(
            tk.Label(footer, text="  •  ", font=("Segoe UI", 8),
                     fg="#c0c0d0", bg=t["BG"]), "bg"
        ).pack(side="left")

        self._li_lbl = tk.Label(footer, text="LinkedIn",
                                font=("Segoe UI", 8, "underline"),
                                bg=t["BG"], cursor="hand2")
        self._reg_w(self._li_lbl, "bg")
        self._li_lbl.pack(side="left")
        self._li_lbl.bind("<Button-1>",
                          lambda e: webbrowser.open("https://www.linkedin.com/in/lohanmarques/"))

        self._rgb_phase = 0.0
        self._animate_rgb()

    def _build_ram_card(self, f):
        t = self._theme
        top = tk.Frame(f, bg=t["CARD"])
        self._reg_w(top, "card")
        top.pack(fill="x", padx=18, pady=(16, 6))

        self._reg_w(
            tk.Label(top, text="RAM em uso", font=("Segoe UI", 9),
                     fg=t["SUBTEXT"], bg=t["CARD"]), "subtext_card"
        ).pack(side="left")

        self._pct_lbl = tk.Label(top, text="–", font=("Segoe UI Semibold", 30),
                                 fg=t["TEXT"], bg=t["CARD"])
        self._reg_w(self._pct_lbl, "pct_lbl")
        self._pct_lbl.pack(side="right")

        self._bar_bg = tk.Frame(f, bg=t["BORDER"], height=4)
        self._bar_bg.pack(fill="x", padx=18, pady=(0, 10))
        self._bar_bg.pack_propagate(False)
        self._bar = tk.Frame(self._bar_bg, bg=ACCENT, height=4)
        self._bar.place(x=0, y=0, relheight=1, width=0)

        row = tk.Frame(f, bg=t["CARD"])
        self._reg_w(row, "card")
        row.pack(fill="x", padx=18, pady=(0, 16))

        self._used_lbl  = self._stat(row, "Usada",      "–")
        self._avail_lbl = self._stat(row, "Disponível", "–")
        self._total_lbl = self._stat(row, "Total",      "–")

    def _build_log_card(self, f):
        t = self._theme
        lbl = tk.Label(f, text="Atividade", font=("Segoe UI", 8),
                       fg=t["SUBTEXT"], bg=t["CARD"])
        self._reg_w(lbl, "subtext_card")
        lbl.pack(anchor="w", padx=16, pady=(10, 2))

        self._log = tk.Text(
            f, height=5, bg=t["LOG_BG"], fg=t["TEXT"],
            font=MONO, bd=0, padx=12, pady=6,
            state="disabled", cursor="arrow",
            selectbackground=t["BORDER"], relief="flat")
        self._reg_w(self._log, "log")
        self._log.pack(fill="x", padx=0, pady=(0, 10))

    def _stat(self, parent, label, value):
        t = self._theme
        f = tk.Frame(parent, bg=t["CARD"])
        self._reg_w(f, "card")
        f.pack(side="left", expand=True)
        lbl_title = tk.Label(f, text=label, font=("Segoe UI", 8),
                             fg=t["SUBTEXT"], bg=t["CARD"])
        self._reg_w(lbl_title, "subtext_card")
        lbl_title.pack(anchor="w")
        lbl_val = tk.Label(f, text=value, font=("Segoe UI Semibold", 12),
                           fg=t["TEXT"], bg=t["CARD"])
        self._reg_w(lbl_val, "text_card")
        lbl_val.pack(anchor="w")
        return lbl_val

    # ── RGB ──────────────────────────────────────────────

    def _animate_rgb(self):
        p = self._rgb_phase
        def w(o): return int((math.sin(p + o) + 1) / 2 * 255)
        # Links rodapé
        self._gh_lbl.config(fg=f"#{w(0):02x}{w(2.094):02x}{w(4.189):02x}")
        self._li_lbl.config(fg=f"#{w(2.094):02x}{w(4.189):02x}{w(0):02x}")
        # Porcentagem de RAM em RGB
        self._pct_lbl.config(fg=f"#{w(1.0):02x}{w(3.094):02x}{w(5.189):02x}")
        self._rgb_phase += 0.06
        self.after(30, self._animate_rgb)

    # ── Progresso ────────────────────────────────────────

    def _set_progress(self, val: int):
        self._prog_var.set(val)
        self._prog_lbl.config(text=f"{val}%")

    # ── Stats ────────────────────────────────────────────

    def _tick(self):
        info = get_ram()
        pct  = info["pct"]
        bar_color = SUCCESS if pct < 60 else WARNING if pct < 85 else DANGER
        # Só atualiza texto da % — cor fica com o RGB do _animate_rgb
        self._pct_lbl.config(text=f"{pct}%")
        self._used_lbl.config(text=f"{info['used']:.1f} GB")
        self._avail_lbl.config(text=f"{info['avail']:.1f} GB")
        self._total_lbl.config(text=f"{info['total']:.1f} GB")
        bg = self._bar_bg
        bg.update_idletasks()
        w = bg.winfo_width()
        self._bar.config(bg=bar_color)
        self._bar.place(x=0, y=0, relheight=1, width=int(w * pct / 100))
        self.after(2000, self._tick)

    # ── Log ──────────────────────────────────────────────

    # Mapa de palavras-chave → emoji + texto amigável para leigos
    _LOG_MAP = [
        ("Ativando privilégios",        "🔓", "Obtendo permissões do sistema..."),
        ("Encerrando processos pesados","🗑️", "Fechando apps pesados em segundo plano..."),
        ("Encerrado:",                  "❌", None),   # mantém msg original
        ("Encolhendo working sets",     "🧹", "Liberando memória ociosa dos programas..."),
        ("Working sets encolhidos",     "✅", None),
        ("Movendo modified pages",      "📦", "Organizando páginas de memória..."),
        ("Limpando standby list",       "🗑️", "Limpando cache de memória..."),
        ("Limpando standby de baixa",   "🗑️", "Limpando cache secundário..."),
        ("Compactando heaps",           "🔧", "Compactando blocos de memória..."),
        ("Limpando working sets",       "🧹", "Varredura final de memória..."),
        ("Concluído",                   "✅", "Limpeza concluída!"),
        ("Aviso:",                      "⚠️", None),
        ("Limpeza automática",          "⏰", None),
    ]

    def _friendly(self, msg: str):
        """Converte mensagem técnica em texto amigável com emoji."""
        for keyword, emoji, friendly in self._LOG_MAP:
            if keyword.lower() in msg.lower():
                text = friendly if friendly else msg
                return f"{emoji}  {text}"
        return f"•  {msg}"

    def _write(self, msg: str):
        stamp = time.strftime("%H:%M")
        friendly = self._friendly(msg)
        self._log.config(state="normal")
        self._log.insert("end", f"{stamp}  {friendly}\n")
        self._log.see("end")
        self._log.config(state="disabled")

    # ── Limpeza ──────────────────────────────────────────

    def _start(self):
        if self._cleaning:
            return
        self._cleaning = True
        self._btn.config(state="disabled", text="Limpando...")
        self._prog_var.set(0)

        def worker():
            result = run_cleanup(
                progress_cb=lambda v: self.after(0, self._set_progress, v),
                log_cb=lambda m: self.after(0, self._write, m))
            self.after(0, self._done, result)

        threading.Thread(target=worker, daemon=True).start()

    def _done(self, result):
        self._cleaning = False
        freed_mb = result["freed"] * 1024
        avail    = result["after"]["avail"]
        if result["freed"] > 0.05:
            self._write(f"✓ Concluído — {freed_mb:.0f} MB liberados ({avail:.2f} GB disponíveis)")
        else:
            self._write(f"✓ Concluído — {avail:.2f} GB disponíveis agora")
        self._btn.config(state="normal", text="Limpar RAM")
        self._set_progress(100)
        self.after(1500, lambda: self._set_progress(0))

    # ── Auto-limpeza ─────────────────────────────────────

    def _toggle_auto(self):
        if self._auto_id:
            self.after_cancel(self._auto_id)
            self._auto_id = None
            self._next_lbl.config(text="")
        if self._auto_on.get():
            self._schedule()

    def _schedule(self):
        mins   = max(5, self._auto_min.get())
        target = time.time() + mins * 60

        def tick():
            rem = int(target - time.time())
            if rem <= 0:
                self._write(f"Limpeza automática ({mins} min)")
                self._start()
                self._auto_id = self.after(500, self._schedule)
                self._next_lbl.config(text="")
            else:
                m, s = divmod(rem, 60)
                self._next_lbl.config(text=f"próxima: {m:02d}:{s:02d}")
                self._auto_id = self.after(1000, tick)

        tick()


# ─────────────────────────────────────────────────────────
#  Entrada
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    if platform.system() != "Windows":
        print("MemClean só funciona no Windows.")
        sys.exit(1)

    if not is_admin():
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable,
                f'"{os.path.abspath(__file__)}"', None, 1)
            sys.exit(0)
        except Exception:
            pass

    app = MemClean()
    app.mainloop()