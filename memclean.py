"""
MemClean — Otimizador de RAM para Windows
by Lohan Marques | github.com/lohan-marques
"""

import tkinter as tk
from tkinter import ttk
import ctypes, ctypes.wintypes
import threading, time, sys, os, platform, subprocess, webbrowser, math

# ─────────────────────────────────────────────────────────
#  Cores — tema claro minimalista
# ─────────────────────────────────────────────────────────
BG       = "#f5f5f7"
CARD     = "#ffffff"
BORDER   = "#e0e0e6"
TEXT     = "#1a1a2e"
SUBTEXT  = "#8888a0"
ACCENT   = "#5b5ef4"
SUCCESS  = "#22c55e"
WARNING  = "#f59e0b"
DANGER   = "#ef4444"
MONO     = ("Consolas", 9)
UI       = ("Segoe UI", 10)
UI_SB    = ("Segoe UI Semibold", 10)
UI_BIG   = ("Segoe UI Light", 32)

# ─────────────────────────────────────────────────────────
#  Processos em segundo plano conhecidos para encerrar
# ─────────────────────────────────────────────────────────
BACKGROUND_PROCS = [
    # Telemetria e diagnóstico Windows
    "DiagTrack",           # Connected User Experiences and Telemetry
    "WMPNetworkSvc",       # Windows Media Player Network
    "RemoteRegistry",      # Registro remoto
    "SysMain",             # Superfetch (pode ser reativado pelo Windows)
    # Indexação
    "WSearch",             # Windows Search indexer
    # Update
    "wuauserv",            # Windows Update (background)
    # Aplicativos comuns que ficam em bg
    "OneDrive",
    "Teams",
    "Slack",
    "Discord",
    "Spotify",
    "chrome",              # abas em bg consomem bastante
    "msedge",
    "SearchIndexer",
    "SearchProtocolHost",
    "SearchFilterHost",
    "RuntimeBroker",       # broker de apps UWP
    "backgroundTaskHost",
]

# ─────────────────────────────────────────────────────────
#  WinAPI — structs e constantes
# ─────────────────────────────────────────────────────────
SE_PRIVILEGE_ENABLED          = 0x00000002
TOKEN_ADJUST_PRIVILEGES       = 0x00000020
TOKEN_QUERY                   = 0x00000008
SystemMemoryListInformation   = 80
MemoryPurgeStandbyList        = 4
MemoryEmptyWorkingSets        = 2
PROCESS_SET_QUOTA             = 0x0100
PROCESS_TERMINATE             = 0x0001

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

# ─────────────────────────────────────────────────────────
#  Funções de sistema
# ─────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def enable_privilege(name: str) -> bool:
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


def empty_working_sets() -> bool:
    try:
        v = ctypes.c_int(MemoryEmptyWorkingSets)
        return ctypes.windll.ntdll.NtSetSystemInformation(
            SystemMemoryListInformation, ctypes.byref(v), ctypes.sizeof(v)) == 0
    except Exception:
        return False


def purge_standby() -> bool:
    try:
        v = ctypes.c_int(MemoryPurgeStandbyList)
        return ctypes.windll.ntdll.NtSetSystemInformation(
            SystemMemoryListInformation, ctypes.byref(v), ctypes.sizeof(v)) == 0
    except Exception:
        return False


def kill_background_processes(log_cb=None) -> int:
    """
    Encerra processos de segundo plano conhecidos que consomem RAM desnecessariamente.
    Retorna quantos foram encerrados.
    """
    killed = 0
    try:
        result = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=10
        )
        running = {}
        for line in result.stdout.strip().splitlines():
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                name = parts[0].lower().replace(".exe", "")
                try:
                    pid = int(parts[1])
                    running[name] = pid
                except ValueError:
                    pass

        for proc in BACKGROUND_PROCS:
            key = proc.lower()
            if key in running:
                pid = running[key]
                try:
                    h = ctypes.windll.kernel32.OpenProcess(
                        PROCESS_TERMINATE, False, pid)
                    if h:
                        ctypes.windll.kernel32.TerminateProcess(h, 0)
                        ctypes.windll.kernel32.CloseHandle(h)
                        if log_cb:
                            log_cb(f"Encerrado: {proc}")
                        killed += 1
                except Exception:
                    pass
    except Exception as e:
        if log_cb:
            log_cb(f"Aviso: não foi possível listar processos ({e})")
    return killed


def run_cleanup(progress_cb=None, log_cb=None) -> dict:
    before = get_ram()

    steps = [
        ("Ativando privilégios...",        lambda: enable_privilege("SeProfileSingleProcessPrivilege")),
        ("Ativando privilégios...",        lambda: enable_privilege("SeIncreaseQuotaPrivilege")),
        ("Encerrando processos em bg...",  lambda: kill_background_processes(log_cb)),
        ("Limpando Working Sets...",       empty_working_sets),
        ("Limpando Standby List...",       purge_standby),
        ("Finalizando...",                 lambda: time.sleep(0.5)),
    ]

    for i, (msg, fn) in enumerate(steps):
        if log_cb and msg != "Ativando privilégios..." or i == 0:
            if log_cb:
                log_cb(msg)
        fn()
        if progress_cb:
            progress_cb(int((i + 1) / len(steps) * 100))
        time.sleep(0.25)

    after = get_ram()
    return {"before": before, "after": after, "freed": after["avail"] - before["avail"]}


# ─────────────────────────────────────────────────────────
#  Interface gráfica — tema branco miniimalista
# ─────────────────────────────────────────────────────────

class MemClean(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MemClean")
        self.geometry("480x600")
        self.resizable(False, False)
        self.configure(bg=BG)

        # Centraliza
        self.update_idletasks()
        x = (self.winfo_screenwidth()  - 480) // 2
        y = (self.winfo_screenheight() - 600) // 2
        self.geometry(f"480x600+{x}+{y}")

        self._cleaning  = False
        self._auto_id   = None
        self._auto_on   = tk.BooleanVar(value=False)
        self._auto_min  = tk.IntVar(value=30)

        self._build()
        self._tick()

    # ── Construção da UI ──────────────────────────────────

    def _build(self):
        # ── Header
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", padx=28, pady=(24, 0))

        tk.Label(hdr, text="MemClean", font=("Segoe UI Semibold", 18),
                 fg=TEXT, bg=BG).pack(side="left")

        tk.Label(hdr, text="by Lohan", font=("Segoe UI", 9),
                 fg=SUBTEXT, bg=BG).pack(side="right", pady=6)

        tk.Label(self, text="Otimizador de RAM para Windows",
                 font=("Segoe UI", 9), fg=SUBTEXT, bg=BG).pack(anchor="w", padx=28)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=28, pady=14)

        # ── Card RAM
        self._card(self._build_ram_card)

        tk.Frame(self, bg=BG, height=8).pack()

        # ── Card Log
        self._card(self._build_log_card)

        tk.Frame(self, bg=BG, height=4).pack()

        # ── Barra de progresso com contador %
        pf = tk.Frame(self, bg=BG)
        pf.pack(fill="x", padx=28)

        prog_row = tk.Frame(pf, bg=BG)
        prog_row.pack(fill="x")

        self._prog_var = tk.IntVar(value=0)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("MemClean.Horizontal.TProgressbar", troughcolor=BORDER,
                        background=ACCENT, thickness=6, borderwidth=0)
        ttk.Progressbar(prog_row, variable=self._prog_var, maximum=100,
                        style="MemClean.Horizontal.TProgressbar").pack(side="left", fill="x", expand=True)

        self._prog_lbl = tk.Label(prog_row, text="0%", font=("Segoe UI", 8),
                                  fg=SUBTEXT, bg=BG, width=5, anchor="e")
        self._prog_lbl.pack(side="left")

        tk.Frame(self, bg=BG, height=10).pack()

        # ── Auto-limpeza
        af = tk.Frame(self, bg=BG)
        af.pack(fill="x", padx=28)

        tk.Checkbutton(
            af, text="Limpar automaticamente a cada",
            variable=self._auto_on, command=self._toggle_auto,
            font=("Segoe UI", 9), fg=SUBTEXT, bg=BG,
            activebackground=BG, activeforeground=TEXT,
            selectcolor=BG, bd=0
        ).pack(side="left")

        tk.Spinbox(
            af, from_=5, to=120, width=4, textvariable=self._auto_min,
            font=("Segoe UI", 9), bg=BG, fg=ACCENT,
            relief="flat", buttonbackground=BG
        ).pack(side="left", padx=4)

        tk.Label(af, text="min", font=("Segoe UI", 9),
                 fg=SUBTEXT, bg=BG).pack(side="left")

        self._next_lbl = tk.Label(af, text="", font=("Segoe UI", 8),
                                  fg=SUBTEXT, bg=BG)
        self._next_lbl.pack(side="right")

        tk.Frame(self, bg=BG, height=16).pack()

        # ── Botão principal
        self._btn = tk.Button(
            self,
            text="Limpar RAM",
            font=("Segoe UI Semibold", 11),
            fg="#ffffff", bg=ACCENT,
            activebackground="#4a4de0", activeforeground="#fff",
            bd=0, padx=0, pady=12, width=22,
            cursor="hand2", relief="flat",
            command=self._start
        )
        self._btn.pack()

        # ── Rodapé com links RGB clicáveis
        footer = tk.Frame(self, bg=BG)
        footer.pack(pady=(12, 4))

        self._gh_lbl = tk.Label(
            footer, text="GitHub",
            font=("Segoe UI", 8, "underline"),
            bg=BG, cursor="hand2"
        )
        self._gh_lbl.pack(side="left")
        self._gh_lbl.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/lohanmarq"))

        tk.Label(footer, text="  •  ", font=("Segoe UI", 8),
                 fg="#c0c0d0", bg=BG).pack(side="left")

        self._li_lbl = tk.Label(
            footer, text="LinkedIn",
            font=("Segoe UI", 8, "underline"),
            bg=BG, cursor="hand2"
        )
        self._li_lbl.pack(side="left")
        self._li_lbl.bind("<Button-1>", lambda e: webbrowser.open("https://www.linkedin.com/in/lohanmarques/"))

        # Inicia animação RGB nos links
        self._rgb_phase = 0.0
        self._animate_rgb()

    def _card(self, builder):
        f = tk.Frame(self, bg=CARD, bd=0, highlightthickness=1,
                     highlightbackground=BORDER)
        f.pack(fill="x", padx=28)
        builder(f)

    def _build_ram_card(self, f):
        top = tk.Frame(f, bg=CARD)
        top.pack(fill="x", padx=18, pady=(16, 6))

        tk.Label(top, text="RAM em uso", font=("Segoe UI", 9),
                 fg=SUBTEXT, bg=CARD).pack(side="left")

        self._pct_lbl = tk.Label(top, text="–", font=("Segoe UI Light", 30),
                                 fg=TEXT, bg=CARD)
        self._pct_lbl.pack(side="right")

        # Barra fina
        bar_bg = tk.Frame(f, bg=BORDER, height=4)
        bar_bg.pack(fill="x", padx=18, pady=(0, 10))
        bar_bg.pack_propagate(False)
        self._bar = tk.Frame(bar_bg, bg=ACCENT, height=4)
        self._bar.place(x=0, y=0, relheight=1, width=0)

        # Stats
        row = tk.Frame(f, bg=CARD)
        row.pack(fill="x", padx=18, pady=(0, 16))

        self._used_lbl  = self._stat(row, "Usada",      "–")
        self._avail_lbl = self._stat(row, "Disponível", "–")
        self._total_lbl = self._stat(row, "Total",      "–")

    def _build_log_card(self, f):
        tk.Label(f, text="Atividade", font=("Segoe UI", 8),
                 fg=SUBTEXT, bg=CARD).pack(anchor="w", padx=16, pady=(10, 2))

        self._log = tk.Text(
            f, height=5, bg=CARD, fg=TEXT,
            font=MONO, bd=0, padx=12, pady=6,
            state="disabled", cursor="arrow",
            selectbackground=BORDER, relief="flat"
        )
        self._log.pack(fill="x", padx=0, pady=(0, 10))

    def _stat(self, parent, label, value):
        f = tk.Frame(parent, bg=CARD)
        f.pack(side="left", expand=True)
        tk.Label(f, text=label, font=("Segoe UI", 8),
                 fg=SUBTEXT, bg=CARD).pack(anchor="w")
        lbl = tk.Label(f, text=value, font=("Segoe UI Semibold", 12),
                       fg=TEXT, bg=CARD)
        lbl.pack(anchor="w")
        return lbl

    # ── Animação RGB nos links ────────────────────────────

    def _animate_rgb(self):
        p = self._rgb_phase

        def wave(offset):
            v = int((math.sin(p + offset) + 1) / 2 * 255)
            return v

        r1, g1, b1 = wave(0), wave(2.094), wave(4.189)           # GitHub
        r2, g2, b2 = wave(2.094), wave(4.189), wave(0)           # LinkedIn (fase diferente)

        self._gh_lbl.config(fg=f"#{r1:02x}{g1:02x}{b1:02x}")
        self._li_lbl.config(fg=f"#{r2:02x}{g2:02x}{b2:02x}")

        self._rgb_phase += 0.06
        self.after(30, self._animate_rgb)

    # ── Atualiza barra + label % ──────────────────────────

    def _set_progress(self, val: int):
        self._prog_var.set(val)
        self._prog_lbl.config(text=f"{val}%")

    # ── Atualização de stats ──────────────────────────────

    def _tick(self):
        info = get_ram()
        pct = info["pct"]

        color = SUCCESS if pct < 60 else WARNING if pct < 85 else DANGER
        self._pct_lbl.config(text=f"{pct}%", fg=color)
        self._used_lbl.config(text=f"{info['used']:.1f} GB")
        self._avail_lbl.config(text=f"{info['avail']:.1f} GB")
        self._total_lbl.config(text=f"{info['total']:.1f} GB")

        bg = self._bar.master
        bg.update_idletasks()
        w = bg.winfo_width()
        self._bar.config(bg=color)
        self._bar.place(x=0, y=0, relheight=1, width=int(w * pct / 100))

        self.after(2000, self._tick)

    # ── Log ──────────────────────────────────────────────

    def _write(self, msg: str):
        stamp = time.strftime("%H:%M:%S")
        self._log.config(state="normal")
        self._log.insert("end", f"[{stamp}] {msg}\n")
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
                log_cb=lambda m: self.after(0, self._write, m)
            )
            self.after(0, self._done, result)

        threading.Thread(target=worker, daemon=True).start()

    def _done(self, result):
        self._cleaning = False
        freed    = result["freed"]
        freed_mb = freed * 1024
        avail    = result["after"]["avail"]

        if freed > 0.05:
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
                None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1)
            sys.exit(0)
        except Exception:
            pass

    app = MemClean()
    app.mainloop()
