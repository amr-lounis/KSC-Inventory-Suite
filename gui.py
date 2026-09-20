#!/usr/bin/env python3
import glob
import json
import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog

import kaspersky_inventory as ksc
import json_to_excel as j2e

ACCENT = "#2563EB"
HEADER_BG = "#1F2937"
BODY_BG = "#F2F4F8"


def get_app_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


SETTINGS = get_app_dir() / "settings.json"


def find_inventories():
    base = get_app_dir()
    files = sorted(set(glob.glob(str(base / "kaspersky_inventory_*.json")) +
                       glob.glob(str(base / "out" / "kaspersky_inventory_*.json"))))
    return files


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Kaspersky Inventory")
        self.geometry("780x700")
        self.minsize(680, 560)
        self.configure(bg=BODY_BG)
        self.option_add("*Font", ("Segoe UI", 10))
        self._apply_theme()

        # ---- header ----
        hdr = tk.Frame(self, bg=HEADER_BG)
        hdr.pack(fill="x")
        tk.Label(hdr, text="Kaspersky Inventory", bg=HEADER_BG, fg="white",
                 font=("Segoe UI", 15, "bold")).pack(side="left", padx=14, pady=10)
        tk.Label(hdr, text="Security Center exporter & reports", bg=HEADER_BG, fg="#9CA3AF",
                 font=("Segoe UI", 10)).pack(side="left", pady=12)

        body = ttk.Frame(self, padding=10)
        body.pack(fill="both", expand=True)

        # ---- settings ----
        data = {}
        try:
            if SETTINGS.exists():
                data = json.loads(SETTINGS.read_text(encoding="utf-8-sig"))
        except Exception:
            data = {}
        defaults = {"KSC_SERVER": "127.0.0.1", "KSC_API_PORT": 13299,
                    "KSC_VERIFY_SSL": False, "KSC_USERNAME": "", "KSC_PASSWORD": ""}
        cur = {**defaults, **data}
        try:
            cur["KSC_API_PORT"] = int(cur["KSC_API_PORT"])
        except Exception:
            cur["KSC_API_PORT"] = 13299

        frm = ttk.LabelFrame(body, text="Connection (settings.json)", padding=10)
        frm.pack(fill="x", pady=(0, 8))
        ttk.Label(frm, text="Server:").grid(row=0, column=0, sticky="w", pady=3)
        self.e_server = ttk.Entry(frm)
        self.e_server.insert(0, str(cur.get("KSC_SERVER", "")))
        self.e_server.grid(row=0, column=1, sticky="ew", pady=3, padx=(6, 0))
        ttk.Label(frm, text="Port:").grid(row=0, column=2, sticky="w", pady=3, padx=(12, 0))
        self.e_port = ttk.Entry(frm, width=10)
        self.e_port.insert(0, str(cur.get("KSC_API_PORT", "13299")))
        self.e_port.grid(row=0, column=3, sticky="ew", pady=3, padx=(6, 0))
        ttk.Label(frm, text="Username:").grid(row=1, column=0, sticky="w", pady=3)
        self.e_user = ttk.Entry(frm)
        self.e_user.insert(0, str(cur.get("KSC_USERNAME", "")))
        self.e_user.grid(row=1, column=1, sticky="ew", pady=3, padx=(6, 0))
        ttk.Label(frm, text="Password:").grid(row=1, column=2, sticky="w", pady=3, padx=(12, 0))
        self.e_pass = ttk.Entry(frm, show="*")
        self.e_pass.insert(0, str(cur.get("KSC_PASSWORD", "")))
        self.e_pass.grid(row=1, column=3, sticky="ew", pady=3, padx=(6, 0))
        self.var_ssl = tk.BooleanVar(value=bool(cur.get("KSC_VERIFY_SSL", False)))
        ttk.Checkbutton(frm, text="Verify SSL", variable=self.var_ssl).grid(row=2, column=1, sticky="w", pady=3)
        for c, w in ((1, 1), (3, 1)):
            frm.columnconfigure(c, weight=w)

        # ---- inventory file picker ----
        ffrm = ttk.LabelFrame(body, text="Inventory file (kaspersky_inventory_*.json)", padding=10)
        ffrm.pack(fill="x", pady=(0, 8))
        self.json_var = tk.StringVar(value=self._detect_latest())
        self.e_json = ttk.Entry(ffrm, textvariable=self.json_var, state="readonly")
        self.e_json.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ttk.Button(ffrm, text="Browse...", command=self.browse_json).pack(side="left")
        ttk.Button(ffrm, text="Latest", command=self.use_latest).pack(side="left", padx=(6, 0))
        ffrm.columnconfigure(0, weight=1)

        # ---- actions ----
        afrm = ttk.LabelFrame(body, text="Actions", padding=10)
        afrm.pack(fill="x", pady=(0, 8))
        self.btn_save = ttk.Button(afrm, text="Save Settings", command=self.save_settings)
        self.btn_save.grid(row=0, column=0, padx=4, pady=2, sticky="ew")
        self.btn_rules = ttk.Button(afrm, text="Update Vuln Rules", command=self.run_rules)
        self.btn_rules.grid(row=0, column=1, padx=4, pady=2, sticky="ew")
        self.btn_run = ttk.Button(afrm, text="Run Inventory", command=self.run_inventory, style="Accent.TButton")
        self.btn_run.grid(row=0, column=2, padx=4, pady=2, sticky="ew")
        self.btn_excel = ttk.Button(afrm, text="JSON to Excel", command=self.run_excel, style="Accent.TButton")
        self.btn_excel.grid(row=0, column=3, padx=4, pady=2, sticky="ew")
        self.btn_vuln = ttk.Button(afrm, text="Vulnerability Report", command=self.run_vuln, style="Accent.TButton")
        self.btn_vuln.grid(row=0, column=4, padx=4, pady=2, sticky="ew")
        for c in range(5):
            afrm.columnconfigure(c, weight=1, uniform="actions")

        # ---- log ----
        log_frm = ttk.LabelFrame(body, text="Log", padding=5)
        log_frm.pack(fill="both", expand=True)
        self.txt = scrolledtext.ScrolledText(log_frm, height=14, font=("Consolas", 9),
                                             bg="white", relief="flat")
        self.txt.pack(fill="both", expand=True)
        self.log("Ready. Settings loaded from settings.json (if exists).")
        if self.json_var.get():
            self.log(f"Selected: {Path(self.json_var.get()).name}")

        self.status = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status, anchor="w", relief="sunken",
                  padding=(8, 3)).pack(fill="x", side="bottom")

    # ---------- theme ----------
    def _apply_theme(self):
        style = ttk.Style()
        for theme in ("clam", "alt", "default", "vista", "xpnative"):
            try:
                style.theme_use(theme)
                break
            except Exception:
                continue
        style.configure("Accent.TButton", background=ACCENT, foreground="white",
                        font=("Segoe UI", 10, "bold"), padding=6)
        style.map("Accent.TButton",
                  background=[("disabled", "#9CA3AF"), ("active", "#1D4ED8")],
                  foreground=[("disabled", "white")])

    # ---------- helpers ----------
    def log(self, msg):
        self.txt.insert("end", msg + "\n")
        self.txt.see("end")
        self.update_idletasks()

    def _buttons(self):
        return (self.btn_run, self.btn_excel, self.btn_vuln, self.btn_rules)

    def _set_busy(self, busy):
        state = "disabled" if busy else "normal"
        for b in self._buttons():
            b.config(state=state)

    def _set_busy_async(self, busy):
        for b in self._buttons():
            self.after(0, lambda b=b, s="disabled" if busy else "normal": b.config(state=s))

    def _detect_latest(self):
        files = find_inventories()
        return files[-1] if files else ""

    def browse_json(self):
        path = filedialog.askopenfilename(
            title="Select inventory JSON",
            initialdir=str(get_app_dir()),
            filetypes=[("Inventory JSON", "kaspersky_inventory_*.json"),
                       ("JSON files", "*.json"),
                       ("All files", "*.*")])
        if path:
            self.json_var.set(path)
            self.log(f"Selected: {Path(path).name}")

    def use_latest(self):
        latest = self._detect_latest()
        if latest:
            self.json_var.set(latest)
            self.log(f"Selected latest: {Path(latest).name}")
        else:
            messagebox.showwarning("No files", "No kaspersky_inventory_*.json found")

    def selected_json(self):
        p = self.json_var.get().strip()
        if not p or not Path(p).exists():
            messagebox.showerror("Error", "Select a valid kaspersky_inventory_*.json first")
            return ""
        return p

    # ---------- settings ----------
    def get_settings_from_ui(self):
        server = self.e_server.get().strip()
        port_raw = self.e_port.get().strip()
        user = self.e_user.get().strip()
        pwd = self.e_pass.get()
        verify = bool(self.var_ssl.get())
        if not server:
            raise ValueError("KSC Server is empty")
        try:
            port = int(port_raw)
            if not 1 <= port <= 65535:
                raise ValueError()
        except Exception:
            raise ValueError("Port must be 1-65535")
        if not user:
            raise ValueError("Username is empty")
        if not pwd:
            raise ValueError("Password is empty")
        return {"KSC_SERVER": server, "KSC_API_PORT": port, "KSC_VERIFY_SSL": verify,
                "KSC_USERNAME": user, "KSC_PASSWORD": pwd}

    def save_settings(self):
        try:
            cfg = self.get_settings_from_ui()
            ksc.save_settings(cfg, SETTINGS)
            self.log(f"Saved to {SETTINGS}")
            self.status.set("Saved")
            messagebox.showinfo("Done", f"Settings saved to\n{SETTINGS}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.log(f"Save failed: {e}")

    # ---------- workers ----------
    def _run_thread(self, title, status, target):
        self._set_busy(True)
        self.status.set(status)
        self.log(title)

        def worker():
            try:
                import io
                import contextlib
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = target()
                for line in buf.getvalue().splitlines():
                    self.after(0, lambda l=line: self.log(l))
                self.after(0, lambda: self._on_done(rc))
            except SystemExit as se:
                self.after(0, lambda: self.log(f"-- Exit {se.code}"))
                self.after(0, lambda: self._set_busy_async(False))
            except Exception as e:
                self.after(0, lambda: self.log(f"Error: {e}"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
                self.after(0, lambda: self._set_busy_async(False))
        threading.Thread(target=worker, daemon=True).start()

    def _on_done(self, rc):
        self._set_busy_async(False)

    def run_inventory(self):
        try:
            cfg = self.get_settings_from_ui()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return
        try:
            ksc.save_settings(cfg, SETTINGS)
        except Exception:
            pass

        def target():
            rc = ksc.main(["--no-input", "--settings", str(SETTINGS)])
            msg = "Completed successfully" if rc == 0 else f"Finished with code {rc}"
            self.after(0, lambda: self.log(f"-- {msg}"))
            self.after(0, lambda: self.status.set(msg))
            if rc == 0:
                latest = self._detect_latest()
                if latest:
                    self.after(0, lambda: self.json_var.set(latest))
                    self.after(0, lambda: self.log(f"Selected new file: {Path(latest).name}"))
            return rc

        self._run_thread("-- Starting Inventory fetch ...", "Running Inventory...", target)

    def run_excel(self):
        src = self.selected_json()
        if not src:
            return
        out = get_app_dir() / "out" / f"software_inventory_{Path(src).stem}.xlsx"

        def target():
            rc = j2e.main([src, "-o", str(out)])
            if rc == 0:
                self.after(0, lambda: self.status.set("Converted"))
                self.after(0, lambda: messagebox.showinfo("Done", f"Saved in out/\n{out.name}"))
            else:
                self.after(0, lambda: self.status.set("Convert failed"))
            return rc

        self._run_thread(f"-- Converting {Path(src).name} -> {out.name} ...",
                         "Converting JSON to Excel...", target)

    def run_vuln(self):
        src = self.selected_json()
        if not src:
            return

        def target():
            import vuln_check as vc
            rc = vc.main([src, "--excel"])
            if rc == 0:
                self.after(0, lambda: self.status.set("Vulnerability report done"))
                self.after(0, lambda: messagebox.showinfo("Done", "Risk report (JSON + Excel) saved in out/"))
            else:
                self.after(0, lambda: self.status.set("Vulnerability scan failed"))
            return rc

        self._run_thread(f"-- Vulnerability scan on {Path(src).name} (offline rules + cache) ...",
                         "Checking vulnerabilities...", target)

    def run_rules(self):
        if not messagebox.askyesno("Update Vuln Rules",
                                   "Download endoflife.date + CISA KEV feeds and rebuild\n"
                                   "upstream sections of vuln_rules.json?\n\nNeeds internet."):
            return

        def target():
            import vuln_check as vc
            rc = vc.main(["--update-rules"])
            if rc == 0:
                self.after(0, lambda: self.status.set("Vuln rules updated"))
                self.after(0, lambda: messagebox.showinfo("Done", "vuln_rules.json updated from the internet"))
            else:
                self.after(0, lambda: self.status.set("Rules update failed - file unchanged"))
                self.after(0, lambda: messagebox.showerror(
                    "Error", "Could not fetch feeds (no internet?). Rules file unchanged."))
            return rc

        self._run_thread("-- Updating vuln_rules.json from endoflife.date + CISA KEV ...",
                         "Updating vuln rules from internet...", target)


if __name__ == "__main__":
    app = App()
    app.mainloop()
