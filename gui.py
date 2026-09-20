#!/usr/bin/env python3
import json
import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

import kaspersky_inventory as ksc
import json_to_excel as j2e

def get_app_dir():
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return Path(__file__).parent

SETTINGS = get_app_dir() / "settings.json"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Kaspersky Inventory - Simple GUI")
        self.geometry("620x520")
        self.resizable(False, False)

        # load settings pre-filled
        data = {}
        try:
            if SETTINGS.exists():
                data = json.loads(SETTINGS.read_text(encoding="utf-8-sig"))
        except:
            data = {}
        defaults = {"KSC_SERVER":"127.0.0.1","KSC_API_PORT":13299,"KSC_VERIFY_SSL":False,"KSC_USERNAME":"","KSC_PASSWORD":""}
        cur = {**defaults, **data}
        try: cur["KSC_API_PORT"]=int(cur["KSC_API_PORT"])
        except: cur["KSC_API_PORT"]=13299

        frm = ttk.LabelFrame(self, text="Settings (settings.json)", padding=10)
        frm.pack(fill="x", padx=10, pady=10)

        ttk.Label(frm, text="KSC Server:").grid(row=0,column=0,sticky="w",pady=3)
        self.e_server = ttk.Entry(frm, width=32)
        self.e_server.insert(0, str(cur.get("KSC_SERVER","")))
        self.e_server.grid(row=0,column=1,sticky="ew",pady=3)

        ttk.Label(frm, text="Port:").grid(row=1,column=0,sticky="w",pady=3)
        self.e_port = ttk.Entry(frm, width=32)
        self.e_port.insert(0, str(cur.get("KSC_API_PORT","13299")))
        self.e_port.grid(row=1,column=1,sticky="ew",pady=3)

        ttk.Label(frm, text="Username:").grid(row=2,column=0,sticky="w",pady=3)
        self.e_user = ttk.Entry(frm, width=32)
        self.e_user.insert(0, str(cur.get("KSC_USERNAME","")))
        self.e_user.grid(row=2,column=1,sticky="ew",pady=3)

        ttk.Label(frm, text="Password:").grid(row=3,column=0,sticky="w",pady=3)
        self.e_pass = ttk.Entry(frm, width=32, show="*")
        self.e_pass.insert(0, str(cur.get("KSC_PASSWORD","")))
        self.e_pass.grid(row=3,column=1,sticky="ew",pady=3)

        self.var_ssl = tk.BooleanVar(value=bool(cur.get("KSC_VERIFY_SSL", False)))
        ttk.Checkbutton(frm, text="Verify SSL", variable=self.var_ssl).grid(row=4,column=1,sticky="w",pady=3)

        frm.columnconfigure(1, weight=1)

        btn_frm = ttk.Frame(self)
        btn_frm.pack(fill="x", padx=10, pady=5)

        self.btn_save = ttk.Button(btn_frm, text="Save Settings", command=self.save_settings)
        self.btn_save.pack(side="left", padx=5)

        self.btn_run = ttk.Button(btn_frm, text="Run Inventory", command=self.run_inventory)
        self.btn_run.pack(side="left", padx=5)

        self.btn_excel = ttk.Button(btn_frm, text="Convert JSON to Excel", command=self.run_excel)
        self.btn_excel.pack(side="left", padx=5)

        self.btn_vuln = ttk.Button(btn_frm, text="Vulnerability Report", command=self.run_vuln)
        self.btn_vuln.pack(side="left", padx=5)

        self.btn_rules = ttk.Button(btn_frm, text="Update Vuln Rules", command=self.run_rules)
        self.btn_rules.pack(side="left", padx=5)

        log_frm = ttk.LabelFrame(self, text="Log", padding=5)
        log_frm.pack(fill="both", expand=True, padx=10, pady=5)
        self.txt = scrolledtext.ScrolledText(log_frm, height=16, font=("Consolas", 9))
        self.txt.pack(fill="both", expand=True)
        self.log("Ready. Settings loaded from settings.json (if exists).")

        self.status = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", padx=10, pady=(0,5))

    def log(self, msg):
        self.txt.insert("end", msg + "\n")
        self.txt.see("end")
        self.update_idletasks()

    def get_settings_from_ui(self):
        server = self.e_server.get().strip()
        port_raw = self.e_port.get().strip()
        user = self.e_user.get().strip()
        pwd = self.e_pass.get()
        verify = bool(self.var_ssl.get())
        if not server:
            raise ValueError("KSC Server is empty")
        try:
            port=int(port_raw)
            if not 1 <= port <= 65535: raise ValueError()
        except:
            raise ValueError("Port must be 1-65535")
        if not user: raise ValueError("Username is empty")
        if not pwd: raise ValueError("Password is empty")
        return {"KSC_SERVER":server,"KSC_API_PORT":port,"KSC_VERIFY_SSL":verify,"KSC_USERNAME":user,"KSC_PASSWORD":pwd}

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

    def run_inventory(self):
        try:
            cfg = self.get_settings_from_ui()
        except Exception as e:
            messagebox.showerror("Error", str(e)); return
        try: ksc.save_settings(cfg, SETTINGS)
        except: pass
        self.btn_run.config(state="disabled")
        self.btn_excel.config(state="disabled")
        self.btn_vuln.config(state="disabled")
        self.btn_rules.config(state="disabled")
        self.status.set("Running Inventory...")
        self.log("-- Starting Inventory fetch ...")
        def worker():
            try:
                rc = ksc.main(["--no-input","--settings",str(SETTINGS)])
                msg = "Completed successfully" if rc==0 else f"Finished with code {rc}"
                self.after(0, lambda: self.log(f"-- {msg}"))
                self.after(0, lambda: self.status.set(msg))
            except SystemExit as se:
                self.after(0, lambda: self.log(f"-- Exit {se.code}"))
            except Exception as e:
                self.after(0, lambda: self.log(f"Error: {e}"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.after(0, lambda: self.btn_run.config(state="normal"))
                self.after(0, lambda: self.btn_excel.config(state="normal"))
                self.after(0, lambda: self.btn_vuln.config(state="normal"))
                self.after(0, lambda: self.btn_rules.config(state="normal"))
        threading.Thread(target=worker, daemon=True).start()

    def run_excel(self):
        self.btn_run.config(state="disabled")
        self.btn_excel.config(state="disabled")
        self.btn_vuln.config(state="disabled")
        self.btn_rules.config(state="disabled")
        self.status.set("Converting JSON to Excel...")
        self.log("-- Converting all kaspersky_inventory_*.json ...")
        def worker():
            try:
                import io, contextlib
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = j2e.main()
                out = buf.getvalue()
                for line in out.splitlines():
                    self.after(0, lambda l=line: self.log(l))
                if rc==0:
                    self.after(0, lambda: self.status.set("Converted"))
                    self.after(0, lambda: messagebox.showinfo("Done", "All files converted to Excel"))
                else:
                    self.after(0, lambda: self.status.set("No JSON files found"))
            except Exception as e:
                self.after(0, lambda: self.log(f"Convert error: {e}"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.after(0, lambda: self.btn_run.config(state="normal"))
                self.after(0, lambda: self.btn_excel.config(state="normal"))
                self.after(0, lambda: self.btn_vuln.config(state="normal"))
                self.after(0, lambda: self.btn_rules.config(state="normal"))
        threading.Thread(target=worker, daemon=True).start()

    def run_vuln(self):
        import glob
        base = get_app_dir()
        files = sorted(set(glob.glob(str(base / "kaspersky_inventory_*.json")) +
                           glob.glob(str(base / "out" / "kaspersky_inventory_*.json"))))
        if not files:
            messagebox.showerror("Error", "No kaspersky_inventory_*.json found")
            return
        latest = files[-1]
        self.btn_run.config(state="disabled")
        self.btn_excel.config(state="disabled")
        self.btn_vuln.config(state="disabled")
        self.btn_rules.config(state="disabled")
        self.status.set("Checking vulnerabilities...")
        self.log(f"-- Vulnerability scan on {Path(latest).name} (offline rules + cache) ...")
        def worker():
            try:
                import io, contextlib, vuln_check as vc
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = vc.main([latest, "--excel"])
                out = buf.getvalue()
                for line in out.splitlines():
                    self.after(0, lambda l=line: self.log(l))
                if rc == 0:
                    self.after(0, lambda: self.status.set("Vulnerability report done"))
                    self.after(0, lambda: messagebox.showinfo("Done", "Risk report (JSON + Excel) saved in out/"))
                else:
                    self.after(0, lambda: self.status.set("Vulnerability scan failed"))
            except Exception as e:
                self.after(0, lambda: self.log(f"Vuln error: {e}"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.after(0, lambda: self.btn_run.config(state="normal"))
                self.after(0, lambda: self.btn_excel.config(state="normal"))
                self.after(0, lambda: self.btn_vuln.config(state="normal"))
                self.after(0, lambda: self.btn_rules.config(state="normal"))
        threading.Thread(target=worker, daemon=True).start()

    def run_rules(self):
        if not messagebox.askyesno("Update Vuln Rules",
                "Download endoflife.date + CISA KEV feeds and rebuild\n"
                "upstream sections of vuln_rules.json?\n\nNeeds internet."):
            return
        self.btn_run.config(state="disabled")
        self.btn_excel.config(state="disabled")
        self.btn_vuln.config(state="disabled")
        self.btn_rules.config(state="disabled")
        self.status.set("Updating vuln rules from internet...")
        self.log("-- Updating vuln_rules.json from endoflife.date + CISA KEV ...")
        def worker():
            try:
                import io, contextlib, vuln_check as vc
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = vc.main(["--update-rules"])
                out = buf.getvalue()
                for line in out.splitlines():
                    self.after(0, lambda l=line: self.log(l))
                if rc == 0:
                    self.after(0, lambda: self.status.set("Vuln rules updated"))
                    self.after(0, lambda: messagebox.showinfo("Done", "vuln_rules.json updated from the internet"))
                else:
                    self.after(0, lambda: self.status.set("Rules update failed - file unchanged"))
                    self.after(0, lambda: messagebox.showerror("Error", "Could not fetch feeds (no internet?). Rules file unchanged."))
            except Exception as e:
                self.after(0, lambda: self.log(f"Rules error: {e}"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.after(0, lambda: self.btn_run.config(state="normal"))
                self.after(0, lambda: self.btn_excel.config(state="normal"))
                self.after(0, lambda: self.btn_vuln.config(state="normal"))
                self.after(0, lambda: self.btn_rules.config(state="normal"))
        threading.Thread(target=worker, daemon=True).start()

if __name__ == "__main__":
    app = App()
    app.mainloop()
