import json
import queue
import threading
import sys
import customtkinter as ctk
from gui.vm_card import VMCard
from gui.report_panel import ReportPanel
from transport.ssh import SSHManager
from hunting.engine import HuntEngine

# --- Thread-Safe Console Redirector ---
class ConsoleRedirector:
    def __init__(self, text_queue):
        self.text_queue = text_queue
        
    def write(self, str_data):
        if str_data.strip():
            self.text_queue.put(str_data.strip())
            
    def flush(self):
        pass

# Professional Appearance Settings
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class ThreatHunterApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("VM__Hunter")
        self.geometry("1300x850") # Expanded for charts and console

        # Load VM configs & Initialize Engine
        self.vms_config = self._load_vms()
        self.engine = HuntEngine(self.vms_config)
        
        # Queues for thread-safe GUI updates
        self.update_queue = queue.Queue() # For Report & VMCard status updates
        self.log_queue = queue.Queue()    # For Live Console prints
        
        # Redirect standard output (print) to our GUI Console
        self.original_stdout = sys.stdout
        sys.stdout = ConsoleRedirector(self.log_queue)

        # Layout Configuration
        self.grid_columnconfigure(0, weight=1, minsize=350) # Left Panel (VMs)
        self.grid_columnconfigure(1, weight=3)              # Right Panel (Reports)
        self.grid_rowconfigure(0, weight=1)                 # Main Content
        self.grid_rowconfigure(1, weight=0)                 # Bottom Console

        # --- Left Panel: VM Fleet ---
        self.left_panel = ctk.CTkScrollableFrame(self, label_text="Monitored Fleet", label_font=("Arial", 16, "bold"), fg_color="#181825")
        self.left_panel.grid(row=0, column=0, padx=(10, 5), pady=(10, 5), sticky="nsew")
        
        self.vm_cards = []
        for vm in self.vms_config:
            # Using your original VMCard integration
            card = VMCard(self.left_panel, vm, self._test_vm_sync, self._start_hunt_thread)
            card.pack(fill="x", pady=8, padx=5)
            self.vm_cards.append(card)

        self.btn_hunt_all = ctk.CTkButton(
            self.left_panel, 
            text="Launch Global Hunt", 
            command=self._hunt_all, 
            fg_color="#E53935", 
            hover_color="#b71c1c",
            font=("Arial", 14, "bold"),
            height=40
        )
        self.btn_hunt_all.pack(pady=20, padx=10, fill="x")

        # --- Right Panel: Reports & Analytics ---
        self.report_panel = ReportPanel(self)
        self.report_panel.grid(row=0, column=1, padx=(5, 10), pady=(10, 5), sticky="nsew")

        # --- Bottom Panel: Live Status Console ---
        self.console_frame = ctk.CTkFrame(self, fg_color="#11111b", height=150)
        self.console_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=(5, 10), sticky="ew")
        
        console_lbl = ctk.CTkLabel(self.console_frame, text="Live Operation Status", font=("Consolas", 12, "bold"), text_color="#a6adc8")
        console_lbl.pack(anchor="w", padx=10, pady=(5, 0))
        
        self.progress_bar = ctk.CTkProgressBar(self.console_frame, mode="indeterminate", fg_color="#313244", progress_color="#89b4fa")
        self.progress_bar.pack(fill="x", padx=10, pady=5)
        self.progress_bar.set(0) # Initially stopped

        self.console_text = ctk.CTkTextbox(self.console_frame, font=("Consolas", 12), fg_color="#11111b", text_color="#a6e3a1", height=80)
        self.console_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.console_text.insert("end", "[*] VM__Hunter Initialized. Ready for hunting operations.\n")

        # Start polling both queues
        self._poll_queues()

    def _load_vms(self):
        try:
            with open("vms.json", "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading vms.json: {e}")
            return []

    def _test_vm_sync(self, vm_data):
        """Synchronous test for a single VM (Ping button)."""
        ssh = SSHManager(
            host=vm_data.get('host'), 
            port=vm_data.get('port', 22), 
            username=vm_data.get('username'), 
            key_path=vm_data.get('key_path'),
            password=vm_data.get('password')
        )
        is_online = ssh.test_connection()
        ssh.close()
        return is_online

    def _start_hunt_thread(self, vm_data, ui_callback):
        """Starts hunting for a single VM in a background thread."""
        self.progress_bar.start()
        print(f"[*] Dispatching targeted hunt agent to {vm_data['name']}...")
        
        def worker():
            report = self.engine.hunt_single_vm(vm_data)
            self.update_queue.put({"type": "single_hunt_done", "report": report, "callback": ui_callback})
        
        threading.Thread(target=worker, daemon=True).start()

    def _hunt_all(self):
        """Starts the HuntEngine's concurrent global hunt."""
        self.progress_bar.start()
        print("[*] Initiating Global Hunt. Dispatching concurrent agents...")
        
        # Disable UI elements during hunt
        for card in self.vm_cards:
            card.btn_hunt.configure(state="disabled")
            card.lbl_status.configure(text="Status: Hunting...", text_color="orange")
        self.btn_hunt_all.configure(state="disabled", text="Hunting in Progress...")

        def worker():
            reports = self.engine.hunt_all_vms()
            self.update_queue.put({"type": "all_hunts_done", "reports": reports})

        threading.Thread(target=worker, daemon=True).start()

    def _poll_queues(self):
        """Checks queues for Console logs and UI updates every 100ms."""
        # 1. Process Console Logs
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.console_text.insert("end", f"{msg}\n")
            self.console_text.see("end")

        # 2. Process UI & Report Updates
        try:
            while True:
                msg = self.update_queue.get_nowait()
                
                if msg["type"] == "single_hunt_done":
                    report = msg["report"]
                    self.report_panel.update_report(report)
                    cb = msg["callback"]
                    
                    if report.status == "Success":
                        cb("Done", "#00FF00")
                    else:
                        cb("Error", "#FF0000")
                        
                    self.progress_bar.stop()
                    print(f"[✓] Targeted Hunt Completed for {report.vm_name}.")
                    
                elif msg["type"] == "all_hunts_done":
                    reports = msg["reports"]
                    for report in reports:
                        self.report_panel.update_report(report)
                    
                    # Reset UI
                    for card in self.vm_cards:
                        card.btn_hunt.configure(state="normal")
                        card.lbl_status.configure(text="Status: Done", text_color="#00FF00")
                    self.btn_hunt_all.configure(state="normal", text="Launch Global Hunt")
                    
                    self.progress_bar.stop()
                    print("[✓] Global Hunt Completed. Analytics dashboard updated.")
                    
        except queue.Empty:
            pass
        finally:
            self.after(100, self._poll_queues)

    def on_closing(self):
        """Restores stdout and safely terminates the application."""
        sys.stdout = self.original_stdout
        self.destroy()

if __name__ == "__main__":
    app = ThreatHunterApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()