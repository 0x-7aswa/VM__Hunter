import customtkinter as ctk

class VMCard(ctk.CTkFrame):
    def __init__(self, master, vm_data, test_callback, hunt_callback, **kwargs):
        super().__init__(master, fg_color="#2b2b2b", border_width=1, border_color="#3b3b3b", **kwargs)
        
        self.vm_data = vm_data
        self.test_callback = test_callback
        self.hunt_callback = hunt_callback

        # VM Name and IP
        self.lbl_name = ctk.CTkLabel(self, text=vm_data.get('name', 'Unknown').upper(), font=("Arial", 15, "bold"))
        self.lbl_name.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="w")
        
        self.lbl_host = ctk.CTkLabel(self, text=f"IP: {vm_data.get('host', 'N/A')}", font=("Arial", 12), text_color="#b0b0b0")
        self.lbl_host.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="w")

        # Status Indicator
        self.lbl_status = ctk.CTkLabel(self, text="Status: Standby", font=("Arial", 12, "bold"), text_color="gray")
        self.lbl_status.grid(row=0, column=1, rowspan=2, padx=10, pady=10, sticky="e")

        # Buttons Frame
        self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="ew")
        self.btn_frame.grid_columnconfigure(0, weight=1)
        self.btn_frame.grid_columnconfigure(1, weight=1)

        self.btn_test = ctk.CTkButton(self.btn_frame, text="Test Ping", command=self._on_test, fg_color="#1f538d")
        self.btn_test.grid(row=0, column=0, padx=(0, 5), sticky="ew")

        self.btn_hunt = ctk.CTkButton(self.btn_frame, text="Hunt Target", command=self._on_hunt, fg_color="#8B0000", hover_color="#5c0000")
        self.btn_hunt.grid(row=0, column=1, padx=(5, 0), sticky="ew")

        self.grid_columnconfigure(1, weight=1) # Push status to the right

    def _on_test(self):
        self.lbl_status.configure(text="Status: Testing...", text_color="yellow")
        is_online = self.test_callback(self.vm_data)
        if is_online:
            self.lbl_status.configure(text="Status: Online", text_color="#00FF00")
        else:
            self.lbl_status.configure(text="Status: Offline", text_color="#FF0000")

    def _on_hunt(self):
        self.lbl_status.configure(text="Status: Hunting...", text_color="orange")
        self.btn_hunt.configure(state="disabled")
        self.hunt_callback(self.vm_data, self._hunt_finished)

    def _hunt_finished(self, status_text, color):
        self.lbl_status.configure(text=f"Status: {status_text}", text_color=color)
        self.btn_hunt.configure(state="normal")