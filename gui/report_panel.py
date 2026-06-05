import json
import os
import tkinter.messagebox as messagebox
import customtkinter as ctk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter

class ReportPanel(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="#1e1e2e", **kwargs)
        self.reports = {}

        # --- Standard Security Color Palette ---
        self.STD_COLORS = {
            'CRITICAL': '#E53935', 
            'HIGH': '#FB8C00',     
            'MEDIUM': '#FDD835',   
            'LOW': '#03A9F4',      
            'INFO': '#4CAF50'      
        }
        self.SEV_WEIGHT = {'INFO': 1, 'LOW': 2, 'MEDIUM': 3, 'HIGH': 4, 'CRITICAL': 5}

        # --- Top Header Section ---
        self.top_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.top_frame.pack(fill="x", padx=15, pady=10)
        
        self.lbl_title = ctk.CTkLabel(self.top_frame, text="VM__Hunter Dashboard", font=("Arial", 22, "bold"), text_color="#cdd6f4")
        self.lbl_title.pack(side="left")
        
        self.btn_save = ctk.CTkButton(self.top_frame, text="Export Report JSON", command=self.save_all_reports, fg_color="#89b4fa", hover_color="#74c7ec", text_color="#11111b", font=("Arial", 14, "bold"))
        self.btn_save.pack(side="right", padx=(10, 0))

        self.selected_target = ctk.StringVar(value="Global (All Targets)")
        self.target_selector = ctk.CTkComboBox(
            self.top_frame, 
            variable=self.selected_target, 
            values=["Global (All Targets)"], 
            command=self._on_target_change,
            fg_color="#181825", text_color="#cdd6f4", border_color="#45475a", 
            dropdown_fg_color="#181825", dropdown_text_color="#cdd6f4", 
            font=("Arial", 13, "bold"), width=200
        )
        self.target_selector.pack(side="right", padx=10)

        # --- KPI Metrics Bar ---
        self.kpi_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.kpi_frame.pack(fill="x", padx=15, pady=(0, 10))
        self.kpi_vars = {"CRITICAL": ctk.StringVar(value="0"), "HIGH": ctk.StringVar(value="0"), "MEDIUM": ctk.StringVar(value="0"), "LOW/INFO": ctk.StringVar(value="0")}
        
        self._create_kpi_card(self.kpi_frame, "CRITICAL", self.kpi_vars["CRITICAL"], self.STD_COLORS['CRITICAL'])
        self._create_kpi_card(self.kpi_frame, "HIGH", self.kpi_vars["HIGH"], self.STD_COLORS['HIGH'])
        self._create_kpi_card(self.kpi_frame, "MEDIUM", self.kpi_vars["MEDIUM"], self.STD_COLORS['MEDIUM'])
        self._create_kpi_card(self.kpi_frame, "LOW/INFO", self.kpi_vars["LOW/INFO"], self.STD_COLORS['LOW'])

        # --- Tabbed View Interface ---
        self.tabs = ctk.CTkTabview(self, fg_color="#181825", segmented_button_selected_color="#313244")
        self.tabs.pack(fill="both", expand=True, padx=15, pady=5)
        
        self.tab_dashboard = self.tabs.add("Visual Analytics")
        self.tab_report = self.tabs.add("Detailed Incident Report")
        self.tab_rules = self.tabs.add("Active Detection Rules")

        self.chart_frame = ctk.CTkFrame(self.tab_dashboard, fg_color="transparent")
        self.chart_frame.pack(fill="both", expand=True, pady=10)

        self.text_area = ctk.CTkTextbox(self.tab_report, font=("Consolas", 14), wrap="word", fg_color="#11111b", text_color="#cdd6f4", height=400)
        self.text_area.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.text_area.tag_config("CRITICAL", foreground=self.STD_COLORS['CRITICAL'])
        self.text_area.tag_config("HIGH", foreground=self.STD_COLORS['HIGH'])
        self.text_area.tag_config("MEDIUM", foreground=self.STD_COLORS['MEDIUM'])
        self.text_area.tag_config("LOW", foreground=self.STD_COLORS['LOW'])
        self.text_area.tag_config("INFO", foreground=self.STD_COLORS['INFO'])
        self.text_area.tag_config("HEADER", foreground="#b4befe")
        self.text_area.tag_config("MITRE", foreground="#cba6f7")

        self.rules_area = ctk.CTkTextbox(self.tab_rules, font=("Consolas", 13), wrap="word", fg_color="#11111b", text_color="#a6adc8", height=400)
        self.rules_area.pack(fill="both", expand=True, padx=5, pady=5)
        self._load_and_display_rules()

    def _create_kpi_card(self, parent, title, var, color):
        frame = ctk.CTkFrame(parent, fg_color="#181825", border_width=1, border_color=color)
        frame.pack(side="left", fill="both", expand=True, padx=5)
        ctk.CTkLabel(frame, text=title, font=("Arial", 12, "bold"), text_color=color).pack(pady=(10,0))
        ctk.CTkLabel(frame, textvariable=var, font=("Arial", 24, "bold"), text_color="#cdd6f4").pack(pady=(0,10))

    def _load_and_display_rules(self):
        rules_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rules.json')
        self.rules_area.delete("1.0", "end")
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                rules = json.load(f).get("rules", [])
            for r in rules:
                self.rules_area.insert("end", f"[{r['id']}] {r['name']}\n", "HEADER")
                self.rules_area.insert("end", f"  Severity : {r['severity']}\n")
                self.rules_area.insert("end", f"  Tactic   : {r['tactic']}\n")
                self.rules_area.insert("end", f"  Targets  : {', '.join(r['target_logs'])}\n")
                self.rules_area.insert("end", "-"*60 + "\n")
        except Exception as e:
            self.rules_area.insert("end", f"Failed to load rules: {e}")

    def _get_active_reports(self):
        selected = self.selected_target.get()
        if selected == "Global (All Targets)":
            return list(self.reports.values())
        elif selected in self.reports:
            return [self.reports[selected]]
        return []

    def _on_target_change(self, choice):
        self._refresh_kpis()
        self._refresh_text()
        self._refresh_charts()

    def update_report(self, report):
        self.reports[report.vm_name] = report
        current_targets = ["Global (All Targets)"] + list(self.reports.keys())
        self.target_selector.configure(values=current_targets)
        self._refresh_kpis()
        self._refresh_text()
        self._refresh_charts()

    def _refresh_kpis(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW/INFO": 0}
        active_reports = self._get_active_reports()
        for rep in active_reports:
            for f in rep.findings:
                sev = f.severity.upper()
                if sev in counts: counts[sev] += 1
                elif sev in ["LOW", "INFO"]: counts["LOW/INFO"] += 1
        for k, v in counts.items(): self.kpi_vars[k].set(str(v))

    def _refresh_text(self):
        self.text_area.delete("1.0", "end")
        active_reports = self._get_active_reports()
        if not active_reports:
            self.text_area.insert("end", "[*] Waiting for telemetry data...\n", "INFO")
            return

        for report in active_reports:
            self.text_area.insert("end", f"[{report.timestamp}] INCIDENT REPORT FOR TARGET: {report.vm_name.upper()}\n", "HEADER")
            self.text_area.insert("end", "="*80 + "\n\n")
            if not report.findings:
                self.text_area.insert("end", "[✓] System Secure. No malicious activity detected based on current rules.\n\n", "INFO")
                continue
            for finding in report.findings:
                sev = finding.severity.upper()
                self.text_area.insert("end", f"[ {sev} ] ", sev)
                self.text_area.insert("end", f"{finding.check_name}\n", "MITRE")
                self.text_area.insert("end", f"    Target Log : {finding.log_path}\n    Details    : {finding.description}\n    Evidence   :\n")
                for ev in finding.evidence: self.text_area.insert("end", f"       -> {ev}\n")
                self.text_area.insert("end", f"    Mitigation : {finding.recommendation}\n" + "-"*80 + "\n\n")

    def _refresh_charts(self):
        for widget in self.chart_frame.winfo_children(): widget.destroy()
        
        active_reports = self._get_active_reports()
        all_severities = []
        malicious_activity = []
        tactic_colors = {} 

        for rep in active_reports:
            for finding in rep.findings:
                sev = finding.severity.upper()
                all_severities.append(sev)
                if sev in ["CRITICAL", "HIGH"]:
                    tactic_name = finding.check_name.split(' (')[0]
                    malicious_activity.append(tactic_name)
                    if tactic_name not in tactic_colors or self.SEV_WEIGHT[sev] > self.SEV_WEIGHT.get(tactic_colors[tactic_name], 0):
                        tactic_colors[tactic_name] = sev

        sev_counts = Counter(all_severities)
        mal_counts = Counter(malicious_activity)
        
        if not sev_counts:
            ctk.CTkLabel(self.chart_frame, text="No telemetry data to visualize for the selected target.", font=("Arial", 16), text_color="#cdd6f4").pack(expand=True)
            return

        sorted_sevs = sorted(sev_counts.keys(), key=lambda x: self.SEV_WEIGHT.get(x, 0))
        sizes_sev = [sev_counts[k] for k in sorted_sevs]
        colors_pie = [self.STD_COLORS.get(k, '#808080') for k in sorted_sevs]

        plt.style.use('dark_background')
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5), dpi=100) 
        fig.patch.set_facecolor('#1e1e2e') 
        
        wedges, texts, autotexts = ax1.pie(
            sizes_sev, colors=colors_pie, autopct='%1.1f%%', 
            startangle=140, pctdistance=0.75, 
            wedgeprops=dict(width=0.4, edgecolor='#1e1e2e', linewidth=2)
        )
        ax1.legend(wedges, sorted_sevs, title="Severity Levels", loc="upper center", bbox_to_anchor=(0.5, -0.05), ncol=3, labelcolor='#cdd6f4', facecolor='#1e1e2e', edgecolor='#45475a')
        for text in autotexts: text.set_color('#ffffff'); text.set_fontsize(10); text.set_weight('bold')
        ax1.set_title(f"Severity Distribution", color="#cdd6f4", pad=20, weight="bold")

        ax2.set_facecolor('#1e1e2e')
        if mal_counts:
            sorted_tactics = sorted(mal_counts.keys(), key=lambda x: mal_counts[x])
            values_mal = [mal_counts[k] for k in sorted_tactics]
            bar_colors = [self.STD_COLORS.get(tactic_colors[k], '#E53935') for k in sorted_tactics]

            max_val = max(values_mal)
            x_max = max_val + (max_val * 0.15) if max_val > 0 else 1

            ax2.barh(sorted_tactics, [x_max]*len(sorted_tactics), color='#2a2b3d', height=0.25, edgecolor='none', zorder=1)
            bars = ax2.barh(sorted_tactics, values_mal, color=bar_colors, height=0.25, edgecolor='none', zorder=2)
            
            for bar, color in zip(bars, bar_colors):
                width = bar.get_width()
                ax2.text(width + (x_max * 0.03), bar.get_y() + bar.get_height()/2, f'{int(width)}', va='center', ha='left', color=color, fontsize=13, weight='bold', zorder=3)
                         
            ax2.set_title(f"Targeted Tactics", color="#cdd6f4", pad=20, weight="bold")
            for spine in ax2.spines.values(): spine.set_visible(False)
            ax2.get_xaxis().set_visible(False)
            ax2.tick_params(axis='y', colors='#cdd6f4', length=0, labelsize=10, pad=10) 
            ax2.set_xlim(0, x_max)
            plt.tight_layout()
        else:
            ax2.text(0.5, 0.5, 'No High/Critical Threats Detected', ha='center', va='center', color=self.STD_COLORS['INFO'], fontsize=12)
            ax2.axis('off')

        canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

    def save_all_reports(self):
        active_reports = self._get_active_reports()
        if not active_reports: 
            messagebox.showwarning("Export Failed", "No reports available to export.")
            return
            
        target = self.selected_target.get().replace(" ", "_").replace("(", "").replace(")", "")
        filename = f"Hunting_Report_{target}.json"
        
        with open(filename, 'w') as f: 
            json.dump([r.to_dict() for r in active_reports], f, indent=4)
            
        messagebox.showinfo("Export Successful", f" Report successfully exported to:\n\n{filename}")
        print(f"[✓] Report successfully exported to {filename}")