from dataclasses import dataclass
from typing import List

@dataclass
class Finding:
    severity: str
    rule_name: str
    mitre_id: str
    mitre_tactic: str
    description: str
    evidence: List[str]
    log_path: str = ""
    recommendation: str = ""

    # Compatibility property used by the GUI to display
    # the rule name together with the MITRE ID
    @property
    def check_name(self):
        return f"{self.rule_name} ({self.mitre_id})"

    def to_dict(self):
        # Final JSON structure used for the forensic report
        return {
            "Severity": self.severity,
            "Adversary_Tactic": self.mitre_tactic,
            "MITRE_ATT&CK_ID": self.mitre_id,
            "Rule_Name": self.rule_name,
            "Log_Source": self.log_path,
            "Description": self.description,
            "Raw_Evidence": self.evidence,
            "Remediation": self.recommendation
        }

@dataclass
class Report:
    vm_name: str
    timestamp: str
    findings: List[Finding]
    status: str
    error_message: str = ""

    def to_dict(self):
        # Wrap the report with target and execution metadata
        return {
            "Target_Asset": self.vm_name,
            "Scan_Timestamp": self.timestamp,
            "Execution_Status": self.status,
            "Error_Logs": self.error_message if self.error_message else "None",
            "Total_Alerts": len(self.findings),
            "Hunt_Results": [f.to_dict() for f in self.findings]
        }