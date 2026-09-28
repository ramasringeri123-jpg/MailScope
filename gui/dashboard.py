import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import threading

from ingestion.email_analyzer import EmailAnalyzer


class MailScopeDashboard:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "MailScope — Email Security Analyzer"
        )

        self.root.geometry("1150x760")
        self.root.minsize(950, 650)

        self.root.configure(
            bg="#0b0f14"
        )

        self.analyzer = EmailAnalyzer()

        self.build_interface()

    # =========================================================
    # INTERFACE
    # =========================================================

    def build_interface(self):

        # -----------------------------------------------------
        # HEADER
        # -----------------------------------------------------

        header = tk.Frame(
            self.root,
            bg="#111820",
            height=80
        )

        header.pack(
            fill="x"
        )

        tk.Label(
            header,
            text="MAILSCOPE",
            font=("Segoe UI", 25, "bold"),
            fg="#ffffff",
            bg="#111820"
        ).pack(
            side="left",
            padx=30
        )

        tk.Label(
            header,
            text="EMAIL SECURITY ENGINE",
            font=("Segoe UI", 10),
            fg="#8b98a8",
            bg="#111820"
        ).pack(
            side="left"
        )

        self.status_label = tk.Label(
            header,
            text="● PROTECTION READY",
            font=("Segoe UI", 11, "bold"),
            fg="#42d392",
            bg="#111820"
        )

        self.status_label.pack(
            side="right",
            padx=30
        )

        # -----------------------------------------------------
        # MAIN
        # -----------------------------------------------------

        main = tk.Frame(
            self.root,
            bg="#0b0f14"
        )

        main.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=20
        )

        # -----------------------------------------------------
        # LEFT
        # -----------------------------------------------------

        left = tk.Frame(
            main,
            bg="#111820"
        )

        left.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 10)
        )

        tk.Label(
            left,
            text="EMAIL INSPECTION",
            font=("Segoe UI", 13, "bold"),
            fg="#ffffff",
            bg="#111820"
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 10)
        )

        self.file_label = tk.Label(
            left,
            text="No email loaded",
            font=("Segoe UI", 10),
            fg="#8b98a8",
            bg="#111820"
        )

        self.file_label.pack(
            anchor="w",
            padx=20
        )

        self.email_box = scrolledtext.ScrolledText(
            left,
            height=22,
            font=("Consolas", 10),
            bg="#080c10",
            fg="#dce6f2",
            insertbackground="white",
            relief="flat",
            wrap="word"
        )

        self.email_box.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=10
        )

        # -----------------------------------------------------
        # IMPORT
        # -----------------------------------------------------

        self.import_button = tk.Button(
            left,
            text="📂  IMPORT .EML EMAIL",
            command=self.import_email,
            font=("Segoe UI", 11, "bold"),
            bg="#1d6fff",
            fg="white",
            activebackground="#1557c7",
            relief="flat",
            pady=12
        )

        self.import_button.pack(
            fill="x",
            padx=20,
            pady=(5, 10)
        )

        self.scan_button = tk.Button(
            left,
            text="▶  ANALYZE EMAIL",
            command=self.analyze_loaded_email,
            font=("Segoe UI", 11, "bold"),
            bg="#18251f",
            fg="#42d392",
            activebackground="#24382e",
            relief="flat",
            pady=12,
            state="disabled"
        )

        self.scan_button.pack(
            fill="x",
            padx=20,
            pady=(0, 20)
        )

        # -----------------------------------------------------
        # RIGHT
        # -----------------------------------------------------

        right = tk.Frame(
            main,
            bg="#111820"
        )

        right.pack(
            side="right",
            fill="both",
            expand=True,
            padx=(10, 0)
        )

        tk.Label(
            right,
            text="SECURITY ASSESSMENT",
            font=("Segoe UI", 13, "bold"),
            fg="#ffffff",
            bg="#111820"
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 10)
        )

        self.risk_label = tk.Label(
            right,
            text="READY",
            font=("Segoe UI", 28, "bold"),
            fg="#42d392",
            bg="#111820"
        )

        self.risk_label.pack(
            pady=(10, 0)
        )

        self.score_label = tk.Label(
            right,
            text="-- / 100",
            font=("Segoe UI", 18),
            fg="#aab6c5",
            bg="#111820"
        )

        self.score_label.pack()

        self.canvas = tk.Canvas(
            right,
            height=30,
            bg="#080c10",
            highlightthickness=0
        )

        self.canvas.pack(
            fill="x",
            padx=30,
            pady=20
        )

        self.action_label = tk.Label(
            right,
            text="ACTION: —",
            font=("Segoe UI", 15, "bold"),
            fg="#ffffff",
            bg="#111820"
        )

        self.action_label.pack()

        # -----------------------------------------------------
        # EMAIL INFORMATION
        # -----------------------------------------------------

        self.metadata_label = tk.Label(
            right,
            text="No email loaded",
            justify="left",
            anchor="w",
            font=("Consolas", 9),
            fg="#8b98a8",
            bg="#111820"
        )

        self.metadata_label.pack(
            fill="x",
            padx=20,
            pady=(15, 5)
        )

        tk.Label(
            right,
            text="DETECTED INDICATORS",
            font=("Segoe UI", 11, "bold"),
            fg="#8b98a8",
            bg="#111820"
        ).pack(
            anchor="w",
            padx=20,
            pady=(10, 5)
        )

        self.findings_box = scrolledtext.ScrolledText(
            right,
            height=16,
            font=("Consolas", 10),
            bg="#080c10",
            fg="#dce6f2",
            relief="flat",
            state="disabled",
            wrap="word"
        )

        self.findings_box.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=(0, 20)
        )

        self.loaded_file = None

    # =========================================================
    # IMPORT EMAIL
    # =========================================================

    def import_email(self):

        file_path = filedialog.askopenfilename(
            title="Select an email",
            filetypes=[
                (
                    "Email files",
                    "*.eml"
                ),
                (
                    "All files",
                    "*.*"
                )
            ]
        )

        if not file_path:
            return

        try:

            email = self.analyzer.parser.parse_file(
                file_path
            )

            self.loaded_file = file_path

            self.file_label.config(
                text=file_path
            )

            self.email_box.delete(
                "1.0",
                tk.END
            )

            self.email_box.insert(
                tk.END,
                email["body"]
            )

            metadata = (
                f"FROM      : {email['sender']}\n"
                f"TO        : {email['recipient']}\n"
                f"SUBJECT   : {email['subject']}\n"
                f"ATTACHMENTS: {email['attachment_count']}"
            )

            self.metadata_label.config(
                text=metadata
            )

            self.scan_button.config(
                state="normal"
            )

            self.set_status(
                "● EMAIL LOADED",
                "#42d392"
            )

            self.reset_result()

        except Exception as error:

            messagebox.showerror(
                "MailScope",
                f"Could not read email:\n\n{error}"
            )

    # =========================================================
    # ANALYZE
    # =========================================================

    def analyze_loaded_email(self):

        if not self.loaded_file:
            return

        self.scan_button.config(
            state="disabled",
            text="SCANNING..."
        )

        self.import_button.config(
            state="disabled"
        )

        self.set_status(
            "● ANALYZING EMAIL",
            "#4da6ff"
        )

        thread = threading.Thread(
            target=self.run_analysis,
            daemon=True
        )

        thread.start()

    # =========================================================
    # ANALYSIS THREAD
    # =========================================================

    def run_analysis(self):

        try:

            result = self.analyzer.analyze_file(
                self.loaded_file
            )

            self.root.after(
                0,
                lambda: self.display_result(result)
            )

        except Exception as error:

            self.root.after(
                0,
                lambda: self.show_error(error)
            )

    # =========================================================
    # DISPLAY RESULT
    # =========================================================

    def display_result(self, result):

        security = result["security"]

        risk = security["severity"]
        score = security["risk_score"]

        if risk == "CRITICAL":

            color = "#ff4d4d"
            action = "BLOCK"

        elif risk == "HIGH":

            color = "#ff8c42"
            action = "WARN"

        elif risk == "MEDIUM":

            color = "#ffd166"
            action = "REVIEW"

        else:

            color = "#42d392"
            action = "ALLOW"

        self.risk_label.config(
            text=f"● {risk}",
            fg=color
        )

        self.score_label.config(
            text=f"{score} / 100"
        )

        self.action_label.config(
            text=f"ACTION: {action}",
            fg=color
        )

        # -----------------------------------------------------
        # RISK BAR
        # -----------------------------------------------------

        self.canvas.delete(
            "all"
        )

        width = self.canvas.winfo_width()

        if width < 10:
            width = 400

        filled = int(
            width * score / 100
        )

        self.canvas.create_rectangle(
            0,
            0,
            width,
            30,
            fill="#1b222b",
            outline=""
        )

        self.canvas.create_rectangle(
            0,
            0,
            filled,
            30,
            fill=color,
            outline=""
        )

        # -----------------------------------------------------
        # FINDINGS
        # -----------------------------------------------------

        self.findings_box.config(
            state="normal"
        )

        self.findings_box.delete(
            "1.0",
            tk.END
        )

        findings = security["findings"]

        if not findings:

            self.findings_box.insert(
                tk.END,
                "✓ NO THREATS DETECTED\n\n"
                "The email passed the current "
                "MailScope security checks."
            )

        else:

            for finding in findings:

                severity = finding.get(
                    "severity",
                    "INFO"
                )

                title = finding.get(
                    "title",
                    finding.get(
                        "type",
                        "Unknown"
                    )
                )

                message = finding.get(
                    "message",
                    ""
                )

                self.findings_box.insert(
                    tk.END,
                    f"[{severity}] {title}\n"
                )

                self.findings_box.insert(
                    tk.END,
                    f"    {message}\n\n"
                )

        self.findings_box.config(
            state="disabled"
        )

        self.set_status(
            f"● ANALYSIS COMPLETE — {risk}",
            color
        )

        self.scan_button.config(
            state="normal",
            text="▶  ANALYZE EMAIL"
        )

        self.import_button.config(
            state="normal"
        )

    # =========================================================
    # RESET
    # =========================================================

    def reset_result(self):

        self.risk_label.config(
            text="READY",
            fg="#42d392"
        )

        self.score_label.config(
            text="-- / 100"
        )

        self.action_label.config(
            text="ACTION: —",
            fg="#ffffff"
        )

        self.findings_box.config(
            state="normal"
        )

        self.findings_box.delete(
            "1.0",
            tk.END
        )

        self.findings_box.config(
            state="disabled"
        )

        self.canvas.delete(
            "all"
        )

    # =========================================================
    # ERROR
    # =========================================================

    def show_error(self, error):

        self.set_status(
            "● ANALYSIS ERROR",
            "#ff4d4d"
        )

        messagebox.showerror(
            "MailScope",
            str(error)
        )

        self.scan_button.config(
            state="normal",
            text="▶  ANALYZE EMAIL"
        )

        self.import_button.config(
            state="normal"
        )

    # =========================================================
    # STATUS
    # =========================================================

    def set_status(self, text, color):

        self.status_label.config(
            text=text,
            fg=color
        )


# =============================================================
# START
# =============================================================

if __name__ == "__main__":

    root = tk.Tk()

    MailScopeDashboard(
        root
    )

    root.mainloop()