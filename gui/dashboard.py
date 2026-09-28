import tkinter as tk
from tkinter import scrolledtext
import os
import time
import threading


# ============================================================
# MAILSCOPE
# AUTONOMOUS SECURITY DASHBOARD
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

INBOX_DIR = os.path.join(
    BASE_DIR,
    "data",
    "inbox"
)

INCIDENT_DIR = os.path.join(
    INBOX_DIR,
    "incidents"
)

PROCESSED_DIR = os.path.join(
    INBOX_DIR,
    "processed"
)


class MailScopeDashboard:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "MailScope — Autonomous Email Security"
        )

        self.root.geometry(
            "1250x780"
        )

        self.root.minsize(
            1050,
            680
        )

        self.root.configure(
            bg="#0b0f14"
        )

        self.last_incidents = set()
        self.last_processed = set()

        self.total_threats = 0
        self.total_safe = 0

        self.build_interface()

        self.start_monitor()

    # ========================================================
    # INTERFACE
    # ========================================================

    def build_interface(self):

        # ----------------------------------------------------
        # HEADER
        # ----------------------------------------------------

        header = tk.Frame(
            self.root,
            bg="#111820",
            height=80
        )

        header.pack(
            fill="x"
        )

        header.pack_propagate(
            False
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
            text="AUTONOMOUS EMAIL SECURITY AGENT",
            font=("Segoe UI", 10),
            fg="#8b98a8",
            bg="#111820"
        ).pack(
            side="left"
        )

        self.status_label = tk.Label(
            header,
            text="● PROTECTION ACTIVE",
            font=("Segoe UI", 11, "bold"),
            fg="#42d392",
            bg="#111820"
        )

        self.status_label.pack(
            side="right",
            padx=30
        )

        # ----------------------------------------------------
        # MAIN
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # STAT CARDS
        # ----------------------------------------------------

        stats = tk.Frame(
            main,
            bg="#0b0f14"
        )

        stats.pack(
            fill="x",
            pady=(0, 15)
        )

        self.create_stat_card(
            stats,
            "EMAILS PROCESSED",
            "0",
            0
        )

        self.threat_value = self.create_stat_card(
            stats,
            "THREATS ISOLATED",
            "0",
            1
        )

        self.safe_value = self.create_stat_card(
            stats,
            "SAFE EMAILS",
            "0",
            2
        )

        self.create_stat_card(
            stats,
            "ENGINE",
            "ACTIVE",
            3
        )

        # ----------------------------------------------------
        # LEFT PANEL
        # ----------------------------------------------------

        left = tk.Frame(
            main,
            bg="#111820"
        )

        left.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 8)
        )

        tk.Label(
            left,
            text="LATEST SECURITY EVENT",
            font=("Segoe UI", 13, "bold"),
            fg="#ffffff",
            bg="#111820"
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 10)
        )

        self.event_label = tk.Label(
            left,
            text="WAITING FOR EMAIL...",
            font=("Segoe UI", 22, "bold"),
            fg="#42d392",
            bg="#111820"
        )

        self.event_label.pack(
            pady=(15, 5)
        )

        self.event_score = tk.Label(
            left,
            text="Risk Score: -- / 100",
            font=("Segoe UI", 15),
            fg="#aab6c5",
            bg="#111820"
        )

        self.event_score.pack()

        self.action_label = tk.Label(
            left,
            text="ACTION: WAITING",
            font=("Segoe UI", 14, "bold"),
            fg="#ffffff",
            bg="#111820"
        )

        self.action_label.pack(
            pady=15
        )

        self.event_box = scrolledtext.ScrolledText(
            left,
            height=18,
            font=("Consolas", 10),
            bg="#080c10",
            fg="#dce6f2",
            relief="flat",
            wrap="word",
            state="disabled"
        )

        self.event_box.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=(5, 20)
        )

        # ----------------------------------------------------
        # RIGHT PANEL
        # ----------------------------------------------------

        right = tk.Frame(
            main,
            bg="#111820"
        )

        right.pack(
            side="right",
            fill="both",
            expand=True,
            padx=(8, 0)
        )

        tk.Label(
            right,
            text="INCIDENT MONITOR",
            font=("Segoe UI", 13, "bold"),
            fg="#ffffff",
            bg="#111820"
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 10)
        )

        self.incident_box = scrolledtext.ScrolledText(
            right,
            height=18,
            font=("Consolas", 10),
            bg="#080c10",
            fg="#dce6f2",
            relief="flat",
            wrap="word",
            state="disabled"
        )

        self.incident_box.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=(5, 10)
        )

        tk.Label(
            right,
            text="PROCESSED SAFE EMAILS",
            font=("Segoe UI", 11, "bold"),
            fg="#8b98a8",
            bg="#111820"
        ).pack(
            anchor="w",
            padx=20,
            pady=(5, 5)
        )

        self.safe_box = scrolledtext.ScrolledText(
            right,
            height=7,
            font=("Consolas", 9),
            bg="#080c10",
            fg="#42d392",
            relief="flat",
            wrap="word",
            state="disabled"
        )

        self.safe_box.pack(
            fill="x",
            padx=20,
            pady=(0, 20)
        )

    # ========================================================
    # STAT CARD
    # ========================================================

    def create_stat_card(
        self,
        parent,
        title,
        value,
        column
    ):

        card = tk.Frame(
            parent,
            bg="#111820",
            height=90
        )

        card.grid(
            row=0,
            column=column,
            sticky="nsew",
            padx=5
        )

        parent.grid_columnconfigure(
            column,
            weight=1
        )

        tk.Label(
            card,
            text=title,
            font=("Segoe UI", 9, "bold"),
            fg="#8b98a8",
            bg="#111820"
        ).pack(
            pady=(15, 0)
        )

        value_label = tk.Label(
            card,
            text=value,
            font=("Segoe UI", 20, "bold"),
            fg="#ffffff",
            bg="#111820"
        )

        value_label.pack(
            pady=(2, 10)
        )

        return value_label

    # ========================================================
    # MONITOR
    # ========================================================

    def start_monitor(self):

        thread = threading.Thread(
            target=self.monitor_loop,
            daemon=True
        )

        thread.start()

    # ========================================================
    # MONITOR LOOP
    # ========================================================

    def monitor_loop(self):

        while True:

            try:

                incidents = self.get_files(
                    INCIDENT_DIR
                )

                processed = self.get_files(
                    PROCESSED_DIR
                )

                self.root.after(
                    0,
                    lambda i=incidents, p=processed:
                    self.update_dashboard(i, p)
                )

            except Exception as error:

                print(
                    f"[GUI MONITOR ERROR] {error}"
                )

            time.sleep(2)

    # ========================================================
    # FILE DISCOVERY
    # ========================================================

    def get_files(self, directory):

        if not os.path.exists(directory):

            os.makedirs(
                directory,
                exist_ok=True
            )

            return []

        files = []

        for filename in os.listdir(directory):

            path = os.path.join(
                directory,
                filename
            )

            if os.path.isfile(path):

                files.append(
                    (
                        filename,
                        os.path.getmtime(path)
                    )
                )

        files.sort(
            key=lambda x: x[1],
            reverse=True
        )

        return files

    # ========================================================
    # DASHBOARD UPDATE
    # ========================================================

    def update_dashboard(
        self,
        incidents,
        processed
    ):

        incident_names = {
            item[0]
            for item in incidents
        }

        processed_names = {
            item[0]
            for item in processed
        }

        # -----------------------------------------------
        # COUNTERS
        # -----------------------------------------------

        self.total_threats = len(
            incidents
        )

        self.total_safe = len(
            processed
        )

        total = (
            self.total_threats
            +
            self.total_safe
        )

        self.threat_value.config(
            text=str(
                self.total_threats
            )
        )

        self.safe_value.config(
            text=str(
                self.total_safe
            )
        )

        # -----------------------------------------------
        # INCIDENT LIST
        # -----------------------------------------------

        self.set_text(
            self.incident_box,
            self.format_incidents(
                incidents
            )
        )

        # -----------------------------------------------
        # SAFE LIST
        # -----------------------------------------------

        self.set_text(
            self.safe_box,
            self.format_safe(
                processed
            )
        )

        # -----------------------------------------------
        # NEW THREAT
        # -----------------------------------------------

        new_incidents = (
            incident_names
            -
            self.last_incidents
        )

        if new_incidents:

            newest = incidents[0][0]

            self.show_event(
                newest,
                True,
                len(incidents)
            )

        elif (
            not self.last_incidents
            and incidents
        ):

            newest = incidents[0][0]

            self.show_event(
                newest,
                True,
                len(incidents)
            )

        # -----------------------------------------------
        # NEW SAFE EMAIL
        # -----------------------------------------------

        elif (
            processed_names
            -
            self.last_processed
        ):

            newest = processed[0][0]

            self.show_event(
                newest,
                False,
                len(incidents)
            )

        elif (
            not self.last_processed
            and processed
            and not incidents
        ):

            newest = processed[0][0]

            self.show_event(
                newest,
                False,
                0
            )

        self.last_incidents = incident_names
        self.last_processed = processed_names

    # ========================================================
    # SHOW EVENT
    # ========================================================

    def show_event(
        self,
        filename,
        threat,
        incident_count
    ):

        if threat:

            self.event_label.config(
                text="● CRITICAL THREAT",
                fg="#ff4d4d"
            )

            self.event_score.config(
                text="Risk Score: HIGH / CRITICAL",
                fg="#ff4d4d"
            )

            self.action_label.config(
                text="ACTION: EMAIL ISOLATED",
                fg="#ff4d4d"
            )

            message = (
                "MAILSCOPE AUTONOMOUS RESPONSE\n"
                "----------------------------------------\n\n"
                f"Incident: {filename}\n\n"
                "Threat detected by the autonomous\n"
                "email security pipeline.\n\n"
                "The email has been moved into the\n"
                "incident isolation directory.\n\n"
                "STATUS: BLOCKED / ISOLATED"
            )

        else:

            self.event_label.config(
                text="● SAFE EMAIL",
                fg="#42d392"
            )

            self.event_score.config(
                text="Risk Score: 0 / 100",
                fg="#42d392"
            )

            self.action_label.config(
                text="ACTION: EMAIL ARCHIVED",
                fg="#42d392"
            )

            message = (
                "MAILSCOPE SECURITY RESPONSE\n"
                "----------------------------------------\n\n"
                f"Email: {filename}\n\n"
                "No threat indicators were detected.\n\n"
                "The email passed the security checks\n"
                "and was moved to processed storage.\n\n"
                "STATUS: SAFE / ALLOWED"
            )

        self.set_text(
            self.event_box,
            message
        )

    # ========================================================
    # FORMAT INCIDENTS
    # ========================================================

    def format_incidents(
        self,
        incidents
    ):

        if not incidents:

            return (
                "No isolated incidents.\n\n"
                "MailScope is monitoring the inbox."
            )

        lines = []

        for filename, timestamp in incidents:

            event_time = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(timestamp)
            )

            lines.append(
                "[THREAT ISOLATED]"
            )

            lines.append(
                f"File      : {filename}"
            )

            lines.append(
                f"Detected  : {event_time}"
            )

            lines.append(
                "Action    : BLOCK / ISOLATE"
            )

            lines.append(
                ""
            )

        return "\n".join(
            lines
        )

    # ========================================================
    # FORMAT SAFE EMAILS
    # ========================================================

    def format_safe(
        self,
        processed
    ):

        if not processed:

            return (
                "No processed safe emails."
            )

        lines = []

        for filename, timestamp in processed:

            event_time = time.strftime(
                "%H:%M:%S",
                time.localtime(timestamp)
            )

            lines.append(
                f"[SAFE] {filename}  {event_time}"
            )

        return "\n".join(
            lines
        )

    # ========================================================
    # TEXT HELPER
    # ========================================================

    def set_text(
        self,
        widget,
        text
    ):

        widget.config(
            state="normal"
        )

        widget.delete(
            "1.0",
            tk.END
        )

        widget.insert(
            tk.END,
            text
        )

        widget.config(
            state="disabled"
        )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    root = tk.Tk()

    MailScopeDashboard(
        root
    )

    root.mainloop()