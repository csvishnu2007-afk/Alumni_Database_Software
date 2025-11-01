import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import hashlib
import re
from datetime import datetime
import os
import webbrowser

# --- Third-Party Library Imports ---
from tkcalendar import DateEntry
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


# ==============================================================================
# SECTION 1: STYLING AND CONFIGURATION
# ==============================================================================

COLORS = {
    "bg": "#1e1e1e",
    "frame_bg": "#2d2d2d",
    "text_fg": "#e0e0e0",
    "accent": "#007bff",
    "accent_fg": "#ffffff",
    "entry_bg": "#3c3c3c",
    "entry_fg": "#e0e0e0",
    "entry_border": "#555555",
    "hover": "#0056b3",
    "sidebar_active": "#007bff",
    "sidebar_fg": "#d0d0d0",
    "danger": "#dc3545",
    "danger_hover": "#c82333",
    "success": "#28a745"
}

FONTS = {
    "title": ("Segoe UI", 24, "bold"),
    "header": ("Segoe UI", 16, "bold"),
    "body_bold": ("Segoe UI", 11, "bold"),
    "body": ("Segoe UI", 11),
    "small": ("Segoe UI", 9),
    "small_bold": ("Segoe UI", 9, "bold")
}

def setup_ttk_styles():
    """Configures global styles for ttk widgets for a consistent modern look."""
    style = ttk.Style()
    style.theme_use("default")

    # --- Treeview Style ---
    style.configure("Treeview",
                    background=COLORS["frame_bg"],
                    foreground=COLORS["text_fg"],
                    rowheight=28,
                    fieldbackground=COLORS["frame_bg"],
                    font=FONTS["body"])
    style.map('Treeview', background=[('selected', COLORS["accent"])])
    style.configure("Treeview.Heading",
                    font=FONTS["body_bold"],
                    background=COLORS["bg"],
                    foreground=COLORS["text_fg"],
                    relief="flat")
    style.map("Treeview.Heading", background=[('active', COLORS["bg"])])

    # --- Combobox Style ---
    style.map('TCombobox', fieldbackground=[('readonly', COLORS["entry_bg"])])
    style.map('TCombobox', selectbackground=[('readonly', COLORS["entry_bg"])])
    style.map('TCombobox', selectforeground=[('readonly', COLORS["entry_fg"])])
    style.configure('TCombobox',
                    foreground=COLORS["entry_fg"],
                    background=COLORS["entry_bg"],
                    arrowcolor=COLORS["text_fg"],
                    bordercolor=COLORS["entry_border"],
                    lightcolor=COLORS["entry_bg"],
                    darkcolor=COLORS["entry_bg"])

    # --- Scrollbar Style ---
    style.configure("Vertical.TScrollbar",
                    background=COLORS["bg"],
                    troughcolor=COLORS["frame_bg"],
                    bordercolor=COLORS["bg"],
                    arrowcolor=COLORS["text_fg"])

    # --- Separator Style ---
    style.configure("TSeparator", background=COLORS["entry_border"])

    # --- LabelFrame Style ---
    style.configure("TLabelframe",
                    background=COLORS["frame_bg"],
                    bordercolor=COLORS["entry_border"])
    style.configure("TLabelframe.Label",
                    background=COLORS["frame_bg"],
                    foreground=COLORS["text_fg"],
                    font=FONTS["body_bold"])


# ==============================================================================
# SECTION 2: DATABASE SETUP
# ==============================================================================

DATABASE_NAME = "alumniconnect.db"

def get_db_connection():
    """Establishes and returns a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row # Makes rows accessible by column name
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def initialize_database():
    """Creates all necessary tables for the application if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL, salt TEXT NOT NULL, roles TEXT NOT NULL)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS institutions (code TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, admin TEXT, FOREIGN KEY(admin) REFERENCES users(username) ON DELETE SET NULL)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, year TEXT, institution_code TEXT, UNIQUE(username, institution_code), FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE, FOREIGN KEY(institution_code) REFERENCES institutions(code) ON DELETE CASCADE)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS alumni (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, year TEXT, institution_code TEXT, UNIQUE(username, institution_code), FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE, FOREIGN KEY(institution_code) REFERENCES institutions(code) ON DELETE CASCADE)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, institution_code TEXT, target_role TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(institution_code) REFERENCES institutions(code) ON DELETE CASCADE)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, institution_code TEXT, title TEXT, description TEXT, event_date TEXT, target_role TEXT, FOREIGN KEY(institution_code) REFERENCES institutions(code) ON DELETE CASCADE)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS shoutbox (id INTEGER PRIMARY KEY AUTOINCREMENT, institution_code TEXT, username TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(institution_code) REFERENCES institutions(code) ON DELETE CASCADE, FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS profiles (username TEXT PRIMARY KEY, full_name TEXT, major TEXT, graduation_year INTEGER, current_company TEXT, job_title TEXT, linkedin_url TEXT, bio TEXT, FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, institution_code TEXT NOT NULL, title TEXT NOT NULL, company TEXT NOT NULL, location TEXT, description TEXT, apply_link TEXT, post_date DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(institution_code) REFERENCES institutions(code) ON DELETE CASCADE)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS alumni_sub_roles (username TEXT PRIMARY KEY, sub_roles TEXT, FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE)""")

    conn.commit()
    conn.close()
    print("Database initialized successfully.")


# ==============================================================================
# SECTION 3: UTILITIES AND HELPER CLASSES/FUNCTIONS
# ==============================================================================

def hash_password(password):
    """Hashes a password with a secure random salt."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest()
    salted_password = password + salt
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed_password, salt

def verify_password(stored_password, stored_salt, provided_password):
    """Verifies a provided password against a stored hash and salt."""
    salted_password = provided_password + stored_salt
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed_password == stored_password

def on_enter(e): e.widget['background'] = COLORS['hover']
def on_leave(e): e.widget['background'] = COLORS['accent']
def on_enter_danger(e): e.widget['background'] = COLORS['danger_hover']
def on_leave_danger(e): e.widget['background'] = COLORS['danger']

class ToolTip:
    """Creates a tooltip for a given widget."""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event):
        if self.tooltip_window or not self.text:
            return
        x, y, _, _ = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + self.widget.winfo_rooty() + 25
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify='left',
                       background="#3c3c3c", relief='solid', borderwidth=1,
                       font=FONTS['small'], fg=COLORS['text_fg'], padx=8, pady=5)
        label.pack(ipadx=1)

    def hide_tooltip(self, event):
        if self.tooltip_window:
            self.tooltip_window.destroy()
        self.tooltip_window = None

class ScrollableFrame(ttk.Frame):
    """A scrollable frame component for long content."""
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.canvas = tk.Canvas(self, bg=COLORS["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview, style="Vertical.TScrollbar")
        self.scrollable_frame = tk.Frame(self.canvas, bg=COLORS["bg"])

        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.bind("<Configure>", self.on_canvas_configure)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_window, width=event.width)

class SidebarButton(tk.Frame):
    """A custom button for the sidebar navigation with an icon and text."""
    def __init__(self, parent, text, icon_path, command):
        super().__init__(parent, bg=COLORS["frame_bg"])
        self.command = command
        self.is_active = False
        self.icon_image = None

        try:
            self.icon_image = ImageTk.PhotoImage(Image.open(icon_path).resize((24, 24), Image.LANCZOS))
        except FileNotFoundError:
            print(f"Warning: Icon not found at '{icon_path}'.")
        except Exception as e:
            print(f"Error loading icon '{icon_path}': {e}")

        self.icon_label = tk.Label(self, image=self.icon_image, bg=COLORS["frame_bg"])
        if self.icon_image:
            self.icon_label.pack(side="left", padx=(15, 10), pady=10)

        self.text_label = tk.Label(self, text=text, font=FONTS["body"], bg=COLORS["frame_bg"], fg=COLORS["sidebar_fg"])
        self.text_label.pack(side="left", padx=15)

        self.bind_events()

    def bind_events(self):
        for widget in [self, self.icon_label, self.text_label]:
            widget.bind("<Button-1>", lambda e: self.command())
            widget.bind("<Enter>", self.on_enter)
            widget.bind("<Leave>", self.on_leave)

    def set_active(self, active=True):
        self.is_active = active
        bg_color = COLORS["sidebar_active"] if active else COLORS["frame_bg"]
        fg_color = COLORS["accent_fg"] if active else COLORS["sidebar_fg"]

        self.configure(bg=bg_color)
        self.icon_label.configure(bg=bg_color)
        self.text_label.configure(bg=bg_color, fg=fg_color)

    def on_enter(self, event):
        if not self.is_active:
            bg_color = COLORS["entry_bg"]
            self.configure(bg=bg_color)
            self.icon_label.configure(bg=bg_color)
            self.text_label.configure(bg=bg_color)

    def on_leave(self, event):
        if not self.is_active:
            bg_color = COLORS["frame_bg"]
            self.configure(bg=bg_color)
            self.icon_label.configure(bg=bg_color)
            self.text_label.configure(bg=bg_color)


# ==============================================================================
# SECTION 4: AUTHENTICATION FRAMES (LOGIN & SIGNUP)
# ==============================================================================

class LoginFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLORS["bg"])
        self.controller = controller

        main_frame = tk.Frame(self, bg=COLORS["bg"])
        main_frame.pack(expand=True)
        center_frame = tk.Frame(main_frame, bg=COLORS["frame_bg"], padx=40, pady=40, relief="solid", bd=1)
        center_frame.pack()

        tk.Label(center_frame, text="Welcome Back", font=FONTS["title"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).pack(pady=(0, 10))
        tk.Label(center_frame, text="Sign in to Alumni Connect", font=FONTS["body"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).pack(pady=(0, 30))

        tk.Label(center_frame, text="Username", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).pack(anchor="w")
        self.username_entry = tk.Entry(center_frame, bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], font=FONTS["body"], width=35, relief="solid", bd=1, highlightthickness=1, highlightbackground=COLORS["entry_border"])
        self.username_entry.pack(pady=(5, 15), ipady=8)

        tk.Label(center_frame, text="Password", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).pack(anchor="w")
        self.password_entry = tk.Entry(center_frame, show="*", bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], font=FONTS["body"], width=35, relief="solid", bd=1, highlightthickness=1, highlightbackground=COLORS["entry_border"])
        self.password_entry.pack(pady=(5, 30), ipady=8)
        self.password_entry.bind("<Return>", self.validate_login)

        login_btn = tk.Button(center_frame, text="Login", command=self.validate_login, bg=COLORS["accent"], fg=COLORS["accent_fg"], font=FONTS["body_bold"], width=30, relief="flat", pady=8, activebackground=COLORS["hover"], activeforeground=COLORS["accent_fg"])
        login_btn.pack(pady=(0, 15))

        tk.Button(center_frame, text="Create an Account", command=lambda: controller.show_frame("SignupFrame"), bg=COLORS["frame_bg"], fg=COLORS["accent"], font=FONTS["small"], relief="flat", activebackground=COLORS["frame_bg"], activeforeground=COLORS["hover"]).pack()

    def validate_login(self, event=None):
        username = self.username_entry.get()
        password = self.password_entry.get()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password, salt, roles FROM users WHERE username=?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result and verify_password(result['password'], result['salt'], password):
            roles_list = result['roles'].split(",")
            messagebox.showinfo("Login Success", f"Welcome, {username}!")
            self.controller.show_dashboard(username, roles_list)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def clear_fields(self):
        self.username_entry.delete(0, 'end')
        self.password_entry.delete(0, 'end')

class SignupFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=COLORS["bg"])
        self.controller = controller

        scroll_frame = ScrollableFrame(self)
        scroll_frame.pack(fill="both", expand=True)
        container = scroll_frame.scrollable_frame

        centering_frame = tk.Frame(container, bg=COLORS["bg"])
        centering_frame.pack(expand=True)
        content_frame = tk.Frame(centering_frame, bg=COLORS["frame_bg"], padx=40, pady=40, relief="solid", bd=1)
        content_frame.pack(pady=20)

        tk.Label(content_frame, text="Create Your Account", font=FONTS["title"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).pack(pady=10)
        tk.Label(content_frame, text="New Username", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).pack(anchor="w", pady=(20,0))
        self.new_username_entry = tk.Entry(content_frame, bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], font=FONTS["body"], width=40, relief="solid", bd=1)
        self.new_username_entry.pack(pady=5, ipady=8)
        tk.Label(content_frame, text="New Password", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).pack(anchor="w", pady=(10,0))
        self.new_password_entry = tk.Entry(content_frame, show="*", bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], font=FONTS["body"], width=40, relief="solid", bd=1)
        self.new_password_entry.pack(pady=5, ipady=8)

        tk.Label(content_frame, text="Select Your Role(s)", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).pack(pady=(20, 5), anchor="w")
        self.role_vars = {"Administrator": tk.IntVar(), "Student": tk.IntVar(), "Alumni": tk.IntVar()}
        for role, var in self.role_vars.items():
            tk.Checkbutton(content_frame, text=role, variable=var, bg=COLORS["frame_bg"], fg=COLORS["text_fg"], selectcolor=COLORS["entry_bg"], activebackground=COLORS["frame_bg"], activeforeground=COLORS["text_fg"], font=FONTS["body"], command=self.toggle_role_fields).pack(anchor="w")

        self.fields_frame = tk.Frame(content_frame, bg=COLORS["frame_bg"])
        self.fields_frame.pack(pady=10, fill="x")

        self.admin_inst_name = tk.Entry(self.fields_frame, font=FONTS["body"], width=40, relief="solid", bd=1, bg=COLORS["entry_bg"], fg=COLORS["entry_fg"])
        self.admin_inst_code = tk.Entry(self.fields_frame, font=FONTS["body"], width=40, relief="solid", bd=1, bg=COLORS["entry_bg"], fg=COLORS["entry_fg"])

        self.student_inst_combo = ttk.Combobox(self.fields_frame, font=FONTS["body"], width=38, state="readonly")
        self.student_year = tk.Entry(self.fields_frame, font=FONTS["body"], width=40, relief="solid", bd=1, bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], validate="key", validatecommand=(self.register(self.validate_numeric), '%P'))

        self.alumni_inst_combo = ttk.Combobox(self.fields_frame, font=FONTS["body"], width=38, state="readonly")
        self.alumni_year = tk.Entry(self.fields_frame, font=FONTS["body"], width=40, relief="solid", bd=1, bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], validate="key", validatecommand=(self.register(self.validate_numeric), '%P'))

        self.toggle_role_fields()

        signup_btn = tk.Button(content_frame, text="Create Account", command=self.register_user, bg=COLORS["accent"], fg=COLORS["accent_fg"], font=FONTS["body_bold"], width=35, relief="flat", pady=8)
        signup_btn.pack(pady=20)
        signup_btn.bind("<Enter>", on_enter)
        signup_btn.bind("<Leave>", on_leave)
        tk.Button(content_frame, text="Back to Login", command=lambda: controller.show_frame("LoginFrame"), bg=COLORS["frame_bg"], fg=COLORS["accent"], font=FONTS["small"], relief="flat").pack()

    def validate_numeric(self, P):
        return (P.isdigit() and len(P) <= 4) or P == ""

    def load_institutions(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name, code FROM institutions")
        self.institutions = {row['name']: row['code'] for row in cursor.fetchall()}
        conn.close()
        inst_names = list(self.institutions.keys())
        self.student_inst_combo['values'] = inst_names
        self.alumni_inst_combo['values'] = inst_names

    def toggle_role_fields(self):
        for widget in self.fields_frame.winfo_children():
            widget.pack_forget()
        if self.role_vars["Administrator"].get():
            tk.Label(self.fields_frame, text="Create Institution Name", font=FONTS["body"], bg=COLORS["frame_bg"], fg=COLORS["text_fg"]).pack(anchor="w")
            self.admin_inst_name.pack(ipady=8, pady=(2, 8), fill='x')
            tk.Label(self.fields_frame, text="Set a Unique Institution Code", font=FONTS["body"], bg=COLORS["frame_bg"], fg=COLORS["text_fg"]).pack(anchor="w")
            self.admin_inst_code.pack(ipady=8, pady=(2, 8), fill='x')
        if self.role_vars["Student"].get():
            tk.Label(self.fields_frame, text="Select Institution", font=FONTS["body"], bg=COLORS["frame_bg"], fg=COLORS["text_fg"]).pack(anchor="w")
            self.student_inst_combo.pack(ipady=5, pady=(2, 8), fill='x')
            tk.Label(self.fields_frame, text="Year of Joining (e.g., 2023)", font=FONTS["body"], bg=COLORS["frame_bg"], fg=COLORS["text_fg"]).pack(anchor="w")
            self.student_year.pack(ipady=8, pady=(2, 8), fill='x')
        if self.role_vars["Alumni"].get():
            tk.Label(self.fields_frame, text="Select Institution", font=FONTS["body"], bg=COLORS["frame_bg"], fg=COLORS["text_fg"]).pack(anchor="w")
            self.alumni_inst_combo.pack(ipady=5, pady=(2, 8), fill='x')
            tk.Label(self.fields_frame, text="Year of Joining (e.g., 2019)", font=FONTS["body"], bg=COLORS["frame_bg"], fg=COLORS["text_fg"]).pack(anchor="w")
            self.alumni_year.pack(ipady=8, pady=(2, 8), fill='x')

    def register_user(self):
        new_user = self.new_username_entry.get().strip()
        new_pass = self.new_password_entry.get()
        selected_roles = [role for role, var in self.role_vars.items() if var.get()]

        if not re.match("^[a-zA-Z0-9_]{3,20}$", new_user):
            messagebox.showerror("Error", "Username must be 3-20 characters long and can only contain letters, numbers, and underscores.")
            return
        if len(new_pass) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long.")
            return
        if not selected_roles:
            messagebox.showerror("Error", "At least one role must be selected.")
            return

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM users WHERE username=?", (new_user,))
            if cursor.fetchone():
                messagebox.showerror("Error", "Username already exists.")
                return

            hashed_pass, salt = hash_password(new_pass)
            cursor.execute("INSERT INTO users (username, password, salt, roles) VALUES (?, ?, ?, ?)", (new_user, hashed_pass, salt, ",".join(selected_roles)))
            cursor.execute("INSERT OR IGNORE INTO profiles (username) VALUES (?)", (new_user,))

            if "Administrator" in selected_roles:
                inst_name = self.admin_inst_name.get().strip()
                inst_code = self.admin_inst_code.get().strip()
                if not inst_name or not inst_code: raise ValueError("Institution Name and Code are required for Administrators.")
                cursor.execute("SELECT * FROM institutions WHERE code=? OR name=?", (inst_code, inst_name))
                if cursor.fetchone(): raise ValueError("Institution Code or Name is already in use.")
                cursor.execute("INSERT INTO institutions (code, name, admin) VALUES (?, ?, ?)", (inst_code, inst_name, new_user))

            if "Student" in selected_roles:
                inst_name = self.student_inst_combo.get()
                year = self.student_year.get()
                if not inst_name or not year: raise ValueError("Institution and Year are required for Students.")
                inst_code = self.institutions[inst_name]
                cursor.execute("INSERT INTO students (username, year, institution_code) VALUES (?, ?, ?)", (new_user, year, inst_code))

            if "Alumni" in selected_roles:
                inst_name = self.alumni_inst_combo.get()
                year = self.alumni_year.get()
                if not inst_name or not year: raise ValueError("Institution and Year are required for Alumni.")
                inst_code = self.institutions[inst_name]
                cursor.execute("INSERT INTO alumni (username, year, institution_code) VALUES (?, ?, ?)", (new_user, year, inst_code))

            conn.commit()
            messagebox.showinfo("Success", "Account created successfully! Please log in.")
            self.new_username_entry.delete(0, 'end')
            self.new_password_entry.delete(0, 'end')
            self.controller.show_frame("LoginFrame")
        except ValueError as e:
            conn.rollback()
            messagebox.showerror("Registration Error", str(e))
        except KeyError:
            conn.rollback()
            messagebox.showerror("Registration Error", "Please select a valid institution from the list.")
        except Exception as e:
            conn.rollback()
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
        finally:
            if conn:
                conn.close()


# ==============================================================================
# SECTION 5: USER DASHBOARD AND SUB-PAGES
# ==============================================================================

class UserProfilePage(tk.Frame):
    def __init__(self, parent, dashboard):
        super().__init__(parent, bg=COLORS["bg"])
        self.dashboard = dashboard
        self.username = dashboard.username

        self.full_name_var = tk.StringVar()
        self.major_var = tk.StringVar()
        self.grad_year_var = tk.StringVar()
        self.company_var = tk.StringVar()
        self.job_title_var = tk.StringVar()
        self.linkedin_var = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        container = ScrollableFrame(self)
        container.pack(fill="both", expand=True, padx=30, pady=20)
        frame = container.scrollable_frame

        tk.Label(frame, text="My Profile", font=FONTS["title"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", pady=(0, 20))

        details_frame = tk.Frame(frame, bg=COLORS["frame_bg"], padx=30, pady=30)
        details_frame.pack(fill="x", pady=10)

        tk.Label(details_frame, text="Personal & Professional Information", font=FONTS["header"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0,15))

        fields = {
            "Full Name:": self.full_name_var, "Major/Field of Study:": self.major_var,
            "Graduation Year:": self.grad_year_var, "Current Company:": self.company_var,
            "Job Title:": self.job_title_var, "LinkedIn Profile URL:": self.linkedin_var,
        }

        self.entries = {}
        for i, (label, var) in enumerate(fields.items(), start=1):
            tk.Label(details_frame, text=label, font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).grid(row=i, column=0, sticky="w", padx=5, pady=8)
            entry = tk.Entry(details_frame, textvariable=var, font=FONTS["body"], bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], width=50, relief="solid", bd=1)
            entry.grid(row=i, column=1, sticky="w", padx=5, pady=8, ipady=4)
            self.entries[label] = entry

        tk.Label(details_frame, text="Bio:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).grid(row=len(fields)+1, column=0, sticky="nw", padx=5, pady=8)
        self.bio_text = tk.Text(details_frame, font=FONTS["body"], bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], width=50, height=5, relief="solid", bd=1, wrap="word")
        self.bio_text.grid(row=len(fields)+1, column=1, sticky="w", padx=5, pady=8)

        save_btn = tk.Button(details_frame, text="Save Changes", command=self.save_profile, bg=COLORS["accent"], fg=COLORS["accent_fg"], font=FONTS["body_bold"], relief="flat", padx=15, pady=5)
        save_btn.grid(row=len(fields)+2, column=1, sticky="e", pady=20)
        save_btn.bind("<Enter>", on_enter)
        save_btn.bind("<Leave>", on_leave)

        pw_frame = tk.Frame(frame, bg=COLORS["frame_bg"], padx=30, pady=30)
        pw_frame.pack(fill="x", pady=20)

        tk.Label(pw_frame, text="Change Password", font=FONTS["header"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0,15))

        tk.Label(pw_frame, text="New Password:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).grid(row=1, column=0, sticky="w", padx=5, pady=8)
        self.new_pass_entry = tk.Entry(pw_frame, show="*", font=FONTS["body"], bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], width=40, relief="solid", bd=1)
        self.new_pass_entry.grid(row=1, column=1, sticky="w", padx=5, pady=8, ipady=4)

        tk.Label(pw_frame, text="Confirm New Password:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).grid(row=2, column=0, sticky="w", padx=5, pady=8)
        self.confirm_pass_entry = tk.Entry(pw_frame, show="*", font=FONTS["body"], bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], width=40, relief="solid", bd=1)
        self.confirm_pass_entry.grid(row=2, column=1, sticky="w", padx=5, pady=8, ipady=4)

        change_pass_btn = tk.Button(pw_frame, text="Update Password", command=self.update_password, bg=COLORS["danger"], fg=COLORS["accent_fg"], font=FONTS["body_bold"], relief="flat", padx=15, pady=5)
        change_pass_btn.grid(row=3, column=1, sticky="e", pady=20)
        change_pass_btn.bind("<Enter>", on_enter_danger)
        change_pass_btn.bind("<Leave>", on_leave_danger)

    def refresh_data(self):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT full_name, major, graduation_year, current_company, job_title, linkedin_url, bio FROM profiles WHERE username=?", (self.username,))
            profile_data = cursor.fetchone()

            if profile_data:
                self.full_name_var.set(profile_data['full_name'] or "")
                self.major_var.set(profile_data['major'] or "")
                self.grad_year_var.set(str(profile_data['graduation_year'] or ""))
                self.company_var.set(profile_data['current_company'] or "")
                self.job_title_var.set(profile_data['job_title'] or "")
                self.linkedin_var.set(profile_data['linkedin_url'] or "")
                self.bio_text.delete("1.0", "end")
                self.bio_text.insert("1.0", profile_data['bio'] or "")
        finally:
            conn.close()

    def save_profile(self):
        grad_year = self.grad_year_var.get()
        if grad_year and not grad_year.isdigit():
            messagebox.showerror("Invalid Input", "Graduation year must be a number.", parent=self)
            return

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE profiles SET
                full_name=?, major=?, graduation_year=?, current_company=?, job_title=?, linkedin_url=?, bio=?
                WHERE username=?
            """, (
                self.full_name_var.get(), self.major_var.get(),
                int(grad_year) if grad_year else None,
                self.company_var.get(), self.job_title_var.get(),
                self.linkedin_var.get(), self.bio_text.get("1.0", "end-1c"),
                self.username
            ))
            conn.commit()
            messagebox.showinfo("Success", "Profile updated successfully.", parent=self)
        except sqlite3.Error as e:
            conn.rollback()
            messagebox.showerror("Database Error", f"Failed to update profile: {e}", parent=self)
        finally:
            conn.close()

    def update_password(self):
        new_pass = self.new_pass_entry.get()
        confirm_pass = self.confirm_pass_entry.get()

        if len(new_pass) < 6:
            messagebox.showerror("Error", "New password must be at least 6 characters long.", parent=self)
            return
        if new_pass != confirm_pass:
            messagebox.showerror("Error", "Passwords do not match.", parent=self)
            return

        hashed_pass, salt = hash_password(new_pass)
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password=?, salt=? WHERE username=?", (hashed_pass, salt, self.username))
            conn.commit()
            self.new_pass_entry.delete(0, 'end')
            self.confirm_pass_entry.delete(0, 'end')
            messagebox.showinfo("Success", "Password updated successfully.", parent=self)
        except sqlite3.Error as e:
            conn.rollback()
            messagebox.showerror("Database Error", f"Failed to update password: {e}", parent=self)
        finally:
            conn.close()

class UserRolesPage(tk.Frame):
    def __init__(self, parent, dashboard):
        super().__init__(parent, bg=COLORS["bg"])
        self.dashboard = dashboard
        self.username = dashboard.username

        self.sub_roles_structure = {
            "🧠 Knowledge & Mentorship Roles": [
                "Mentor", "Guest Speaker", "Domain Expert", "Resume Reviewer", "Mock Interviewer"
            ],
            "💼 Career & Opportunity Roles": [
                "Job Offerer", "Internship Provider", "Startup Founder", "Recruiter Liaison", "Freelance Connector"
            ],
            "🎓 Academic & Institutional Roles": [
                "Faculty", "Research Collaborator", "Curriculum Advisor", "Lab Sponsor"
            ],
            "🌐 Community & Outreach Roles": [
                "Event Sponsor", "Club Advisor", "Social Media Amplifier"
            ],
            "🛠 Technical & Creative Roles": [
                "Content Creator", "Dashboard Designer"
            ]
        }
        self.role_vars = {}
        self.create_widgets()

    def create_widgets(self):
        self.main_container = ScrollableFrame(self)
        self.main_container.pack(fill="both", expand=True, padx=30, pady=20)
        frame = self.main_container.scrollable_frame

        tk.Label(frame, text="My Roles", font=FONTS["title"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", pady=(0, 20))

        roles_frame = tk.Frame(frame, bg=COLORS["frame_bg"], padx=20, pady=20)
        roles_frame.pack(fill="x", pady=10)
        tk.Label(roles_frame, text="Your current primary roles are:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).pack(anchor="w")
        roles_text = ", ".join(self.dashboard.roles)
        tk.Label(roles_frame, text=roles_text, font=FONTS["body"], fg=COLORS["accent"], bg=COLORS["frame_bg"]).pack(anchor="w")

        self.sub_roles_container = tk.Frame(frame, bg=COLORS["bg"])
        self.sub_roles_container.pack(fill="x", expand=True)

    def refresh_data(self):
        for widget in self.sub_roles_container.winfo_children():
            widget.destroy()

        if "Alumni" not in self.dashboard.roles:
            tk.Label(self.sub_roles_container, text="\nSub-role selection is available for Alumni.", font=FONTS["body"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack()
            return

        tk.Label(self.sub_roles_container, text="As an Alumnus, you can volunteer for the following roles:", font=FONTS["header"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", pady=(20, 10))

        for category, roles in self.sub_roles_structure.items():
            labelframe = ttk.LabelFrame(self.sub_roles_container, text=f" {category} ", style="TLabelframe")
            labelframe.configure(padding=(20, 10))
            labelframe.pack(fill="x", pady=10, padx=5)

            for i, role in enumerate(roles):
                var = tk.IntVar()
                self.role_vars[role] = var
                cb = tk.Checkbutton(labelframe, text=role, variable=var, bg=COLORS["frame_bg"], fg=COLORS["text_fg"], selectcolor=COLORS["entry_bg"], activebackground=COLORS["frame_bg"], font=FONTS["body"], anchor="w")
                cb.grid(row=i//2, column=i%2, sticky="w", pady=5, padx=10)

        save_btn = tk.Button(self.sub_roles_container, text="Save My Roles", command=self.save_roles, bg=COLORS["accent"], fg=COLORS["accent_fg"], font=FONTS["body_bold"], relief="flat", padx=15, pady=5)
        save_btn.pack(pady=20)

        self.load_saved_roles()

    def load_saved_roles(self):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT sub_roles FROM alumni_sub_roles WHERE username=?", (self.username,))
            result = cursor.fetchone()
            if result and result['sub_roles']:
                saved_roles = result['sub_roles'].split(',')
                for role_name, var in self.role_vars.items():
                    if role_name in saved_roles:
                        var.set(1)
                    else:
                        var.set(0)
        finally:
            conn.close()

    def save_roles(self):
        selected_roles = [role for role, var in self.role_vars.items() if var.get() == 1]
        roles_str = ",".join(selected_roles)

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO alumni_sub_roles (username, sub_roles) VALUES (?, ?)", (self.username, roles_str))
            conn.commit()
            messagebox.showinfo("Success", "Your roles have been updated successfully!", parent=self)
        except sqlite3.Error as e:
            conn.rollback()
            messagebox.showerror("Database Error", f"Failed to save roles: {e}", parent=self)
        finally:
            conn.close()

class UserInboxPage(tk.Frame):
    def __init__(self, parent, dashboard):
        super().__init__(parent, bg=COLORS["bg"])
        self.dashboard = dashboard
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="My Inbox", font=FONTS["title"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", padx=30, pady=20)
        self.scroll_frame = ScrollableFrame(self)
        self.scroll_frame.pack(fill="both", expand=True, padx=30, pady=10)

    def refresh_data(self):
        for widget in self.scroll_frame.scrollable_frame.winfo_children():
            widget.destroy()

        inst_codes = list(set(p['inst_code'] for p in self.dashboard.user_profiles))
        user_roles_tuple = tuple(role for role in self.dashboard.roles if role in ['Student', 'Alumni'])

        all_messages = []
        if inst_codes and user_roles_tuple:
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                placeholders_roles = ','.join('?' for _ in user_roles_tuple)
                placeholders_inst = ','.join('?' for _ in inst_codes)
                query = f"""
                    SELECT message, timestamp, target_role, institution_code FROM messages
                    WHERE institution_code IN ({placeholders_inst})
                    AND (target_role = 'All' OR target_role IN ({placeholders_roles}))
                    ORDER BY timestamp DESC
                """
                params = inst_codes + list(user_roles_tuple)
                cursor.execute(query, params)
                all_messages = cursor.fetchall()
            finally:
                conn.close()

        if not all_messages:
            tk.Label(self.scroll_frame.scrollable_frame, text="Your inbox is empty.", font=FONTS["body"], bg=COLORS["bg"], fg=COLORS["text_fg"]).pack(pady=10)
        else:
            for msg in all_messages:
                msg_frame = tk.Frame(self.scroll_frame.scrollable_frame, bg=COLORS["frame_bg"], bd=1, relief="solid")
                inst_name = self.dashboard.institutions_map.get(msg['institution_code'], "Unknown")
                ts_formatted = datetime.strptime(msg['timestamp'].split('.')[0], '%Y-%m-%d %H:%M:%S').strftime('%d %b %Y, %I:%M %p')
                header_text = f"To: {msg['target_role']} | From: {inst_name} | On: {ts_formatted}"

                tk.Label(msg_frame, text=header_text, font=FONTS["small_bold"], bg=COLORS["frame_bg"], fg=COLORS["accent"], justify="left").pack(anchor="w", padx=15, pady=(10,0))
                ttk.Separator(msg_frame).pack(fill='x', padx=15, pady=5)
                tk.Label(msg_frame, text=msg['message'], font=FONTS["body"], wraplength=700, bg=COLORS["frame_bg"], fg=COLORS["text_fg"], justify="left").pack(anchor="w", padx=15, pady=(0,15))
                msg_frame.pack(fill="x", expand=True, padx=10, pady=5)

class UserEventsPage(tk.Frame):
    def __init__(self, parent, dashboard):
        super().__init__(parent, bg=COLORS["bg"])
        self.dashboard = dashboard
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Upcoming Events", font=FONTS["title"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", padx=30, pady=20)
        self.scroll_frame = ScrollableFrame(self)
        self.scroll_frame.pack(fill="both", expand=True, padx=30, pady=10)

    def refresh_data(self):
        for widget in self.scroll_frame.scrollable_frame.winfo_children(): widget.destroy()

        inst_codes = list(set(p['inst_code'] for p in self.dashboard.user_profiles))
        user_roles_tuple = tuple(role for role in self.dashboard.roles if role in ['Student', 'Alumni'])

        all_events = []
        if inst_codes and user_roles_tuple:
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                placeholders_roles = ','.join('?' for _ in user_roles_tuple)
                placeholders_inst = ','.join('?' for _ in inst_codes)
                query = f"""
                    SELECT e.title, e.description, e.event_date, i.name
                    FROM events e JOIN institutions i ON e.institution_code = i.code
                    WHERE e.institution_code IN ({placeholders_inst})
                    AND (e.target_role = 'All' OR e.target_role IN ({placeholders_roles}))
                    ORDER BY e.event_date DESC
                """
                params = inst_codes + list(user_roles_tuple)
                cursor.execute(query, params)
                all_events = cursor.fetchall()
            finally:
                conn.close()

        if not all_events:
            tk.Label(self.scroll_frame.scrollable_frame, text="No upcoming events.", font=FONTS["body"], bg=COLORS["bg"], fg=COLORS["text_fg"]).pack(pady=10)
        else:
            for event in all_events:
                event_frame = tk.Frame(self.scroll_frame.scrollable_frame, bg=COLORS["frame_bg"], bd=1, relief="solid")
                header_text = f"{event['title'].upper()}  |  Date: {event['event_date']}  |  Institution: {event['name']}"
                tk.Label(event_frame, text=header_text, font=FONTS["body_bold"], bg=COLORS["frame_bg"], fg=COLORS["accent"], justify="left").pack(anchor="w", padx=15, pady=(10,0))
                ttk.Separator(event_frame).pack(fill='x', padx=15, pady=5)
                tk.Label(event_frame, text=event['description'], font=FONTS["body"], wraplength=700, bg=COLORS["frame_bg"], fg=COLORS["text_fg"], justify="left").pack(anchor="w", padx=15, pady=(0,15))
                event_frame.pack(fill="x", expand=True, padx=10, pady=5)

class UserChatPage(tk.Frame):
    def __init__(self, parent, dashboard):
        super().__init__(parent, bg=COLORS["bg"])
        self.dashboard = dashboard
        self.create_widgets()

    def create_widgets(self):
        top_frame = tk.Frame(self, bg=COLORS["bg"])
        top_frame.pack(fill="x", padx=30, pady=(20,10))
        tk.Label(top_frame, text="Institution Chat", font=FONTS["title"], bg=COLORS["bg"], fg=COLORS["text_fg"]).pack(side="left")

        self.inst_combo = ttk.Combobox(top_frame, values=[name for code, name in self.dashboard.institutions_map.items()], state="readonly", font=FONTS["body"], width=30)
        if self.dashboard.institutions_map:
            self.inst_combo.pack(side="right")
            self.inst_combo.bind("<<ComboboxSelected>>", self.populate_chat)

        self.chat_display_frame = ScrollableFrame(self)
        self.chat_display_frame.pack(fill="both", expand=True, padx=30, pady=5)

        entry_frame = tk.Frame(self, bg=COLORS["bg"], pady=10)
        entry_frame.pack(fill="x", padx=30, pady=(5,20))

        self.msg_entry = tk.Entry(entry_frame, bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], font=FONTS["body"], relief="solid", bd=1)
        self.msg_entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 10))
        self.msg_entry.bind("<Return>", self.send_chat_message)

        send_btn = tk.Button(entry_frame, text="Send", command=self.send_chat_message, bg=COLORS["accent"], fg=COLORS["accent_fg"], font=FONTS["body"], relief="flat", padx=20, pady=4)
        send_btn.pack(side="right")

    def refresh_data(self):
        if self.dashboard.institutions_map:
            self.inst_combo.set(list(self.dashboard.institutions_map.values())[0])
        self.populate_chat()

    def populate_chat(self, event=None):
        for widget in self.chat_display_frame.scrollable_frame.winfo_children(): widget.destroy()
        selected_inst_name = self.inst_combo.get()
        if not selected_inst_name: return

        inst_code = next((code for code, name in self.dashboard.institutions_map.items() if name == selected_inst_name), None)
        if not inst_code: return

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT username, message, timestamp FROM shoutbox WHERE institution_code=? ORDER BY timestamp ASC", (inst_code,))
            messages = cursor.fetchall()
            for msg_row in messages:
                self.add_message_to_ui(msg_row['username'], msg_row['message'], msg_row['timestamp'])
        finally:
            conn.close()

        self.chat_display_frame.canvas.yview_moveto(1.0)

    def add_message_to_ui(self, user, msg, ts):
        """Adds a single message to the chat display."""
        ts_formatted = datetime.strptime(ts.split('.')[0], '%Y-%m-%d %H:%M:%S').strftime('%d %b, %H:%M')
        header = f"{user} ({ts_formatted})"
        color = COLORS["accent"] if user == self.dashboard.username else COLORS["text_fg"]

        msg_frame = tk.Frame(self.chat_display_frame.scrollable_frame, bg=COLORS["bg"])
        tk.Label(msg_frame, text=header, font=FONTS["small_bold"], bg=COLORS["bg"], fg=color).pack(anchor="w")
        tk.Label(msg_frame, text=msg, wraplength=700, font=FONTS["body"], bg=COLORS["bg"], fg=COLORS["text_fg"], justify="left").pack(anchor="w", pady=(0, 10))
        msg_frame.pack(fill="x", expand=True)

        self.after(50, lambda: self.chat_display_frame.canvas.yview_moveto(1.0))

    def send_chat_message(self, event=None):
        message = self.msg_entry.get().strip()
        selected_inst_name = self.inst_combo.get()
        if not message or not selected_inst_name: return

        inst_code = next((code for code, name in self.dashboard.institutions_map.items() if name == selected_inst_name), None)
        if not inst_code: return

        conn = get_db_connection()
        timestamp = datetime.now()
        try:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO shoutbox (institution_code, username, message, timestamp) VALUES (?, ?, ?, ?)", (inst_code, self.dashboard.username, message, timestamp))
            conn.commit()
            self.msg_entry.delete(0, 'end')
            self.add_message_to_ui(self.dashboard.username, message, timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'))
        except sqlite3.Error as e:
            conn.rollback()
            messagebox.showerror("Error", f"Could not send message: {e}", parent=self)
        finally:
            conn.close()

class UserCareersPage(tk.Frame):
    def __init__(self, parent, dashboard):
        super().__init__(parent, bg=COLORS["bg"])
        self.dashboard = dashboard
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Career Opportunities", font=FONTS["title"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", padx=30, pady=20)

        filter_frame = tk.Frame(self, bg=COLORS["bg"])
        filter_frame.pack(fill="x", padx=30, pady=(0, 10))

        tk.Label(filter_frame, text="Search:", font=FONTS["body_bold"], bg=COLORS["bg"], fg=COLORS["text_fg"]).pack(side="left", padx=(0,5))
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(filter_frame, textvariable=self.search_var, font=FONTS["body"], bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], relief="solid", bd=1)
        search_entry.pack(side="left", padx=5, ipady=4)
        search_entry.bind("<KeyRelease>", self.filter_jobs)

        tk.Label(filter_frame, text="Institution:", font=FONTS["body_bold"], bg=COLORS["bg"], fg=COLORS["text_fg"]).pack(side="left", padx=(20,5))
        self.inst_filter_combo = ttk.Combobox(filter_frame, state="readonly", font=FONTS["body"])
        self.inst_filter_combo.pack(side="left", padx=5)
        self.inst_filter_combo.bind("<<ComboboxSelected>>", self.filter_jobs)

        content_pane = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=8, bg=COLORS["bg"], bd=0)
        content_pane.pack(fill="both", expand=True, padx=30, pady=10)

        tree_frame = tk.Frame(content_pane, bg=COLORS["frame_bg"])
        self.tree = ttk.Treeview(tree_frame, columns=("Title", "Company", "Location"), show="headings")
        self.tree.heading("Title", text="Job Title")
        self.tree.heading("Company", text="Company")
        self.tree.heading("Location", text="Location")
        self.tree.column("Title", width=250)
        self.tree.column("Company", width=150)
        self.tree.column("Location", width=120)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.show_job_details)
        content_pane.add(tree_frame, width=550)

        details_frame = tk.Frame(content_pane, bg=COLORS["frame_bg"], padx=20, pady=20)
        self.details_title = tk.Label(details_frame, font=FONTS["header"], fg=COLORS["accent"], bg=COLORS["frame_bg"], wraplength=400, justify="left")
        self.details_title.pack(anchor="w")
        self.details_company = tk.Label(details_frame, font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"])
        self.details_company.pack(anchor="w", pady=(5,0))
        self.details_location = tk.Label(details_frame, font=FONTS["small"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"])
        self.details_location.pack(anchor="w", pady=(0,10))

        desc_scroll = ScrollableFrame(details_frame)
        desc_scroll.pack(fill="both", expand=True, pady=5)
        self.details_desc = tk.Label(desc_scroll.scrollable_frame, font=FONTS["body"], fg=COLORS["text_fg"], bg=COLORS["bg"], wraplength=450, justify="left")
        self.details_desc.pack(anchor="w")

        self.apply_link_button = tk.Button(details_frame, text="Apply Now", bg=COLORS["accent"], fg=COLORS["accent_fg"], relief="flat", font=FONTS["body_bold"])
        self.apply_link_button.pack(pady=15)

        content_pane.add(details_frame)

    def refresh_data(self):
        self.all_jobs = []
        inst_codes = list(self.dashboard.institutions_map.keys())
        if not inst_codes: return

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            placeholders = ','.join('?' for _ in inst_codes)
            cursor.execute(f"SELECT id, title, company, location, description, apply_link, institution_code FROM jobs WHERE institution_code IN ({placeholders}) ORDER BY post_date DESC", inst_codes)
            self.all_jobs = cursor.fetchall()
        finally:
            conn.close()

        inst_names = ["All Institutions"] + list(self.dashboard.institutions_map.values())
        self.inst_filter_combo['values'] = inst_names
        self.inst_filter_combo.set("All Institutions")

        self.filter_jobs()
        self.clear_details()

    def filter_jobs(self, event=None):
        for i in self.tree.get_children(): self.tree.delete(i)

        search_term = self.search_var.get().lower()
        selected_inst_name = self.inst_filter_combo.get()

        for job in self.all_jobs:
            job_id, title, company, location, desc, link, inst_code = job['id'], job['title'], job['company'], job['location'], job['description'], job['apply_link'], job['institution_code']
            inst_name = self.dashboard.institutions_map.get(inst_code, "")

            if selected_inst_name != "All Institutions" and inst_name != selected_inst_name:
                continue

            if search_term and not (search_term in title.lower() or search_term in company.lower() or (desc and search_term in desc.lower())):
                continue

            self.tree.insert("", "end", iid=job_id, values=(title, company, location))

    def show_job_details(self, event):
        selected_item = self.tree.focus()
        if not selected_item: return

        job_id = int(selected_item)
        job_data = next((job for job in self.all_jobs if job['id'] == job_id), None)
        if not job_data: return

        title, company, location, desc, link = job_data['title'], job_data['company'], job_data['location'], job_data['description'], job_data['apply_link']
        self.details_title.config(text=title)
        self.details_company.config(text=company)
        self.details_location.config(text=f"📍 {location or 'N/A'}")
        self.details_desc.config(text=desc)

        if link:
            self.apply_link_button.pack(pady=15)
            self.apply_link_button.config(command=lambda u=link: webbrowser.open(u))
        else:
            self.apply_link_button.pack_forget()

    def clear_details(self):
        self.details_title.config(text="Select a job to view details")
        self.details_company.config(text="")
        self.details_location.config(text="")
        self.details_desc.config(text="")
        self.apply_link_button.pack_forget()

class AllUsersDirectoryPage(tk.Frame):
    def __init__(self, parent, dashboard):
        super().__init__(parent, bg=COLORS["bg"])
        self.dashboard = dashboard
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="User Directory", font=FONTS["title"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", padx=30, pady=20)

        control_frame = tk.Frame(self, bg=COLORS["bg"])
        control_frame.pack(fill="x", padx=30, pady=10)
        
        tk.Label(control_frame, text="Search:", font=FONTS["body_bold"], bg=COLORS["bg"], fg=COLORS["text_fg"]).pack(side="left", padx=(0, 5))
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(control_frame, textvariable=self.search_var, font=FONTS["body"], bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], relief="solid", bd=1, width=30)
        search_entry.pack(side="left", padx=5, ipady=4)
        search_entry.bind("<KeyRelease>", self.filter_users)

        tk.Label(control_frame, text="Institution:", font=FONTS["body_bold"], bg=COLORS["bg"], fg=COLORS["text_fg"]).pack(side="left", padx=(20, 10))
        self.inst_combo = ttk.Combobox(control_frame, state="readonly", font=FONTS["body"], width=30)
        self.inst_combo.pack(side="left")
        self.inst_combo.bind("<<ComboboxSelected>>", lambda e: self.populate_directory())

        tree_frame = tk.Frame(self, bg=COLORS["frame_bg"])
        tree_frame.pack(fill="both", expand=True, padx=30, pady=10)

        self.tree = ttk.Treeview(tree_frame, columns=("Name", "Role", "Year"), show="headings")
        self.tree.heading("Name", text="Full Name")
        self.tree.heading("Role", text="Role")
        self.tree.heading("Year", text="Joining Year")
        self.tree.column("Name", width=250)
        self.tree.column("Role", width=100, anchor="center")
        self.tree.column("Year", width=100, anchor="center")
        self.tree.pack(fill="both", expand=True, side="left")
        self.tree.bind("<<TreeviewSelect>>", self.on_user_select)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.all_users_data = []

    def refresh_data(self):
        # Admin dashboard has a single institution, user dashboard can have multiple
        if isinstance(self.dashboard, AdminDashboard):
            self.inst_combo['values'] = [self.dashboard.institution_name]
            self.inst_combo.set(self.dashboard.institution_name)
            self.inst_combo.config(state="disabled")
        else: # UserDashboard
             inst_names = list(self.dashboard.institutions_map.values())
             self.inst_combo['values'] = inst_names
             if inst_names:
                self.inst_combo.set(inst_names[0])
        
        self.populate_directory()

    def populate_directory(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        
        selected_inst_name = self.inst_combo.get()
        if not selected_inst_name: return

        if isinstance(self.dashboard, AdminDashboard):
            inst_code = self.dashboard.institution_code
        else: # UserDashboard
            inst_code = next((code for code, name in self.dashboard.institutions_map.items() if name == selected_inst_name), None)
        
        if not inst_code: return

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            query = """
                SELECT p.username, p.full_name, 'Student' as role, s.year
                FROM profiles p JOIN students s ON p.username = s.username
                WHERE s.institution_code = ?
                UNION ALL
                SELECT p.username, p.full_name, 'Alumni' as role, a.year
                FROM profiles p JOIN alumni a ON p.username = a.username
                WHERE a.institution_code = ?
                ORDER BY p.full_name;
            """
            cursor.execute(query, (inst_code, inst_code))
            self.all_users_data = cursor.fetchall()
            self.filter_users() # Initial population
        finally:
            conn.close()

    def filter_users(self, event=None):
        search_term = self.search_var.get().lower()
        for i in self.tree.get_children(): self.tree.delete(i)

        for user_row in self.all_users_data:
            full_name = user_row['full_name'] or ""
            username = user_row['username']
            if search_term in full_name.lower() or search_term in username.lower():
                display_name = full_name if full_name else username
                self.tree.insert("", "end", iid=username, values=(display_name, user_row['role'], user_row['year']))

    def on_user_select(self, event):
        selected_item = self.tree.focus()
        if not selected_item: return
        
        username = self.tree.item(selected_item)['tags'][0] if self.tree.item(selected_item)['tags'] else selected_item
        ViewProfileWindow(self, username=username)

class ViewProfileWindow(tk.Toplevel):
    def __init__(self, parent, username):
        super().__init__(parent)
        self.username = username
        self.title(f"Profile of {self.username}")
        self.geometry("600x700")
        self.configure(bg=COLORS["bg"])
        self.transient(parent)
        self.grab_set()

        self.create_widgets()
        self.load_profile_data()
    
    def create_widgets(self):
        container = ScrollableFrame(self)
        container.pack(fill="both", expand=True, padx=20, pady=20)
        self.frame = container.scrollable_frame
        self.frame.configure(bg=COLORS["frame_bg"])

        self.profile_widgets = {}
        fields = ["Full Name", "Major/Field of Study", "Graduation Year", "Current Company", "Job Title", "LinkedIn Profile", "Bio"]
        for i, field in enumerate(fields):
            tk.Label(self.frame, text=f"{field}:", font=FONTS["body_bold"], bg=COLORS["frame_bg"], fg=COLORS["text_fg"]).grid(row=i, column=0, sticky="ne", padx=10, pady=8)
            if field == "Bio":
                 value_label = tk.Label(self.frame, text="N/A", font=FONTS["body"], bg=COLORS["frame_bg"], fg=COLORS["text_fg"], wraplength=400, justify="left")
            else:
                value_label = tk.Label(self.frame, text="N/A", font=FONTS["body"], bg=COLORS["frame_bg"], fg=COLORS["text_fg"])
            value_label.grid(row=i, column=1, sticky="nw", padx=10, pady=8)
            self.profile_widgets[field] = value_label
        
        self.linkedin_button = tk.Button(self.frame, text="Visit LinkedIn", bg=COLORS["accent"], fg=COLORS["accent_fg"], font=FONTS["body_bold"], relief="flat")

    def load_profile_data(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM profiles WHERE username=?", (self.username,))
        profile = cursor.fetchone()
        conn.close()

        if not profile:
            messagebox.showerror("Error", "Could not load profile data.", parent=self)
            self.destroy()
            return
        
        self.profile_widgets["Full Name"].config(text=profile['full_name'] or "N/A")
        self.profile_widgets["Major/Field of Study"].config(text=profile['major'] or "N/A")
        self.profile_widgets["Graduation Year"].config(text=profile['graduation_year'] or "N/A")
        self.profile_widgets["Current Company"].config(text=profile['current_company'] or "N/A")
        self.profile_widgets["Job Title"].config(text=profile['job_title'] or "N/A")
        self.profile_widgets["Bio"].config(text=profile['bio'] or "N/A")
        
        linkedin_url = profile['linkedin_url']
        if linkedin_url:
            self.profile_widgets["LinkedIn Profile"].grid_forget()
            self.linkedin_button.grid(row=5, column=1, sticky="nw", padx=10, pady=8)
            self.linkedin_button.config(command=lambda: webbrowser.open(linkedin_url))
        else:
            self.linkedin_button.grid_forget()
            self.profile_widgets["LinkedIn Profile"].grid(row=5, column=1, sticky="nw", padx=10, pady=8)
            self.profile_widgets["LinkedIn Profile"].config(text="N/A")

class UserDashboard(tk.Toplevel):
    def __init__(self, controller, username, roles):
        super().__init__()
        self.controller = controller
        self.username = username
        self.roles = roles
        self.title(f"Alumni Connect - {username}")
        self.state('zoomed')
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.configure(bg=COLORS["bg"])

        self.user_profiles = []
        self.institutions_map = {}
        self.load_user_data()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar_frame = tk.Frame(self, bg=COLORS["frame_bg"], width=250)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsw")
        self.sidebar_frame.pack_propagate(False)

        self.content_frame = tk.Frame(self, bg=COLORS["bg"])
        self.content_frame.grid(row=0, column=1, sticky="nsew")
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)

        self.pages = {}
        self.sidebar_buttons = {}
        self.setup_sidebar()
        self.show_page("Profile")

    def load_user_data(self):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT year, institution_code FROM students WHERE username=?", (self.username,))
            for row in cursor.fetchall():
                self.user_profiles.append({"role": "Student", "year": row['year'], "inst_code": row['institution_code']})

            cursor.execute("SELECT year, institution_code FROM alumni WHERE username=?", (self.username,))
            for row in cursor.fetchall():
                self.user_profiles.append({"role": "Alumni", "year": row['year'], "inst_code": row['institution_code']})

            inst_codes = list(set(p['inst_code'] for p in self.user_profiles))
            if inst_codes:
                placeholders = ','.join('?' for _ in inst_codes)
                cursor.execute(f"SELECT code, name FROM institutions WHERE code IN ({placeholders})", inst_codes)
                for row in cursor.fetchall():
                    self.institutions_map[row['code']] = row['name']
        finally:
            conn.close()

    def setup_sidebar(self):
        tk.Label(self.sidebar_frame, text="Alumni Connect", font=FONTS["header"], bg=COLORS["frame_bg"], fg=COLORS["accent"]).pack(pady=20, padx=10)

        menu_items = [
            ("Profile", "assets/profile.png", UserProfilePage),
            ("My Roles", "assets/roles.png", UserRolesPage),
            ("Inbox", "assets/inbox.png", UserInboxPage),
            ("Events", "assets/event.png", UserEventsPage),
            ("Chat", "assets/chat.png", UserChatPage),
            ("Careers", "assets/career.png", UserCareersPage),
            ("User Directory", "assets/directory.png", AllUsersDirectoryPage) # Updated
        ]

        for text, icon, Page in menu_items:
            button = SidebarButton(self.sidebar_frame, text, icon, command=lambda p=text: self.show_page(p))
            button.pack(fill="x", pady=2)
            self.sidebar_buttons[text] = button
            self.pages[text] = Page(self.content_frame, self)
            self.pages[text].grid(row=0, column=0, sticky="nsew")

        logout_btn = SidebarButton(self.sidebar_frame, "Logout", "assets/logout.png", self.logout)
        logout_btn.pack(side="bottom", fill="x", pady=20)
        ToolTip(logout_btn, "Log out of your account")

    def show_page(self, page_name):
        for name, button in self.sidebar_buttons.items():
            button.set_active(name == page_name)

        page = self.pages[page_name]
        page.tkraise()
        if hasattr(page, 'refresh_data'):
            page.refresh_data()

    def logout(self):
        self.destroy()
        self.controller.return_to_login()

    def on_close(self):
        self.destroy()
        self.controller.destroy()


# ==============================================================================
# SECTION 6: ADMIN DASHBOARD AND SUB-PAGES
# ==============================================================================

class AdminAnalyticsPage(tk.Frame):
    def __init__(self, parent, dashboard):
        super().__init__(parent, bg=COLORS["bg"])
        self.dashboard = dashboard
        self.institution_code = dashboard.institution_code
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Institution Dashboard", font=FONTS["title"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", padx=30, pady=20)

        metrics_frame = tk.Frame(self, bg=COLORS["bg"])
        metrics_frame.pack(fill="x", padx=30, pady=10)

        self.student_count_label = self.create_metric_card(metrics_frame, "Total Students", "0")
        self.alumni_count_label = self.create_metric_card(metrics_frame, "Total Alumni", "0")
        self.events_count_label = self.create_metric_card(metrics_frame, "Total Events", "0")
        self.jobs_count_label = self.create_metric_card(metrics_frame, "Active Jobs", "0")

        self.chart_frame = tk.Frame(self, bg=COLORS["frame_bg"], padx=20, pady=20)
        self.chart_frame.pack(fill="both", expand=True, padx=30, pady=20)

    def create_metric_card(self, parent, title, value):
        card = tk.Frame(parent, bg=COLORS["frame_bg"], relief="solid", bd=1)
        card.pack(side="left", fill="x", expand=True, padx=10)
        tk.Label(card, text=title, font=FONTS["body"], bg=COLORS["frame_bg"], fg=COLORS["text_fg"]).pack(pady=(10, 0))
        value_label = tk.Label(card, text=value, font=FONTS["title"], bg=COLORS["frame_bg"], fg=COLORS["accent"])
        value_label.pack(pady=(0, 10))
        return value_label

    def refresh_data(self):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS count FROM students WHERE institution_code=?", (self.institution_code,))
            student_count = cursor.fetchone()['count']
            cursor.execute("SELECT COUNT(*) AS count FROM alumni WHERE institution_code=?", (self.institution_code,))
            alumni_count = cursor.fetchone()['count']
            cursor.execute("SELECT COUNT(*) AS count FROM events WHERE institution_code=?", (self.institution_code,))
            events_count = cursor.fetchone()['count']
            cursor.execute("SELECT COUNT(*) AS count FROM jobs WHERE institution_code=?", (self.institution_code,))
            jobs_count = cursor.fetchone()['count']
        finally:
            conn.close()

        self.student_count_label.config(text=str(student_count))
        self.alumni_count_label.config(text=str(alumni_count))
        self.events_count_label.config(text=str(events_count))
        self.jobs_count_label.config(text=str(jobs_count))

        self.update_chart(student_count, alumni_count)

    def update_chart(self, student_count, alumni_count):
        for widget in self.chart_frame.winfo_children(): widget.destroy()

        if student_count == 0 and alumni_count == 0:
            tk.Label(self.chart_frame, text="No user data to display.", font=FONTS["body"], bg=COLORS["frame_bg"], fg=COLORS["text_fg"]).pack(expand=True)
            return

        fig = plt.Figure(figsize=(6, 4), dpi=100)
        fig.patch.set_facecolor(COLORS["frame_bg"])
        ax = fig.add_subplot(111)

        labels = ['Students', 'Alumni']
        counts = [student_count, alumni_count]
        colors = [COLORS["accent"], COLORS["success"]]

        ax.bar(labels, counts, color=colors)

        ax.set_title('Student vs. Alumni Distribution', color=COLORS["text_fg"])
        ax.set_ylabel('Number of Users', color=COLORS["text_fg"])
        ax.tick_params(axis='x', colors=COLORS["text_fg"])
        ax.tick_params(axis='y', colors=COLORS["text_fg"])
        ax.set_facecolor(COLORS["entry_bg"])

        for spine in ax.spines.values():
            spine.set_edgecolor(COLORS["text_fg"])

        canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

class AdminManageUsersPage(tk.Frame):
    def __init__(self, parent, dashboard):
        super().__init__(parent, bg=COLORS["bg"])
        self.dashboard = dashboard
        self.institution_code = dashboard.institution_code
        self.create_widgets()

    def create_widgets(self):
        main_pane = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=8, bg=COLORS["bg"], bd=0)
        main_pane.pack(fill="both", expand=True, padx=30, pady=20)

        student_frame, self.student_tree = self.create_treeview_frame(main_pane, "Students")
        main_pane.add(student_frame)

        action_frame = tk.Frame(main_pane, bg=COLORS["bg"], width=150)
        action_frame.pack_propagate(False)
        tk.Label(action_frame, text="Actions", font=FONTS["header"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(pady=10)
        graduate_btn = tk.Button(action_frame, text="Graduate →", command=self.graduate_student, bg=COLORS["accent"], fg=COLORS["accent_fg"], font=FONTS["body"], relief="flat", width=15, pady=5)
        graduate_btn.pack(pady=10)
        ToolTip(graduate_btn, "Move selected student to the Alumni list.")

        remove_student_btn = tk.Button(action_frame, text="Remove Student", command=self.remove_student, bg=COLORS["danger"], fg=COLORS["accent_fg"], font=FONTS["body"], relief="flat", width=15, pady=5)
        remove_student_btn.pack(pady=(50, 10))
        ToolTip(remove_student_btn, "WARNING: This will delete the user's account entirely.")

        remove_alumni_btn = tk.Button(action_frame, text="Remove Alumni", command=self.remove_alumni, bg=COLORS["danger"], fg=COLORS["accent_fg"], font=FONTS["body"], relief="flat", width=15, pady=5)
        remove_alumni_btn.pack(pady=10)
        ToolTip(remove_alumni_btn, "WARNING: This will delete the user's account entirely.")
        main_pane.add(action_frame, width=170, padx=10)

        alumni_frame, self.alumni_tree = self.create_treeview_frame(main_pane, "Alumni")
        main_pane.add(alumni_frame)

    def create_treeview_frame(self, parent, title):
        container = tk.Frame(parent, bg=COLORS["frame_bg"])
        tk.Label(container, text=title, font=FONTS["header"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).pack(pady=(10, 15), anchor="w", padx=10)
        tree = ttk.Treeview(container, columns=("Username", "Year"), show="headings")
        tree.heading("Username", text="Username")
        tree.heading("Year", text="Year of Joining")
        tree.column("Username", width=150)
        tree.column("Year", width=100, anchor="center")
        tree.pack(fill="both", expand=True, padx=10, pady=5)
        return container, tree

    def refresh_data(self):
        for i in self.student_tree.get_children(): self.student_tree.delete(i)
        for i in self.alumni_tree.get_children(): self.alumni_tree.delete(i)

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT username, year FROM students WHERE institution_code=?", (self.institution_code,))
            for row in cursor.fetchall(): self.student_tree.insert("", "end", values=(row['username'], row['year']), iid=row['username'])
            cursor.execute("SELECT username, year FROM alumni WHERE institution_code=?", (self.institution_code,))
            for row in cursor.fetchall(): self.alumni_tree.insert("", "end", values=(row['username'], row['year']), iid=row['username'])
        finally:
            conn.close()

    def graduate_student(self):
        selected_item = self.student_tree.focus()
        if not selected_item:
            messagebox.showwarning("Selection Error", "Please select a student to graduate.", parent=self)
            return

        username, year = self.student_tree.item(selected_item)['values']
        if messagebox.askyesno("Confirm Graduation", f"Are you sure you want to move {username} to the alumni list?", parent=self):
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("INSERT OR IGNORE INTO alumni (username, year, institution_code) VALUES (?, ?, ?)", (username, year, self.institution_code))
                cursor.execute("DELETE FROM students WHERE username=? AND institution_code=?", (username, self.institution_code))

                cursor.execute("SELECT roles FROM users WHERE username=?", (username,))
                roles_str = cursor.fetchone()['roles']
                role_set = set(roles_str.split(','))
                role_set.add("Alumni")
                new_roles = ",".join(sorted(list(role_set)))

                cursor.execute("UPDATE users SET roles=? WHERE username=?", (new_roles, username))
                conn.commit()
                messagebox.showinfo("Success", f"{username} has been graduated.", parent=self)
                self.refresh_data()
            except sqlite3.Error as e:
                conn.rollback()
                messagebox.showerror("Database Error", f"An error occurred: {e}", parent=self)
            finally:
                conn.close()

    def remove_student(self): self.remove_user(self.student_tree, "student")
    def remove_alumni(self): self.remove_user(self.alumni_tree, "alumnus")

    def remove_user(self, tree, user_type):
        selected_item = tree.focus()
        if not selected_item:
            messagebox.showwarning("Selection Error", f"Please select a {user_type} to remove.", parent=self)
            return

        username = tree.item(selected_item)['values'][0]
        if messagebox.askyesno("Confirm Removal", f"WARNING: This will permanently delete {username}'s entire user account and all associated data.\nThis action cannot be undone. Are you sure?", parent=self, icon='warning'):
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM users WHERE username=?", (username,))
                conn.commit()
                messagebox.showinfo("Success", f"User '{username}' has been removed.", parent=self)
                self.refresh_data()
            except sqlite3.Error as e:
                conn.rollback()
                messagebox.showerror("Database Error", f"An error occurred: {e}", parent=self)
            finally:
                conn.close()

class AdminPostMessagePage(tk.Frame):
    def __init__(self, parent, dashboard):
        super().__init__(parent, bg=COLORS["bg"])
        self.dashboard = dashboard
        self.institution_code = dashboard.institution_code
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Compose Message", font=FONTS["title"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", padx=30, pady=20)

        main_frame = tk.Frame(self, bg=COLORS["frame_bg"], padx=20, pady=20)
        main_frame.pack(fill="both", expand=True, padx=30, pady=10)

        tk.Label(main_frame, text="Select Audience:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).pack(anchor="w", pady=(0, 5))
        self.target_var = tk.StringVar(value="All")
        options_frame = tk.Frame(main_frame, bg=COLORS["frame_bg"])
        options_frame.pack(anchor="w", pady=(0, 15))
        tk.Radiobutton(options_frame, text="All", variable=self.target_var, value="All", bg=COLORS["frame_bg"], fg=COLORS["text_fg"], selectcolor=COLORS["entry_bg"], font=FONTS["body"]).pack(side="left", padx=5)
        tk.Radiobutton(options_frame, text="Students Only", variable=self.target_var, value="Student", bg=COLORS["frame_bg"], fg=COLORS["text_fg"], selectcolor=COLORS["entry_bg"], font=FONTS["body"]).pack(side="left", padx=5)
        tk.Radiobutton(options_frame, text="Alumni Only", variable=self.target_var, value="Alumni", bg=COLORS["frame_bg"], fg=COLORS["text_fg"], selectcolor=COLORS["entry_bg"], font=FONTS["body"]).pack(side="left", padx=5)

        tk.Label(main_frame, text="Message:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["frame_bg"]).pack(anchor="w", pady=(0, 5))
        self.msg_text = tk.Text(main_frame, height=10, bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], font=FONTS["body"], relief="solid", bd=1, wrap="word")
        self.msg_text.pack(fill="both", expand=True)

        send_btn = tk.Button(main_frame, text="Send Message", command=self.send_message, bg=COLORS["accent"], fg=COLORS["accent_fg"], font=FONTS["body_bold"], relief="flat", padx=20, pady=8)
        send_btn.pack(pady=(20, 0), anchor="e")

    def send_message(self):
        message = self.msg_text.get("1.0", "end-1c").strip()
        if not message:
            messagebox.showwarning("Empty Message", "Cannot send an empty message.", parent=self)
            return

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO messages (institution_code, target_role, message, timestamp) VALUES (?, ?, ?, ?)", (self.institution_code, self.target_var.get(), message, datetime.now()))
            conn.commit()
            messagebox.showinfo("Success", "Message has been sent successfully.", parent=self)
            self.msg_text.delete("1.0", "end")
        except sqlite3.Error as e:
            conn.rollback()
            messagebox.showerror("Database Error", f"An error occurred: {e}", parent=self)
        finally:
            conn.close()

class AdminManageEventsPage(tk.Frame):
    def __init__(self, parent, dashboard):
        super().__init__(parent, bg=COLORS["bg"])
        self.dashboard = dashboard
        self.institution_code = dashboard.institution_code
        self.create_widgets()

    def create_widgets(self):
        top_frame = tk.Frame(self, bg=COLORS["bg"])
        top_frame.pack(fill="x", padx=30, pady=20)
        tk.Label(top_frame, text="Manage Events", font=FONTS["title"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(side="left")

        add_btn = tk.Button(top_frame, text="✚ Add New Event", command=self.open_add_event_form, bg=COLORS["accent"], fg=COLORS["accent_fg"], font=FONTS["body_bold"], relief="flat", padx=10, pady=5)
        add_btn.pack(side="right")
        del_btn = tk.Button(top_frame, text="✖ Delete Selected", command=self.delete_event, bg=COLORS["danger"], fg=COLORS["accent_fg"], font=FONTS["body_bold"], relief="flat", padx=10, pady=5)
        del_btn.pack(side="right", padx=10)

        tree_frame = tk.Frame(self, bg=COLORS["frame_bg"])
        tree_frame.pack(fill="both", expand=True, padx=30, pady=10)
        self.event_tree = ttk.Treeview(tree_frame, columns=("ID", "Title", "Date", "Audience"), show="headings")
        self.event_tree.heading("ID", text="ID"); self.event_tree.column("ID", width=50, anchor="center")
        self.event_tree.heading("Title", text="Title"); self.event_tree.column("Title", width=300)
        self.event_tree.heading("Date", text="Event Date"); self.event_tree.column("Date", width=150, anchor="center")
        self.event_tree.heading("Audience", text="Audience"); self.event_tree.column("Audience", width=150, anchor="center")
        self.event_tree.pack(fill="both", expand=True)

    def refresh_data(self):
        for i in self.event_tree.get_children(): self.event_tree.delete(i)
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, title, event_date, target_role FROM events WHERE institution_code=? ORDER BY event_date DESC", (self.institution_code,))
            for row in cursor.fetchall(): self.event_tree.insert("", "end", values=(row['id'], row['title'], row['event_date'], row['target_role']), iid=row['id'])
        finally:
            conn.close()

    def delete_event(self):
        selected = self.event_tree.focus()
        if not selected:
            messagebox.showwarning("Selection Error", "Please select an event to delete.", parent=self)
            return
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this event?", parent=self):
            event_id = self.event_tree.item(selected)['values'][0]
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM events WHERE id=?", (event_id,))
                conn.commit()
                self.refresh_data()
            except sqlite3.Error as e:
                conn.rollback()
                messagebox.showerror("Error", f"Failed to delete event: {e}", parent=self)
            finally:
                conn.close()

    def open_add_event_form(self):
        form_win = tk.Toplevel(self)
        form_win.title("Add New Event")
        form_win.geometry("500x450")
        form_win.configure(bg=COLORS["bg"])
        form_win.transient(self)
        form_win.grab_set()

        form_frame = tk.Frame(form_win, bg=COLORS["bg"], padx=20, pady=20)
        form_frame.pack(fill="both", expand=True)

        tk.Label(form_frame, text="Event Title:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w")
        title_entry = tk.Entry(form_frame, font=FONTS["body"], bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], relief="solid", bd=1)
        title_entry.pack(fill="x", ipady=5, pady=(2, 10))

        tk.Label(form_frame, text="Event Date:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w")
        date_entry = DateEntry(form_frame, date_pattern='yyyy-mm-dd', background=COLORS["accent"], foreground=COLORS["accent_fg"], borderwidth=2)
        date_entry.pack(fill="x", ipady=5, pady=(2, 10))

        tk.Label(form_frame, text="Audience:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w")
        target_var = tk.StringVar(value="All")
        tk.Radiobutton(form_frame, text="All", variable=target_var, value="All", bg=COLORS["bg"], fg=COLORS["text_fg"], selectcolor=COLORS["entry_bg"]).pack(anchor="w")
        tk.Radiobutton(form_frame, text="Students Only", variable=target_var, value="Student", bg=COLORS["bg"], fg=COLORS["text_fg"], selectcolor=COLORS["entry_bg"]).pack(anchor="w")
        tk.Radiobutton(form_frame, text="Alumni Only", variable=target_var, value="Alumni", bg=COLORS["bg"], fg=COLORS["text_fg"], selectcolor=COLORS["entry_bg"]).pack(anchor="w", pady=(0, 10))

        tk.Label(form_frame, text="Description:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w")
        desc_text = tk.Text(form_frame, height=5, bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], font=FONTS["body"], relief="solid", bd=1)
        desc_text.pack(fill="both", expand=True)

        def save_event():
            title, date, target, desc = title_entry.get(), date_entry.get(), target_var.get(), desc_text.get("1.0", "end-1c")
            if not all([title, date, desc]):
                messagebox.showerror("Error", "All fields are required.", parent=form_win)
                return
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO events (institution_code, title, description, event_date, target_role) VALUES (?, ?, ?, ?, ?)", (self.institution_code, title, desc, date, target))
                conn.commit()
                messagebox.showinfo("Success", "Event created.", parent=form_win)
                form_win.destroy()
                self.refresh_data()
            except Exception as e:
                conn.rollback()
                messagebox.showerror("Error", f"Could not save event: {e}", parent=form_win)
            finally:
                conn.close()

        save_btn = tk.Button(form_frame, text="Save Event", command=save_event, bg=COLORS["accent"], fg=COLORS["accent_fg"])
        save_btn.pack(pady=20)

class AdminManageJobsPage(tk.Frame):
    def __init__(self, parent, dashboard):
        super().__init__(parent, bg=COLORS["bg"])
        self.dashboard = dashboard
        self.institution_code = dashboard.institution_code
        self.create_widgets()

    def create_widgets(self):
        top_frame = tk.Frame(self, bg=COLORS["bg"])
        top_frame.pack(fill="x", padx=30, pady=20)
        tk.Label(top_frame, text="Manage Jobs", font=FONTS["title"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(side="left")

        add_btn = tk.Button(top_frame, text="✚ Post New Job", command=self.open_add_job_form, bg=COLORS["accent"], fg=COLORS["accent_fg"], font=FONTS["body_bold"], relief="flat", padx=10, pady=5)
        add_btn.pack(side="right")
        del_btn = tk.Button(top_frame, text="✖ Delete Selected", command=self.delete_job, bg=COLORS["danger"], fg=COLORS["accent_fg"], font=FONTS["body_bold"], relief="flat", padx=10, pady=5)
        del_btn.pack(side="right", padx=10)

        tree_frame = tk.Frame(self, bg=COLORS["frame_bg"])
        tree_frame.pack(fill="both", expand=True, padx=30, pady=10)
        self.job_tree = ttk.Treeview(tree_frame, columns=("ID", "Title", "Company", "Location"), show="headings")
        self.job_tree.heading("ID", text="ID"); self.job_tree.column("ID", width=50, anchor="center")
        self.job_tree.heading("Title", text="Title"); self.job_tree.column("Title", width=250)
        self.job_tree.heading("Company", text="Company"); self.job_tree.column("Company", width=150)
        self.job_tree.heading("Location", text="Location"); self.job_tree.column("Location", width=150)
        self.job_tree.pack(fill="both", expand=True)

    def refresh_data(self):
        for i in self.job_tree.get_children(): self.job_tree.delete(i)
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, title, company, location FROM jobs WHERE institution_code=? ORDER BY post_date DESC", (self.institution_code,))
            for row in cursor.fetchall(): self.job_tree.insert("", "end", values=(row['id'], row['title'], row['company'], row['location']), iid=row['id'])
        finally:
            conn.close()

    def delete_job(self):
        selected = self.job_tree.focus()
        if not selected:
            messagebox.showwarning("Selection Error", "Please select a job to delete.", parent=self)
            return
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this job posting?", parent=self):
            job_id = self.job_tree.item(selected)['values'][0]
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM jobs WHERE id=?", (job_id,))
                conn.commit()
                self.refresh_data()
            except sqlite3.Error as e:
                conn.rollback()
                messagebox.showerror("Error", f"Could not delete job: {e}", parent=self)
            finally:
                conn.close()

    def open_add_job_form(self):
        form_win = tk.Toplevel(self)
        form_win.title("Post New Job")
        form_win.geometry("550x550")
        form_win.configure(bg=COLORS["bg"])
        form_win.transient(self)
        form_win.grab_set()

        scroll_frame = ScrollableFrame(form_win)
        scroll_frame.pack(fill="both", expand=True)
        form = scroll_frame.scrollable_frame

        tk.Label(form, text="Job Title:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", padx=20, pady=(20,0))
        title_entry = tk.Entry(form, font=FONTS["body"], bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], relief="solid", bd=1)
        title_entry.pack(fill="x", ipady=5, pady=(2, 10), padx=20)

        tk.Label(form, text="Company:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", padx=20)
        company_entry = tk.Entry(form, font=FONTS["body"], bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], relief="solid", bd=1)
        company_entry.pack(fill="x", ipady=5, pady=(2, 10), padx=20)

        tk.Label(form, text="Location:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", padx=20)
        location_entry = tk.Entry(form, font=FONTS["body"], bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], relief="solid", bd=1)
        location_entry.pack(fill="x", ipady=5, pady=(2, 10), padx=20)

        tk.Label(form, text="Application Link (Optional):", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", padx=20)
        link_entry = tk.Entry(form, font=FONTS["body"], bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], relief="solid", bd=1)
        link_entry.pack(fill="x", ipady=5, pady=(2, 10), padx=20)

        tk.Label(form, text="Description:", font=FONTS["body_bold"], fg=COLORS["text_fg"], bg=COLORS["bg"]).pack(anchor="w", padx=20)
        desc_text = tk.Text(form, height=8, bg=COLORS["entry_bg"], fg=COLORS["entry_fg"], font=FONTS["body"], relief="solid", bd=1)
        desc_text.pack(fill="x", expand=True, padx=20)

        def save_job():
            title = title_entry.get().strip()
            company = company_entry.get().strip()
            loc = location_entry.get().strip()
            link = link_entry.get().strip()
            desc = desc_text.get("1.0", "end-1c").strip()

            if not all([title, company, desc]):
                messagebox.showerror("Error", "Title, Company, and Description are required.", parent=form_win)
                return

            if link and not (link.startswith('http://') or link.startswith('https://')):
                messagebox.showwarning("Invalid Link", "The application link appears to be invalid. Please ensure it starts with 'http://' or 'https://'.", parent=form_win)
                return

            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO jobs (institution_code, title, company, location, apply_link, description) VALUES (?, ?, ?, ?, ?, ?)",
                               (self.institution_code, title, company, loc, link, desc))
                conn.commit()
                messagebox.showinfo("Success", "Job posted successfully.", parent=form_win)
                form_win.destroy()
                self.refresh_data()
            except Exception as e:
                conn.rollback()
                messagebox.showerror("Error", f"Could not post job: {e}", parent=form_win)
            finally:
                conn.close()

        save_btn = tk.Button(form, text="Post Job", command=save_job, bg=COLORS["accent"], fg=COLORS["accent_fg"])
        save_btn.pack(pady=20)

class AdminDashboard(tk.Toplevel):
    def __init__(self, controller, institution_code):
        super().__init__()
        self.controller = controller
        self.institution_code = institution_code
        self.title("Administrator Dashboard")
        self.state('zoomed')
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.configure(bg=COLORS["bg"])

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM institutions WHERE code=?", (self.institution_code,))
        self.institution_name = cursor.fetchone()['name']
        conn.close()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar_frame = tk.Frame(self, bg=COLORS["frame_bg"], width=250)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsw")
        self.sidebar_frame.pack_propagate(False)

        self.content_frame = tk.Frame(self, bg=COLORS["bg"])
        self.content_frame.grid(row=0, column=1, sticky="nsew")
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)

        self.pages = {}
        self.sidebar_buttons = {}
        self.setup_sidebar()
        self.show_page("Dashboard")

    def setup_sidebar(self):
        tk.Label(self.sidebar_frame, text=f"{self.institution_name}", font=FONTS["header"], bg=COLORS["frame_bg"], fg=COLORS["accent"], wraplength=230).pack(pady=20, padx=10)

        menu_items = [
            ("Dashboard", "assets/analytics.png", AdminAnalyticsPage),
            ("Manage Users", "assets/users.png", AdminManageUsersPage),
            ("User Directory", "assets/directory1.png", AllUsersDirectoryPage), # Added
            ("Post Message", "assets/message.png", AdminPostMessagePage),
            ("Manage Events", "assets/manage_events.png", AdminManageEventsPage),
            ("Manage Jobs", "assets/manage_jobs.png", AdminManageJobsPage),
        ]

        for text, icon, Page in menu_items:
            button = SidebarButton(self.sidebar_frame, text, icon, command=lambda p=text: self.show_page(p))
            button.pack(fill="x", pady=2)
            self.sidebar_buttons[text] = button
            self.pages[text] = Page(self.content_frame, self)
            self.pages[text].grid(row=0, column=0, sticky="nsew")

        logout_btn = SidebarButton(self.sidebar_frame, "Logout", "assets/logout.png", self.logout)
        logout_btn.pack(side="bottom", fill="x", pady=20)

    def show_page(self, page_name):
        for name, button in self.sidebar_buttons.items():
            button.set_active(name == page_name)
        page = self.pages[page_name]
        page.tkraise()
        if hasattr(page, 'refresh_data'):
            page.refresh_data()

    def logout(self):
        self.destroy()
        self.controller.return_to_login()

    def on_close(self):
        self.destroy()
        self.controller.destroy()


# ==============================================================================
# SECTION 7: MAIN APPLICATION CONTROLLER CLASS
# ==============================================================================

class RoleApp(tk.Tk):
    """
    The main application controller. It manages frames and transitions
    between the login/signup screens and the main dashboards.
    """
    def __init__(self):
        super().__init__()
        self.title("Alumni Connect")
        self.state('zoomed')
        self.configure(bg=COLORS["bg"])
        self.minsize(1024, 768)

        container = tk.Frame(self, bg=COLORS["bg"])
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        self.current_user = None

        for F in (LoginFrame, SignupFrame):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LoginFrame")

    def show_frame(self, page_name: str) -> None:
        """Raises a specific frame to the top."""
        frame = self.frames[page_name]
        if page_name == "SignupFrame":
            frame.load_institutions()
        frame.tkraise()

    def show_dashboard(self, username: str, roles: list) -> None:
        """Hides the login window and shows the appropriate user/admin dashboard."""
        self.current_user = username
        self.withdraw()

        if "Administrator" in roles:
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT code FROM institutions WHERE admin=?", (username,))
                result = cursor.fetchone()
            finally:
                conn.close()

            if result:
                AdminDashboard(controller=self, institution_code=result['code'])
            else:
                messagebox.showerror("Error", "Admin data inconsistent. Could not find associated institution.")
                self.return_to_login()
        else:
            UserDashboard(controller=self, username=username, roles=roles)

    def return_to_login(self) -> None:
        """Clears user session and returns to the login screen."""
        self.current_user = None
        self.frames["LoginFrame"].clear_fields()
        self.deiconify()
        self.show_frame("LoginFrame")


# ==============================================================================
# SECTION 8: APPLICATION ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    initialize_database()

    app = RoleApp()

    setup_ttk_styles()

    app.mainloop()