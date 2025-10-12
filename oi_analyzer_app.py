import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import requests
import pandas as pd
import json
from datetime import datetime, timezone, time, timedelta
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import webbrowser # Import webbrowser for OTA update process

# --- NEW: Pillow library is required for displaying ad images ---
# Install it using pip: pip install Pillow
from PIL import Image, ImageTk

# --- NEW: tkcalendar library is required for the date selector ---
# Install it using pip: pip install tkcalendar
from tkcalendar import DateEntry

# --- REMOVED: Selenium and related browser/proxy libraries are no longer needed ---

# --- Firebase & Google Auth ---
# These libraries are required. Install them using pip:
# pip install firebase-admin google-auth-oauthlib google-api-python-client
import firebase_admin
from firebase_admin import credentials, firestore
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import os
import pickle
import sys # Import sys for the update process
import subprocess # Import subprocess for the update process

# ==============================================================================
# --- NEW: Standard Browser Header ---
# ==============================================================================
# This header makes all requests from the app appear as if they are coming
# from a standard Chrome browser on a Windows machine.
BROWSER_HEADER = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}
# ==============================================================================


# ==============================================================================
# --- NEW: OTA Update Configuration ---
# ==============================================================================
# The current version of the application.
CURRENT_VERSION = "3.3.0" 

# The URL to the raw version.json file on your GitHub repository.
# This file tells the app about the latest version and where to download it.
# IMPORTANT: You must create this file in a public GitHub repo for this to work.
VERSION_URL = "https://raw.githubusercontent.com/nobyali/oi-analyzer/main/version.json"
# ==============================================================================

# --- REMOVED: ZenRows API Key is no longer needed ---


# ==============================================================================
# IMPORTANT: FIREBASE CONFIGURATION
# 1. Create a new project at https://console.firebase.google.com/
# 2. Go to Project Settings -> Service accounts -> Generate new private key.
#    This will download a JSON file. RENAME IT TO 'serviceAccountKey.json'
#    and place it in the same directory as this script.
# 3. Go to Project Settings -> General. Scroll down to "Your apps".
#    Click the Web icon (</>) to create a new Web App.
# 4. Copy the 'firebaseConfig' object and paste its contents below.
# 5. Go to Authentication -> Sign-in method -> Add Google as a provider.
# 6. Go to Firestore Database -> Create database -> Start in production mode.
#    In the "Rules" tab, change the rules to `allow read, write: if request.auth != null;` and publish.
# ==============================================================================

# --- Admin Configuration ---
# After you log in with your Google account for the first time, get your
# User UID from the Firebase Authentication console (under the 'Users' tab)
# and paste it here to enable the Admin Panel button in the app.
ADMIN_UID = "115235049999133238334" # Replace with your actual Admin UID from Firebase

# --- NEW: Nifty 50 Stock List for Autocomplete ---
NIFTY_50_STOCKS = [
    'ADANIENT', 'ADANIPORTS', 'APOLLOHOSP', 'ASIANPAINT', 'AXISBANK', 
    'BAJAJ-AUTO', 'BAJFINANCE', 'BAJAJFINSV', 'BPCL', 'BHARTIARTL', 
    'BRITANNIA', 'CIPLA', 'COALINDIA', 'DIVISLAB', 'DRREDDY', 'EICHERMOT', 
    'GRASIM', 'HCLTECH', 'HDFCBANK', 'HDFCLIFE', 'HEROMOTOCO', 'HINDALCO', 
    'HINDUNILVR', 'ICICIBANK', 'ITC', 'INDUSINDBK', 'INFY', 'JSWSTEEL', 
    'KOTAKBANK', 'LTIM', 'LT', 'M&M', 'MARUTI', 'NTPC', 'NESTLEIND', 
    'ONGC', 'POWERGRID', 'RELIANCE', 'SBILIFE', 'SBIN', 'SUNPHARMA', 
    'TCS', 'TATACONSUM', 'TATAMOTORS', 'TATASTEEL', 'TECHM', 'TITAN', 
    'ULTRACEMCO', 'UPL', 'WIPRO'
]

# --- NEW: MCX Symbol List ---
MCX_SYMBOLS = [
    'GOLD', 'SILVER', 'CRUDEOIL', 'NATURALGAS', 'COPPER', 'ZINC'
]


# --- REVISED: Custom Autocomplete Entry Widget ---
class AutocompleteEntry(ttk.Entry):
    def __init__(self, parent, *args, **kwargs):
        self.suggestions = kwargs.pop('suggestions', [])
        super().__init__(parent, *args, **kwargs)

        self.suggestion_toplevel = None
        self.suggestion_listbox = None

        self.bind('<KeyRelease>', self.on_key_release)
        self.bind('<Down>', self.focus_on_listbox)
        self.bind('<Escape>', self.hide_suggestions)
        # We handle focus out slightly differently to allow clicks on the listbox
        self.bind('<FocusOut>', lambda e: self.after(100, self.on_focus_out))

    def on_key_release(self, event):
        # Ignore navigation keys to prevent the list from flickering
        if event.keysym in ("Down", "Up", "Return", "Escape", "Shift_L", "Shift_R", "Control_L", "Control_R"):
            return

        entry_text = self.get().upper()
        self.hide_suggestions() # Hide previous suggestions

        if entry_text:
            matches = [s for s in self.suggestions if s.startswith(entry_text)]
            if matches:
                # Create a floating Toplevel window for suggestions
                self.suggestion_toplevel = tk.Toplevel(self)
                self.suggestion_toplevel.wm_overrideredirect(True) # No title bar
                
                # Align the suggestion box perfectly under the entry field
                x = self.winfo_rootx()
                y = self.winfo_rooty() + self.winfo_height()
                width = self.winfo_width()
                
                listbox_height = min(5, len(matches)) * 22 # Approx height based on font
                self.suggestion_toplevel.geometry(f"{width}x{listbox_height}+{x}+{y}")
                
                self.suggestion_listbox = tk.Listbox(self.suggestion_toplevel, height=min(5, len(matches)))
                self.suggestion_listbox.pack(fill=tk.BOTH, expand=True)

                for match in matches:
                    self.suggestion_listbox.insert(tk.END, match)
                
                # Bind events for mouse and keyboard selection
                self.suggestion_listbox.bind('<<ListboxSelect>>', self.on_suggestion_select)
                self.suggestion_listbox.bind('<Return>', self.on_suggestion_select)
                self.suggestion_listbox.bind('<Escape>', self.hide_suggestions)

    def on_suggestion_select(self, event):
        # This function is triggered by both mouse click and the Enter key
        if self.suggestion_listbox:
            selected_indices = self.suggestion_listbox.curselection()
            if selected_indices:
                value = self.suggestion_listbox.get(selected_indices[0])
                self.delete(0, tk.END)
                self.insert(0, value)
                self.hide_suggestions()
                self.focus() # Return focus to the entry field
                self.icursor(tk.END) # Move cursor to the end

    def hide_suggestions(self, event=None):
        if self.suggestion_toplevel:
            self.suggestion_toplevel.destroy()
            self.suggestion_toplevel = None
            self.suggestion_listbox = None
    
    def on_focus_out(self):
        # Hide suggestions only if focus is not on the listbox itself
        if self.suggestion_listbox:
            try:
                if self.focus_get() != self.suggestion_listbox:
                    self.hide_suggestions()
            except tk.TclError:
                # This can happen if the widget is destroyed
                self.hide_suggestions()

    def focus_on_listbox(self, event):
        # Move focus from the entry to the listbox on Down arrow press
        if self.suggestion_listbox:
            self.suggestion_listbox.focus_set()
            self.suggestion_listbox.selection_set(0) # Select the first item


class FirebaseService:
    """Handles all communication with Firebase services."""
    def __init__(self):
        try:
            if not os.path.exists('serviceAccountKey.json'):
                raise FileNotFoundError("Firebase service account key ('serviceAccountKey.json') not found.")
            cred = credentials.Certificate('serviceAccountKey.json')
            firebase_admin.initialize_app(cred)
            self.db = firestore.client()
        except Exception as e:
            messagebox.showerror("Firebase Init Error", f"Could not initialize Firebase Admin SDK: {e}\nPlease ensure 'serviceAccountKey.json' is configured correctly.")
            self.db = None

    def get_user_status(self, uid):
        if not self.db: return 'denied', None
        user_ref = self.db.collection('users').document(uid)
        user_doc = user_ref.get()
        if user_doc.exists:
            return user_doc.to_dict().get('status', 'pending'), user_doc.to_dict()
        return None, None # User does not exist

    def create_user_profile(self, uid, name, email):
        if not self.db: return
        user_ref = self.db.collection('users').document(uid)
        user_ref.set({
            'uid': uid,
            'name': name,
            'email': email,
            'status': 'pending', # All new users are pending approval
            'created_at': firestore.SERVER_TIMESTAMP
        })

    def get_all_users(self):
        if not self.db: return []
        users_ref = self.db.collection('users')
        return [doc.to_dict() for doc in users_ref.stream()]

    def update_user_status(self, uid, new_status):
        """
        Updates a user's status in Firestore.
        BUG FIX: Added try-except block to catch and report errors during the update process,
        ensuring that failures are not silent.
        """
        if not self.db or new_status not in ['approved', 'denied', 'pending']:
            messagebox.showerror("Invalid Operation", "Cannot update status due to invalid parameters or DB connection.")
            return
        try:
            user_ref = self.db.collection('users').document(uid)
            user_ref.update({'status': new_status})
        except Exception as e:
            messagebox.showerror("Firebase Error", f"Failed to update user status in Firestore for UID {uid}.\n\nError: {e}")

    def log_user_activity(self, uid, email, asset_type, symbol):
        """Logs a user's data fetch activity to Firestore."""
        if not self.db: return
        try:
            self.db.collection('usage_logs').add({
                'uid': uid,
                'email': email,
                'asset_type': asset_type,
                'symbol': symbol,
                'timestamp': firestore.SERVER_TIMESTAMP
            })
        except Exception as e:
            print(f"Failed to log user activity: {e}") # Log silently to console

    def get_usage_logs(self):
        """Retrieves all usage logs from Firestore, ordered by most recent."""
        if not self.db: return []
        logs_ref = self.db.collection('usage_logs').order_by('timestamp', direction=firestore.Query.DESCENDING)
        return [doc.to_dict() for doc in logs_ref.stream()]


class AuthService:
    """Handles the Google OAuth2 login flow."""
    SCOPES = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email', 'openid']

    def login_with_google(self):
        creds = None
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists('credentials.json'):
                        messagebox.showerror("Auth Error", "Google API credentials ('credentials.json') not found.")
                        return None
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', self.SCOPES)
                creds = flow.run_local_server(port=0)
            
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
        
        try:
            service = build('oauth2', 'v2', credentials=creds)
            user_info = service.userinfo().get().execute()
            return user_info
        except Exception as e:
            messagebox.showerror("API Error", f"Could not fetch user info: {e}")
            if os.path.exists('token.pickle'):
                os.remove('token.pickle')
            return None
    
    def logout(self):
        if os.path.exists('token.pickle'):
            os.remove('token.pickle')

class AdminPanel(tk.Toplevel):
    """Admin window to approve/deny users and view usage."""
    def __init__(self, parent, firebase_service):
        super().__init__(parent)
        self.title("Admin Panel")
        self.geometry("1000x700") # Increased size
        self.firebase_service = firebase_service

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- RESTRUCTURE: Use a Notebook for different sections ---
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # --- Tab 1: User Management ---
        user_mgmt_frame = ttk.Frame(notebook, padding="10")
        notebook.add(user_mgmt_frame, text="User Management")
        self.create_user_management_tab(user_mgmt_frame)

        # --- Tab 2: Usage Analytics ---
        usage_frame = ttk.Frame(notebook, padding="10")
        notebook.add(usage_frame, text="Usage Analytics")
        self.create_usage_analytics_tab(usage_frame)

    def create_user_management_tab(self, parent):
        controls_frame = ttk.Frame(parent)
        controls_frame.pack(fill=tk.X, pady=5)
        ttk.Button(controls_frame, text="Refresh Users", command=self.populate_users).pack(side=tk.LEFT)
        ttk.Button(controls_frame, text="Approve Selected", command=lambda: self.update_selected_user_status('approved')).pack(side=tk.LEFT, padx=10)
        ttk.Button(controls_frame, text="Deny Selected", command=lambda: self.update_selected_user_status('denied')).pack(side=tk.LEFT)

        self.user_tree = ttk.Treeview(parent, columns=('uid', 'email', 'name', 'status'), show='headings')
        self.user_tree.heading('uid', text='User ID')
        self.user_tree.heading('email', text='Email')
        self.user_tree.heading('name', text='Name')
        self.user_tree.heading('status', text='Status')
        self.user_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        self.user_tree.tag_configure('approved', background='#d4edda')
        self.user_tree.tag_configure('denied', background='#f8d7da')
        self.user_tree.tag_configure('pending', background='#fff3cd')

        self.populate_users()

    def create_usage_analytics_tab(self, parent):
        parent.grid_rowconfigure(2, weight=1)
        parent.grid_rowconfigure(4, weight=2)
        parent.grid_columnconfigure(0, weight=1)

        controls_frame = ttk.Frame(parent)
        controls_frame.grid(row=0, column=0, sticky="ew", pady=5)
        ttk.Button(controls_frame, text="Refresh Usage Data", command=self.populate_usage_data).pack(side=tk.LEFT)

        # --- Summary Table ---
        ttk.Label(parent, text="Usage Summary by User", font=('Segoe UI', 12, 'bold')).grid(row=1, column=0, sticky="w", pady=(10,0))
        self.summary_tree = ttk.Treeview(parent, columns=('email', 'total_requests', 'last_active'), show='headings')
        self.summary_tree.heading('email', text='User Email')
        self.summary_tree.heading('total_requests', text='Total Fetches')
        self.summary_tree.heading('last_active', text='Last Active')
        self.summary_tree.grid(row=2, column=0, sticky="nsew", pady=10)
        self.summary_tree.column('email', width=300)

        # --- Detailed Log Table ---
        ttk.Label(parent, text="Detailed Activity Log", font=('Segoe UI', 12, 'bold')).grid(row=3, column=0, sticky="w")
        self.logs_tree = ttk.Treeview(parent, columns=('timestamp', 'email', 'asset', 'symbol'), show='headings')
        self.logs_tree.heading('timestamp', text='Timestamp')
        self.logs_tree.heading('email', text='User Email')
        self.logs_tree.heading('asset', text='Asset Type')
        self.logs_tree.heading('symbol', text='Symbol')
        self.logs_tree.grid(row=4, column=0, sticky="nsew", pady=10)
        self.logs_tree.column('timestamp', width=200)
        self.logs_tree.column('email', width=300)
        
        self.populate_usage_data()

    def populate_usage_data(self):
        # Clear existing data
        for item in self.summary_tree.get_children(): self.summary_tree.delete(item)
        for item in self.logs_tree.get_children(): self.logs_tree.delete(item)

        logs = self.firebase_service.get_usage_logs()
        if not logs:
            return
        
        # Populate detailed logs tree
        for log in logs:
            ts = log.get('timestamp')
            timestamp_str = ts.strftime('%Y-%m-%d %I:%M:%S %p') if ts else "Processing..."
            self.logs_tree.insert('', 'end', values=(
                timestamp_str,
                log.get('email', 'N/A'),
                log.get('asset_type', 'N/A'),
                log.get('symbol', 'N/A')
            ))

        # Create DataFrame for summary analysis
        df = pd.DataFrame(logs)
        if df.empty or 'email' not in df.columns or 'timestamp' not in df.columns:
            return

        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce').dt.tz_localize(None)
        df.dropna(subset=['timestamp'], inplace=True)

        summary = df.groupby('email').agg(
            total_requests=('email', 'count'),
            last_active=('timestamp', 'max')
        ).reset_index().sort_values(by='total_requests', ascending=False)
        
        for _, row in summary.iterrows():
            self.summary_tree.insert('', 'end', values=(
                row['email'],
                row['total_requests'],
                row['last_active'].strftime('%Y-%m-%d %I:%M:%S %p')
            ))

    def populate_users(self):
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)
        
        users = self.firebase_service.get_all_users()
        for user in sorted(users, key=lambda u: u.get('email', '')):
            status = user.get('status', 'pending')
            self.user_tree.insert('', 'end', values=(user.get('uid'), user.get('email'), user.get('name'), status), tags=(status,))

    def update_selected_user_status(self, new_status):
        selected_item = self.user_tree.focus()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a user from the list.")
            return

        user_uid = str(self.user_tree.item(selected_item)['values'][0])
        if messagebox.askyesno("Confirm Action", f"Are you sure you want to set status to '{new_status}' for user {user_uid}?"):
            self.firebase_service.update_user_status(user_uid, new_status)
            self.populate_users()


class MainApplicationFrame(ttk.Frame):
    """The main OI Analyzer application view."""
    def __init__(self, parent, controller, current_user):
        super().__init__(parent)
        self.controller = controller
        self.current_user = current_user
        self.last_analysis_result = None # NEW: Store last result for export
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.style.configure("Treeview", rowheight=25, font=('Segoe UI', 9))
        self.style.configure("Treeview.Heading", font=('Segoe UI', 10, 'bold'))
        self.style.map('Treeview', background=[('selected', '#a0a0a0')])
        
        self.style.configure("resistance.Treeview", background="#ffe5e5")
        self.style.configure("support.Treeview", background="#e5f5e5")
        self.style.map("resistance.Treeview", background=[('selected', '#ffb3b3')])
        self.style.map("support.Treeview", background=[('selected', '#b3ffb3')])
        
        self.style.configure('max_oi.Treeview', background='yellow', font=('Segoe UI', 9, 'bold'))
        # --- NEW STYLE --- Highlight for the strike nearest to the spot price
        self.style.configure('spot.Treeview', background='#e8daff', font=('Segoe UI', 9, 'bold')) # Light lavender
        
        self.style.configure('Header.TLabel', font=('Segoe UI', 10, 'bold'))
        self.style.configure('Level.TLabel', font=('Segoe UI', 9))
        self.style.configure('R.TLabel', font=('Segoe UI', 9), foreground='#c0392b')
        self.style.configure('S.TLabel', font=('Segoe UI', 9), foreground='#27ae60')
        self.style.configure('P.TLabel', font=('Segoe UI', 9, 'bold'), foreground='#2c3e50')
        self.style.configure('Sub.TLabel', font=('Segoe UI', 7, 'italic'), foreground='#555555')

        # --- NEW: Custom styles for the conviction progress bar ---
        self.style.configure('bullish.Horizontal.TProgressbar', background='#27ae60') # Green
        self.style.configure('bearish.Horizontal.TProgressbar', background='#c0392b') # Red

        self.auto_refresh_job = None
        self.create_widgets()
        
        # --- NEW: Automatically fetch data for the default symbol on startup ---
        # Use 'after' to ensure the main window is fully drawn before fetching.
        self.after(500, self.start_fetch_thread)
        
    def create_widgets(self):
        """
        UI REFACTOR: This method has been completely reorganized to create a new top header bar
        for all controls and primary analysis data, cleaning up the main view.
        """
        main_frame = ttk.Frame(self, padding="5")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.grid_rowconfigure(2, weight=1) 
        main_frame.grid_columnconfigure(0, weight=1)

        # --- Top Header Bar ---
        top_bar = ttk.Frame(main_frame, style='Card.TFrame', relief="ridge", padding=5)
        top_bar.grid(row=0, column=0, sticky='ew', pady=(0, 5))

        # --- Left Controls (Input) ---
        left_controls = ttk.Frame(top_bar)
        left_controls.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        # --- NEW: Asset Type Selection ---
        asset_type_frame = ttk.Frame(left_controls)
        asset_type_frame.pack(anchor='w', pady=(0, 5))
        ttk.Label(asset_type_frame, text="Asset:", font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=(0, 5))
        self.asset_type_var = tk.StringVar(value="Indices")
        indices_radio = ttk.Radiobutton(asset_type_frame, text="Indices", variable=self.asset_type_var, value="Indices", command=self.update_asset_type_controls)
        indices_radio.pack(side=tk.LEFT)
        # --- NEW: Stocks Radio Button ---
        stocks_radio = ttk.Radiobutton(asset_type_frame, text="Stocks", variable=self.asset_type_var, value="Stocks", command=self.update_asset_type_controls)
        stocks_radio.pack(side=tk.LEFT, padx=5)
        crypto_radio = ttk.Radiobutton(asset_type_frame, text="Crypto", variable=self.asset_type_var, value="Crypto", command=self.update_asset_type_controls)
        crypto_radio.pack(side=tk.LEFT, padx=5)
        # --- NEW: MCX Radio Button ---
        mcx_radio = ttk.Radiobutton(asset_type_frame, text="MCX", variable=self.asset_type_var, value="MCX", command=self.update_asset_type_controls)
        mcx_radio.pack(side=tk.LEFT, padx=5)

        input_frame = ttk.Frame(left_controls)
        input_frame.pack(anchor='w')
        ttk.Label(input_frame, text="Symbol:", font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=(0, 5))
        self.symbol_var = tk.StringVar(value='NIFTY')
        
        # --- MODIFICATION: Use AutocompleteEntry for stock symbols ---
        self.stock_symbol_entry = AutocompleteEntry(input_frame, textvariable=self.symbol_var, width=12, suggestions=NIFTY_50_STOCKS)
        
        self.symbol_menu = ttk.Combobox(input_frame, textvariable=self.symbol_var, values=['NIFTY', 'BANKNIFTY', 'FINNIFTY'], state="readonly", width=10)
        self.symbol_menu.pack(side=tk.LEFT, padx=5) # Initially packed
        
        self.fetch_button = ttk.Button(input_frame, text="Fetch Data", command=self.start_fetch_thread)
        self.fetch_button.pack(side=tk.LEFT, padx=10)
        
        # --- NEW: Expiry Date Selection ---
        self.expiry_label = ttk.Label(input_frame, text="Expiry:", font=('Segoe UI', 10))
        self.expiry_var = tk.StringVar()
        self.expiry_menu = ttk.Combobox(input_frame, textvariable=self.expiry_var, state="readonly", width=12)
        # --- MODIFIED: Use a DateEntry widget for MCX Expiry ---
        self.mcx_expiry_entry = DateEntry(input_frame, textvariable=self.expiry_var, width=12, date_pattern='y-mm-dd', background='darkblue', foreground='white', borderwidth=2)
        
        # Bind symbol changes to update expiry dates
        self.symbol_menu.bind("<<ComboboxSelected>>", self.on_symbol_change)
        self.stock_symbol_entry.bind("<Return>", self.on_symbol_change)
        
        # Call this to set the initial state correctly
        self.update_asset_type_controls()


        refresh_frame = ttk.Frame(left_controls)
        refresh_frame.pack(anchor='w', pady=(5,0))
        self.auto_refresh_var = tk.BooleanVar()
        ttk.Checkbutton(refresh_frame, text="Auto Refresh", variable=self.auto_refresh_var, command=self.toggle_auto_refresh).pack(side=tk.LEFT)
        self.refresh_interval_var = tk.StringVar(value='60')
        ttk.Label(refresh_frame, text="every").pack(side=tk.LEFT, padx=(10, 0))
        ttk.Entry(refresh_frame, textvariable=self.refresh_interval_var, width=4).pack(side=tk.LEFT, padx=5)
        ttk.Label(refresh_frame, text="sec").pack(side=tk.LEFT)
        
        # --- NEW: Switch to toggle analysis panels ---
        self.show_analysis_panels_var = tk.BooleanVar(value=True)
        analysis_toggle = ttk.Checkbutton(left_controls, text="Show Analysis Panels", variable=self.show_analysis_panels_var, command=self.toggle_analysis_panels)
        analysis_toggle.pack(anchor='w', pady=(5,0))

        ttk.Separator(top_bar, orient='vertical').pack(side=tk.LEFT, fill='y', padx=10)

        # --- Center Display (Strategy Signal) ---
        strategy_frame = ttk.Frame(top_bar)
        strategy_frame.pack(side=tk.LEFT, fill=tk.Y, expand=True)
        self.strategy_label = ttk.Label(strategy_frame, text="MOST PROBABLE DIRECTION: Waiting for data...", font=('Segoe UI', 12, 'bold'), anchor='center')
        self.strategy_label.pack(pady=(5,0), expand=True)
        self.strategy_reason_label = ttk.Label(strategy_frame, text="Reason: -", font=('Segoe UI', 9), wraplength=400, justify='center')
        self.strategy_reason_label.pack(pady=(0,5), expand=True)
        
        ttk.Separator(top_bar, orient='vertical').pack(side=tk.LEFT, fill='y', padx=10)

        # --- Right Controls (Probabilistic Analysis & Session) ---
        right_controls = ttk.Frame(top_bar)
        right_controls.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        
        # Probabilistic analysis moved here
        prob_frame = ttk.Frame(right_controls)
        prob_frame.pack(side=tk.LEFT, fill=tk.Y)
        self.create_probabilistic_display(prob_frame)
        
        # Session controls
        session_frame = ttk.Frame(right_controls)
        session_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(10,0))
        # --- NEW: About Button ---
        ttk.Button(session_frame, text="About", command=self.show_about_dialog).pack(side=tk.TOP, anchor='ne')
        # --- NEW: Export Button ---
        ttk.Button(session_frame, text="Export CSV", command=self.export_to_csv).pack(side=tk.TOP, anchor='ne', pady=(5,0))
        if self.current_user.get('id') == ADMIN_UID:
            ttk.Button(session_frame, text="Admin Panel", command=self.open_admin_panel).pack(side=tk.TOP, anchor='ne', pady=(5,0))
        ttk.Button(session_frame, text="Logout", command=self.controller.logout).pack(side=tk.TOP, anchor='ne', pady=(5,0))


        # --- NEW: Container for the two side-by-side analysis panels ---
        self.analysis_panels_frame = ttk.Frame(main_frame)
        self.analysis_panels_frame.grid(row=1, column=0, sticky='ew', pady=(5, 10), padx=5)
        self.analysis_panels_frame.grid_columnconfigure(0, weight=1)
        self.analysis_panels_frame.grid_columnconfigure(1, weight=1)

        # --- Market Structure Analysis Panel ---
        self.create_market_structure_panel(self.analysis_panels_frame)

        # --- NEW: Spot Price Study Panel ---
        self.create_spot_price_study_panel(self.analysis_panels_frame)


        # --- Data Pane (Tables and Charts) ---
        data_pane = ttk.PanedWindow(main_frame, orient=tk.VERTICAL)
        data_pane.grid(row=2, column=0, sticky='nsew')
        tables_frame = ttk.Frame(data_pane)
        data_pane.add(tables_frame, weight=2)
        tables_frame.grid_columnconfigure(0, weight=1)
        tables_frame.grid_columnconfigure(1, weight=1)
        tables_frame.grid_rowconfigure(1, weight=1)

        ttk.Label(tables_frame, text="Resistance (Highest Call OI)", font=('Segoe UI', 12, 'bold'), foreground="#c0392b").grid(row=0, column=0, pady=(0, 5))
        ttk.Label(tables_frame, text="Support (Highest Put OI)", font=('Segoe UI', 12, 'bold'), foreground="#27ae60").grid(row=0, column=1, pady=(0, 5))

        self.resistance_tree = self.create_treeview(tables_frame, "resistance.Treeview")
        self.resistance_tree.grid(row=1, column=0, sticky='nsew', padx=(0, 5))
        self.support_tree = self.create_treeview(tables_frame, "support.Treeview")
        self.support_tree.grid(row=1, column=1, sticky='nsew', padx=(5, 0))

        charts_notebook = ttk.Notebook(data_pane)
        data_pane.add(charts_notebook, weight=3)
        self.create_chart_tab(charts_notebook, "Spot Action")
        self.create_chart_tab(charts_notebook, "OI Difference")
        self.create_chart_tab(charts_notebook, "PCR")
        self.create_chart_tab(charts_notebook, "Max Pain")
        # --- NEW: IV Chart Tab ---
        self.create_chart_tab(charts_notebook, "Implied Volatility")
        self.create_chart_tab(charts_notebook, "Daily OI Change")
        self.create_chart_tab(charts_notebook, "Total Open Interest")
        self.create_chart_tab(charts_notebook, "Integrated OI View")
        self.create_chart_tab(charts_notebook, "Trending Strikes")
        
        self.status_label = ttk.Label(self, text="Ready", relief=tk.SUNKEN, anchor=tk.W, padding=5)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    def create_market_structure_panel(self, parent):
        """NEW: Creates the dedicated UI panel for the new market structure analysis."""
        structure_frame = ttk.LabelFrame(parent, text="OI-Driven Market Structure Analysis", padding="10")
        structure_frame.grid(row=0, column=0, sticky='nsew', padx=(0, 5))
        
        structure_frame.grid_columnconfigure(1, weight=1)

        # Hypothesis Display
        ttk.Label(structure_frame, text="Hypothesis:", font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky='w')
        self.hypothesis_var = tk.StringVar(value="Awaiting Data...")
        ttk.Label(structure_frame, textvariable=self.hypothesis_var, font=('Segoe UI', 11, 'bold'), foreground='#2980b9').grid(row=0, column=1, sticky='w', padx=5)

        # Conviction Strength Display
        ttk.Label(structure_frame, text="Conviction:", font=('Segoe UI', 10, 'bold')).grid(row=1, column=0, sticky='w', pady=(5,0))
        self.conviction_strength_var = tk.DoubleVar(value=0)
        self.conviction_bar = ttk.Progressbar(structure_frame, variable=self.conviction_strength_var, maximum=100)
        self.conviction_bar.grid(row=1, column=1, sticky='ew', padx=5, pady=(5,0))

        # Reasoning Display
        ttk.Label(structure_frame, text="Reasoning:", font=('Segoe UI', 10, 'bold')).grid(row=2, column=0, sticky='nw', pady=(5,0))
        self.reasoning_var = tk.StringVar(value="-")
        ttk.Label(structure_frame, textvariable=self.reasoning_var, font=('Segoe UI', 9, 'italic'), wraplength=1000, justify=tk.LEFT).grid(row=2, column=1, sticky='w', padx=5, pady=(5,0))

    def create_spot_price_study_panel(self, parent):
        """NEW: Creates the UI panel for the spot price and order block analysis."""
        spot_frame = ttk.LabelFrame(parent, text="Current Spot Price Study", padding="10")
        spot_frame.grid(row=0, column=1, sticky='nsew', padx=(5, 0))

        spot_frame.grid_columnconfigure(1, weight=1)

        # Immediate Order Blocks (based on OI Change) - REVISED LABELS
        ttk.Label(spot_frame, text="Immediate Support (Demand):", font=('Segoe UI', 9, 'bold'), foreground='#27ae60').grid(row=0, column=0, sticky='w')
        self.spot_bullish_block_var = tk.StringVar(value="--")
        ttk.Label(spot_frame, textvariable=self.spot_bullish_block_var, font=('Segoe UI', 9)).grid(row=0, column=1, sticky='w', padx=5)

        ttk.Label(spot_frame, text="Immediate Resistance (Supply):", font=('Segoe UI', 9, 'bold'), foreground='#c0392b').grid(row=1, column=0, sticky='w')
        self.spot_bearish_block_var = tk.StringVar(value="--")
        ttk.Label(spot_frame, textvariable=self.spot_bearish_block_var, font=('Segoe UI', 9)).grid(row=1, column=1, sticky='w', padx=5)
        
        # --- NEW: Swing Zones (based on OI concentration between walls) ---
        ttk.Separator(spot_frame, orient='horizontal').grid(row=2, column=0, columnspan=2, sticky='ew', pady=5)
        
        ttk.Label(spot_frame, text="Swing Support:", font=('Segoe UI', 9, 'bold'), foreground='#2980b9').grid(row=3, column=0, sticky='w')
        self.swing_support_var = tk.StringVar(value="--")
        ttk.Label(spot_frame, textvariable=self.swing_support_var, font=('Segoe UI', 9)).grid(row=3, column=1, sticky='w', padx=5)

        ttk.Label(spot_frame, text="Swing Resistance:", font=('Segoe UI', 9, 'bold'), foreground='#8e44ad').grid(row=4, column=0, sticky='w')
        self.swing_resistance_var = tk.StringVar(value="--")
        ttk.Label(spot_frame, textvariable=self.swing_resistance_var, font=('Segoe UI', 9)).grid(row=4, column=1, sticky='w', padx=5)

        # Movement Prediction
        ttk.Separator(spot_frame, orient='horizontal').grid(row=5, column=0, columnspan=2, sticky='ew', pady=5)
        ttk.Label(spot_frame, text="Prediction:", font=('Segoe UI', 10, 'bold')).grid(row=6, column=0, sticky='nw', pady=(8,0))
        self.spot_prediction_var = tk.StringVar(value="Awaiting Data...")
        ttk.Label(spot_frame, textvariable=self.spot_prediction_var, font=('Segoe UI', 9, 'italic'), wraplength=400, justify=tk.LEFT).grid(row=6, column=1, columnspan=2, sticky='w', padx=5, pady=(8,0))

    def toggle_analysis_panels(self):
        """NEW: Hides or shows the analysis panels based on the checkbox state."""
        if self.show_analysis_panels_var.get():
            self.analysis_panels_frame.grid()
        else:
            self.analysis_panels_frame.grid_remove()

    def format_value(self, num):
        """Formats large numbers into a compact representation (e.g., 1.5M, 25K)."""
        if num is None or not isinstance(num, (int, float)):
            return ""
        if abs(num) >= 1_000_000:
            return f'{num / 1_000_000:.1f}M'
        if abs(num) >= 1_000:
            return f'{num / 1_000:.0f}K'
        return f'{num:.0f}'

    def update_asset_type_controls(self):
        """NEW: Updates the symbol input controls based on the selected asset type."""
        asset_type = self.asset_type_var.get()
        
        # Hide all controls first
        self.symbol_menu.pack_forget()
        self.stock_symbol_entry.pack_forget()
        self.expiry_label.pack_forget()
        self.expiry_menu.pack_forget()
        self.mcx_expiry_entry.pack_forget()

        if asset_type == "Indices":
            self.symbol_menu['values'] = ['NIFTY', 'BANKNIFTY', 'FINNIFTY']
            self.symbol_var.set('NIFTY')
            self.symbol_menu.pack(side=tk.LEFT, padx=5)
            self.expiry_label.pack(side=tk.LEFT, padx=(10, 5))
            self.expiry_menu.pack(side=tk.LEFT)
            self.update_expiry_dates()
        elif asset_type == "Stocks":
            self.symbol_var.set('RELIANCE') # Default stock
            self.stock_symbol_entry.pack(side=tk.LEFT, padx=5)
            self.expiry_label.pack(side=tk.LEFT, padx=(10, 5))
            self.expiry_menu.pack(side=tk.LEFT)
            self.update_expiry_dates()
        elif asset_type == "Crypto":
            self.symbol_menu['values'] = ['BTC', 'ETH']
            self.symbol_var.set('BTC')
            self.symbol_menu.pack(side=tk.LEFT, padx=5)
        elif asset_type == "MCX":
            self.symbol_menu['values'] = MCX_SYMBOLS
            self.symbol_var.set('CRUDEOIL')
            self.symbol_menu.pack(side=tk.LEFT, padx=5)
            self.expiry_label.pack(side=tk.LEFT, padx=(10, 5))
            self.mcx_expiry_entry.pack(side=tk.LEFT)
            self.update_expiry_dates()


    def on_symbol_change(self, event=None):
        """NEW: Triggered when the symbol is changed to update expiry dates."""
        self.after(100, self.update_expiry_dates)

    def update_expiry_dates(self):
        """NEW: Fetches and populates the expiry dates dropdown for the selected symbol."""
        asset_type = self.asset_type_var.get()
        symbol = self.symbol_var.get().upper()

        if not symbol or asset_type not in ["Indices", "Stocks", "MCX"]:
            return

        self.expiry_var.set("Loading...")
        self.expiry_menu['values'] = []
        
        def _fetch_expiries():
            expiries = []
            if asset_type == "Indices" or asset_type == "Stocks":
                expiries = self.fetch_nse_expiry_dates(symbol, asset_type)
            elif asset_type == "MCX":
                expiries = self.fetch_mcx_expiry_dates(symbol)
            
            # Schedule the UI update on the main thread
            self.after(0, self.populate_expiry_menu, expiries)

        threading.Thread(target=_fetch_expiries, daemon=True).start()

    def populate_expiry_menu(self, expiries):
        """MODIFIED: Safely populates the expiry dropdown or entry on the main thread."""
        if expiries:
            # For non-MCX assets, populate the dropdown list
            if self.asset_type_var.get() != "MCX":
                self.expiry_menu['values'] = expiries
            # For all asset types, set the default (nearest) expiry
            self.expiry_var.set(expiries[0])
        else:
            self.expiry_var.set("No Expiries Found")
            if self.asset_type_var.get() != "MCX":
                self.expiry_menu['values'] = []


    def create_probabilistic_display(self, parent):
        """UI REFACTOR: Layout changed from pack to a compact grid to fit in the header."""
        self.prob_levels = {}
        
        parent.grid_columnconfigure(1, weight=1)
        
        ttk.Label(parent, text="Trend Prob:", style='Header.TLabel').grid(row=0, column=0, sticky='w')
        prob_frame = ttk.Frame(parent)
        prob_frame.grid(row=0, column=1, columnspan=3, sticky='w')
        self.prob_bull_var = tk.StringVar(value="--%")
        self.prob_bear_var = tk.StringVar(value="--%")
        ttk.Label(prob_frame, textvariable=self.prob_bull_var, style='S.TLabel', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT)
        ttk.Label(prob_frame, textvariable=self.prob_bear_var, style='R.TLabel', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=5)

        self.prob_levels['continuation_up_var'] = self.create_level_row(parent, 1, "Bull Cont:", 'S.TLabel')
        self.prob_levels['reversal_up_var'] = self.create_level_row(parent, 1, "Bull Rev:", 'S.TLabel', col_offset=2)
        self.prob_levels['continuation_down_var'] = self.create_level_row(parent, 2, "Bear Cont:", 'R.TLabel')
        self.prob_levels['reversal_down_var'] = self.create_level_row(parent, 2, "Bear Rev:", 'R.TLabel', col_offset=2)

        # --- NEW: Bayesian Probability Display ---
        ttk.Label(parent, text="Bayesian Prob:", style='Header.TLabel').grid(row=3, column=0, sticky='w', pady=(5,0))
        self.bayesian_prob_var = tk.StringVar(value="--%")
        self.bayesian_prob_label = ttk.Label(parent, textvariable=self.bayesian_prob_var, font=('Segoe UI', 12, 'bold'))
        self.bayesian_prob_label.grid(row=3, column=1, columnspan=3, sticky='w', pady=(5,0))

    def create_level_row(self, parent, row_idx, title, style, col_offset=0):
        var = tk.StringVar(value="---")
        ttk.Label(parent, text=title, style='Level.TLabel').grid(row=row_idx, column=0 + col_offset, sticky='w', pady=(5,0))
        ttk.Label(parent, textvariable=var, style=style, font=('Segoe UI', 9, 'bold')).grid(row=row_idx, column=1 + col_offset, sticky='w', pady=(5,0))
        return var
                
    def create_chart_tab(self, notebook, text):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=text)
        fig, ax = plt.subplots(facecolor='#f0f0f0')
        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        setattr(self, f"{text.lower().replace(' ', '_')}_fig", fig)
        setattr(self, f"{text.lower().replace(' ', '_')}_ax", ax)
        setattr(self, f"{text.lower().replace(' ', '_')}_canvas", canvas)
        self.init_chart(ax, text)
        return frame

    def init_chart(self, ax, title):
        ax.set_title(title)
        ax.grid(axis='y', linestyle='--', alpha=0.7)
        ax.figure.tight_layout()

    def create_treeview(self, parent, style_name):
        # --- NEW: Added 'iv' column ---
        columns = ('strike', 'iv', 'oi', 'change_oi', 'sentiment')
        tree = ttk.Treeview(parent, columns=columns, show='headings', style=style_name)
        tree.heading('strike', text='Strike Price')
        tree.heading('iv', text='IV (%)')
        tree.heading('oi', text='Open Interest')
        tree.heading('change_oi', text='Change in OI')
        tree.heading('sentiment', text='Sentiment')
        
        tree.column('strike', anchor=tk.CENTER, width=100)
        tree.column('iv', anchor=tk.CENTER, width=80)
        tree.column('oi', anchor=tk.E, width=130)
        tree.column('change_oi', anchor=tk.E, width=130)
        tree.column('sentiment', anchor=tk.CENTER, width=120)
        return tree

    def toggle_auto_refresh(self):
        if self.auto_refresh_var.get():
            self.status_label.config(text="Starting auto-refresh...")
            self.run_auto_refresh()
        else:
            if self.auto_refresh_job:
                self.after_cancel(self.auto_refresh_job)
                self.auto_refresh_job = None
                self.status_label.config(text="Auto-refresh stopped.")

    def is_market_hours(self):
        """Checks if the current time is within NSE market hours (9:15 AM - 3:30 PM IST)."""
        # India Standard Time is UTC +5:30
        ist_offset = timedelta(hours=5, minutes=30)
        ist_now = datetime.now(timezone.utc) + ist_offset
        
        # Check if it's a weekday (Monday=0, Sunday=6)
        if ist_now.weekday() >= 5:
            return False # It's Saturday or Sunday

        # Define market open and close times
        market_open = time(9, 15)
        market_close = time(15, 30)

        # Check if current time is within the market hours
        return market_open <= ist_now.time() <= market_close

    def is_mcx_market_hours(self):
        """NEW: Checks if the current time is within MCX market hours (9:00 AM - 11:30 PM IST)."""
        ist_offset = timedelta(hours=5, minutes=30)
        ist_now = datetime.now(timezone.utc) + ist_offset
        
        if ist_now.weekday() >= 5:
            return False # It's Saturday or Sunday

        # Define market open and close times (using 11:30 PM as a general close)
        market_open = time(9, 0)
        market_close = time(23, 30)

        return market_open <= ist_now.time() <= market_close

    def run_auto_refresh(self):
        """
        --- REVISED ---
        This function is now a smart scheduler. It triggers an immediate fetch and then
        calculates the delay until the next fetch based on the asset type and market hours.
        """
        # --- BUG FIX: The main fetch is now handled by the thread, so we just schedule the next run here. ---
        if not self.auto_refresh_var.get():
            return
            
        # First, run the fetch in a thread
        self.start_fetch_thread() 

        try:
            interval_sec = int(self.refresh_interval_var.get())
            if interval_sec <= 5: # Add a minimum threshold to prevent accidental spamming
                interval_sec = 5
                self.refresh_interval_var.set('5')
            
            asset_type = self.asset_type_var.get()
            delay_ms = interval_sec * 1000

            # Check market hours for NSE assets
            if (asset_type == "Indices" or asset_type == "Stocks") and not self.is_market_hours():
                # Market is closed, so calculate a long delay until the next market open.
                ist_offset = timedelta(hours=5, minutes=30)
                now_ist = datetime.now(timezone.utc) + ist_offset
                
                next_open = now_ist.replace(hour=9, minute=15, second=0, microsecond=0)

                if now_ist.time() > time(15, 30): # If it's after today's market close
                    next_open += timedelta(days=1)

                # Skip weekends
                if next_open.weekday() == 5: # If next open is a Saturday
                    next_open += timedelta(days=2)
                elif next_open.weekday() == 6: # If next open is a Sunday
                    next_open += timedelta(days=1)
                
                delay_seconds = (next_open - now_ist).total_seconds()
                delay_ms = int(delay_seconds * 1000)
                
                next_open_str = next_open.strftime('%a, %b %d at %I:%M %p')
                # Use self.after to ensure this UI update runs on the main thread
                self.after(0, self.update_status, f"Market closed. Next NSE refresh at {next_open_str}.")
            
            # --- NEW: Check market hours for MCX assets ---
            elif asset_type == "MCX" and not self.is_mcx_market_hours():
                # Market is closed, so calculate a long delay until the next market open.
                ist_offset = timedelta(hours=5, minutes=30)
                now_ist = datetime.now(timezone.utc) + ist_offset
                
                next_open = now_ist.replace(hour=9, minute=0, second=0, microsecond=0)

                if now_ist.time() > time(23, 30): # If it's after today's market close
                    next_open += timedelta(days=1)

                if next_open.weekday() == 5: # Saturday
                    next_open += timedelta(days=2)
                elif next_open.weekday() == 6: # Sunday
                    next_open += timedelta(days=1)
                
                delay_seconds = (next_open - now_ist).total_seconds()
                delay_ms = int(delay_seconds * 1000)
                
                next_open_str = next_open.strftime('%a, %b %d at %I:%M %p')
                self.after(0, self.update_status, f"Market closed. Next MCX refresh at {next_open_str}.")


            # Schedule the next call to this scheduler function
            self.auto_refresh_job = self.after(delay_ms, self.run_auto_refresh)

        except (ValueError, TypeError):
            messagebox.showerror("Invalid Input", "Please enter a valid positive number for the interval (in seconds).")
            self.auto_refresh_var.set(False)

    def start_fetch_thread(self):
        symbol = self.symbol_var.get().upper()
        if not symbol:
            messagebox.showwarning("Input Required", "Please enter a symbol.")
            return

        self.fetch_button.config(state=tk.DISABLED)
        self.status_label.config(text=f"Fetching data for {symbol}...")
        thread = threading.Thread(target=self.fetch_and_display_data, daemon=True)
        thread.start()

    def fetch_and_display_data(self):
        # --- BUG FIX: Removed duplicated auto-refresh logic to prevent RuntimeError ---
        symbol = self.symbol_var.get().upper()
        asset_type = self.asset_type_var.get()
        # --- NEW: Get selected expiry date ---
        expiry_date = self.expiry_var.get() if asset_type != "Crypto" else None

        # --- NEW: Log user activity ---
        if self.current_user:
            self.controller.firebase_service.log_user_activity(
                self.current_user.get('id'),
                self.current_user.get('email'),
                asset_type,
                symbol
            )

        if asset_type == "Indices" or asset_type == "Stocks":
            oi_data = self.fetch_nse_oi_data(symbol, asset_type)
        elif asset_type == "MCX":
            # --- MODIFIED: Pass expiry date to MCX fetcher ---
            oi_data = self.fetch_mcx_oi_data(symbol, expiry_date)
        else: # Crypto
            oi_data = self.fetch_crypto_oi_data(symbol)
        
        if not oi_data:
            self.controller.after(0, self.update_status, f"Failed to fetch Option Chain data for {symbol}.")
            self.controller.after(0, lambda: self.fetch_button.config(state=tk.NORMAL))
            return
            
        analysis_result = self.analyze_oi(oi_data, asset_type, symbol, expiry_date)
        # --- NEW: Store result for export ---
        self.last_analysis_result = analysis_result
        self.controller.after(0, self.update_gui, analysis_result)

    def update_gui(self, analysis_result):
        if not analysis_result:
            self.update_status("Error analyzing data. Check console.")
            self.fetch_button.config(state=tk.NORMAL)
            return

        (res_df, sup_df, spot_df, full_chart_df, trending_df, 
         pcr_df, max_pain_df, max_pain_strike, info, strategy, prob_levels, 
         bayesian_result, structure_analysis, spot_price_analysis) = analysis_result

        if info:
            info_text = f"Analysis for: {info['symbol']} | Spot Price: {info['price']} | Last Updated: {info['time']}"
            self.controller.title(info_text)
        
        # --- MODIFICATION --- Pass spot price to populate_treeview for highlighting
        spot_price = info.get('price', 0)
        self.update_strategy_display(strategy)
        self.update_probabilistic_display(prob_levels)
        self.update_bayesian_display(bayesian_result) 
        self.update_market_structure_display(structure_analysis) # NEW: Update structure panel
        self.update_spot_price_study_display(spot_price_analysis) # NEW: Update spot study panel
        self.populate_treeview(self.resistance_tree, res_df, spot_price)
        self.populate_treeview(self.support_tree, sup_df, spot_price)

        self.update_spot_chart(spot_df, info)
        self.update_change_oi_chart(full_chart_df, info)
        self.update_total_oi_chart(full_chart_df, info)
        # --- MODIFICATION --- Pass spot_df for directional arrow analysis
        self.update_integrated_oi_chart(full_chart_df, spot_df, info)
        self.update_trending_strikes_chart(trending_df, info)
        self.update_oi_difference_chart(full_chart_df, info)
        self.update_pcr_chart(pcr_df, info)
        self.update_max_pain_chart(max_pain_df, max_pain_strike, info)
        # --- NEW: Call IV chart update ---
        self.update_iv_chart(full_chart_df, info)

        self.update_status(f"Data loaded successfully. Max Pain: {max_pain_strike}. Probable Direction: {strategy.get('signal', 'N/A')}")
        self.fetch_button.config(state=tk.NORMAL)

    def update_strategy_display(self, strategy):
        if not strategy: return
        signal = strategy.get('signal', 'NEUTRAL')
        reason = strategy.get('reason', '-')
        color = strategy.get('color', 'black')
        self.strategy_label.config(text=f"MOST PROBABLE DIRECTION: {signal}", foreground=color)
        self.strategy_reason_label.config(text=f"Reason: {reason}")

    def update_market_structure_display(self, analysis):
        """NEW: Updates the market structure panel with the latest analysis."""
        if not analysis:
            self.hypothesis_var.set("Awaiting Data...")
            self.conviction_strength_var.set(0)
            self.reasoning_var.set("-")
            return

        self.hypothesis_var.set(analysis.get('hypothesis', 'Calculation Error'))
        self.reasoning_var.set(analysis.get('reasoning', ''))
        
        conviction = analysis.get('conviction_score', 0)
        # We display absolute strength, the color indicates direction
        self.conviction_strength_var.set(abs(conviction))

        if conviction > 0:
            self.conviction_bar.config(style='bullish.Horizontal.TProgressbar')
        else:
            self.conviction_bar.config(style='bearish.Horizontal.TProgressbar')

    def update_spot_price_study_display(self, analysis):
        """NEW: Updates the spot price study panel with the latest analysis."""
        if not analysis:
            self.spot_bullish_block_var.set("--")
            self.spot_bearish_block_var.set("--")
            self.spot_prediction_var.set("Awaiting Data...")
            return

        self.spot_bullish_block_var.set(analysis.get('bullish_block', '--'))
        self.spot_bearish_block_var.set(analysis.get('bearish_block', '--'))
        self.spot_prediction_var.set(analysis.get('prediction', '...'))
        # --- NEW: Update swing zone labels ---
        self.swing_support_var.set(analysis.get('swing_support', '--'))
        self.swing_resistance_var.set(analysis.get('swing_resistance', '--'))


    def update_probabilistic_display(self, levels):
        if not levels:
            self.prob_bull_var.set("--%")
            self.prob_bear_var.set("--%")
            for var in self.prob_levels.values():
                var.set("---")
            return

        self.prob_bull_var.set(f"Bullish: {levels.get('prob_bullish', 0):.1%}")
        self.prob_bear_var.set(f"Bearish: {levels.get('prob_bearish', 0):.1%}")
        
        self.prob_levels['reversal_up_var'].set(f"{levels.get('reversal_up', 'N/A')}")
        self.prob_levels['reversal_down_var'].set(f"{levels.get('reversal_down', 'N/A')}")
        self.prob_levels['continuation_up_var'].set(f"{levels.get('continuation_up', 'N/A')}")
        self.prob_levels['continuation_down_var'].set(f"{levels.get('continuation_down', 'N/A')}")

    def update_bayesian_display(self, bayesian_result):
        if not bayesian_result:
            self.bayesian_prob_var.set("--%")
            self.bayesian_prob_label.config(foreground='black')
            return

        prob_bullish = bayesian_result.get('bullish', 0.5)
        if prob_bullish >= 0.5:
            text = f"Bullish: {prob_bullish:.1%}"
            color = "#27ae60" # Green
        else:
            prob_bearish = bayesian_result.get('bearish', 0.5)
            text = f"Bearish: {prob_bearish:.1%}"
            color = "#c0392b" # Red
            
        self.bayesian_prob_var.set(text)
        self.bayesian_prob_label.config(foreground=color)
        
    def populate_treeview(self, tree, df, spot_price):
        """ --- REVISED --- Logic updated to highlight the single strike closest to the spot price."""
        for item in tree.get_children(): tree.delete(item)
        if df is None or df.empty or spot_price == 0: return
        
        max_oi_strike = df.loc[df['OI'].idxmax()]['Strike Price']
        
        # --- REVISED LOGIC ---
        # Find the single strike price closest to the spot price from the dataframe
        atm_strike = df.iloc[(df['Strike Price'] - spot_price).abs().argsort()[:1]].iloc[0]['Strike Price']
        
        for _, row in df.iterrows():
            tags = ()
            current_strike = row['Strike Price']
            
            # Tag for Max OI first
            if current_strike == max_oi_strike:
                tags += ('max_oi.Treeview',)
                
            # Tag for the single At-The-Money (ATM) strike.
            # Appending this ensures its style takes precedence if a strike is both ATM and Max OI.
            if current_strike == atm_strike:
                tags += ('spot.Treeview',)
            
            # --- NEW: Added IV to the values list ---
            iv_val = f"{row.get('IV', 0):.2f}" if row.get('IV') is not None else "N/A"
            values = [f"{row['Strike Price']:,g}", iv_val, f"{row['OI']:,}", f"{row['Change in OI']:,}", row['Sentiment']]
            tree.insert('', 'end', values=values, tags=tags)

    def update_chart(self, ax, canvas, title, clear=True):
        if clear:
            ax.clear()
        ax.set_title(title)
        ax.grid(axis='y', linestyle='--', alpha=0.7)
        ax.figure.tight_layout()
        canvas.draw()

    def update_spot_chart(self, spot_df, info):
        ax = self.spot_action_ax
        canvas = self.spot_action_canvas
        ax.clear()
        if spot_df is None or spot_df.empty or not info or not info.get('price'):
            self.init_chart(ax, "Spot Price Action: Net OI Change")
            canvas.draw()
            return
        
        spot_price = info['price']
        strikes = spot_df['Strike Price']
        net_change = spot_df['Net Change'].fillna(0)
        colors = ['#27ae60' if x >= 0 else '#c0392b' for x in net_change]

        bars = ax.bar(strikes, net_change, color=colors, width=20)
        
        # --- NEW: Add value labels on bars ---
        for bar in bars:
            yval = bar.get_height()
            va = 'bottom' if yval >= 0 else 'top'
            ax.text(bar.get_x() + bar.get_width()/2.0, yval, self.format_value(yval), 
                    ha='center', va=va, fontsize=7, color='black')

        ax.set_title(f"Spot Price Action for {info.get('symbol', '')} around {spot_price}")
        ax.set_ylabel("Net OI Change (Directional Pressure)")
        ax.set_xlabel("Strike Price")
        ax.axhline(0, color='black', linewidth=0.8)
        
        # --- NEW: Add vertical line for spot price ---
        if spot_price > 0:
            ax.axvline(x=spot_price, color='#2980b9', linestyle='--', linewidth=1.2, label=f'Spot: {spot_price:,.2f}')
            ax.legend()
        
        # --- NEW: Explicitly set x-axis ticks to match each bar ---
        ax.set_xticks(strikes)
        ax.set_xticklabels([f'{s:g}' for s in strikes], rotation=45, ha='right', fontsize=8)

        self.update_chart(ax, canvas, ax.get_title(), clear=False)

    def update_change_oi_chart(self, df, info):
        ax = self.daily_oi_change_ax
        canvas = self.daily_oi_change_canvas
        ax.clear()
        if df is None or df.empty:
            self.init_chart(ax, "Daily Change in Open Interest")
            canvas.draw()
            return

        strikes = df['strikePrice']
        spot_price = info.get('price', 0)
        ce_change = df['CE.changeinOpenInterest']
        pe_change = df['PE.changeinOpenInterest']
        width = 0.4 * (strikes.iloc[1] - strikes.iloc[0] if len(strikes) > 1 else 50)

        ce_bars = ax.bar(strikes + width/2, ce_change, width, label='Call OI Change', color='#c0392b')
        pe_bars = ax.bar(strikes - width/2, pe_change, width, label='Put OI Change', color='#27ae60')

        # --- NEW: Add value labels on bars ---
        for bar in ce_bars:
            yval = bar.get_height()
            if yval != 0:
                ax.text(bar.get_x() + bar.get_width()/2.0, yval, self.format_value(yval), ha='center', va='bottom', fontsize=7)
        for bar in pe_bars:
            yval = bar.get_height()
            if yval != 0:
                ax.text(bar.get_x() + bar.get_width()/2.0, yval, self.format_value(yval), ha='center', va='bottom', fontsize=7)

        ax.set_xlabel("Strike Price")
        ax.set_ylabel("Change in Open Interest")
        
        # --- NEW: Add vertical line for spot price ---
        if spot_price > 0:
            ax.axvline(x=spot_price, color='#2980b9', linestyle='--', linewidth=1.2, label=f'Spot: {spot_price:,.2f}')

        # --- NEW: Explicitly set x-axis ticks to match each bar ---
        ax.set_xticks(strikes)
        ax.set_xticklabels([f'{s:g}' for s in strikes], rotation=45, ha='right', fontsize=8)

        ax.legend()
        self.update_chart(ax, canvas, f"Daily Change in Open Interest for {info.get('symbol', '')}", clear=False)

    def update_total_oi_chart(self, df, info):
        ax = self.total_open_interest_ax
        canvas = self.total_open_interest_canvas
        ax.clear()
        if df is None or df.empty:
            self.init_chart(ax, "Total Open Interest")
            canvas.draw()
            return
            
        strikes = df['strikePrice']
        spot_price = info.get('price', 0)
        ce_oi = df['CE.openInterest']
        pe_oi = df['PE.openInterest']
        width = 0.4 * (strikes.iloc[1] - strikes.iloc[0] if len(strikes) > 1 else 50)

        # UPDATED: Put bars are green and on the left, Call bars are red and on the right
        pe_bars = ax.bar(strikes - width/2, pe_oi, width, label='Total Put OI', color='#27ae60')
        ce_bars = ax.bar(strikes + width/2, ce_oi, width, label='Total Call OI', color='#c0392b')

        # --- NEW: Add value labels on bars ---
        for bar in ce_bars:
            yval = bar.get_height()
            if yval != 0:
                ax.text(bar.get_x() + bar.get_width()/2.0, yval, self.format_value(yval), ha='center', va='bottom', fontsize=7, rotation=90)
        for bar in pe_bars:
            yval = bar.get_height()
            if yval != 0:
                ax.text(bar.get_x() + bar.get_width()/2.0, yval, self.format_value(yval), ha='center', va='bottom', fontsize=7, rotation=90)

        ax.set_xlabel("Strike Price")
        ax.set_ylabel("Total Open Interest")
        
        # --- NEW: Add vertical line for spot price ---
        if spot_price > 0:
            ax.axvline(x=spot_price, color='#2980b9', linestyle='--', linewidth=1.2, label=f'Spot: {spot_price:,.2f}')

        # --- NEW: Explicitly set x-axis ticks to match each bar ---
        ax.set_xticks(strikes)
        ax.set_xticklabels([f'{s:g}' for s in strikes], rotation=45, ha='right', fontsize=8)

        ax.legend()
        self.update_chart(ax, canvas, f"Total Open Interest for {info.get('symbol', '')}", clear=False)

    def update_integrated_oi_chart(self, df, spot_df, info):
        """ --- MODIFICATION --- Added spot_df and info to draw directional arrow."""
        ax = self.integrated_oi_view_ax
        canvas = self.integrated_oi_view_canvas
        ax.clear()

        if df is None or df.empty:
            self.init_chart(ax, "Integrated OI View: Buildup & Unwinding")
            canvas.draw()
            return

        strikes = df['strikePrice']
        spot_price = info.get('price', 0)
        width = 0.4 * (strikes.iloc[1] - strikes.iloc[0] if len(strikes) > 1 else 50)
        
        # UPDATED: Simplified colors to be consistently red for calls and green for puts
        ce_color = '#c0392b'
        pe_color = '#27ae60'
        
        # UPDATED: Puts on the left, Calls on the right
        put_bars = ax.bar(strikes - width/2, df['PE.openInterest'], width=width, color=pe_color)
        for i, bar in enumerate(put_bars):
            if df['PE.changeinOpenInterest'].iloc[i] <= 0:
                bar.set_hatch('//')

        call_bars = ax.bar(strikes + width/2, df['CE.openInterest'], width=width, color=ce_color)
        for i, bar in enumerate(call_bars):
            if df['CE.changeinOpenInterest'].iloc[i] <= 0:
                bar.set_hatch('//')

        # --- NEW: Add value labels on bars ---
        for bar in call_bars:
            yval = bar.get_height()
            if yval != 0:
                ax.text(bar.get_x() + bar.get_width()/2.0, yval, self.format_value(yval), ha='center', va='bottom', fontsize=7, rotation=90)
        for bar in put_bars:
            yval = bar.get_height()
            if yval != 0:
                ax.text(bar.get_x() + bar.get_width()/2.0, yval, self.format_value(yval), ha='center', va='bottom', fontsize=7, rotation=90)

        ax.set_xlabel("Strike Price")
        ax.set_ylabel("Total Open Interest")
        
        # --- NEW FEATURE: Directional Arrow ---
        if spot_price > 0 and spot_df is not None and not spot_df.empty:
            net_pressure = spot_df['Net Change'].sum()
            arrow_char = '↑' if net_pressure > 0 else '↓'
            arrow_color = '#27ae60' if net_pressure > 0 else '#c0392b'
            max_y = df[['CE.openInterest', 'PE.openInterest']].max().max()
            arrow_y_pos = max_y * 1.05
            ax.text(spot_price, arrow_y_pos, arrow_char, 
                    ha='center', va='center', fontweight='bold', 
                    fontsize=22, color=arrow_color,
                    bbox=dict(facecolor='white', alpha=0.5, boxstyle='circle,pad=0.2'))
            ax.axvline(x=spot_price, color='#2980b9', linestyle='--', linewidth=1.2, label=f'Spot: {spot_price:.2f}')

        from matplotlib.patches import Patch
        # UPDATED: Simplified legend to reflect new color scheme
        legend_elements = [
            Patch(facecolor='#c0392b', label='Call OI'),
            Patch(facecolor='#27ae60', label='Put OI'),
            Patch(facecolor='white', hatch='//', edgecolor='gray', label='Unwinding (OI Decrease)')
        ]
        
        # This combines the patch legend with the line legend (for the spot price)
        handles, labels = ax.get_legend_handles_labels()
        ax.legend(handles=handles + legend_elements, labels=labels + [l.get_label() for l in legend_elements], loc='upper left')

        # --- NEW: Explicitly set x-axis ticks to match each bar ---
        ax.set_xticks(strikes)
        ax.set_xticklabels([f'{s:g}' for s in strikes], rotation=45, ha='right', fontsize=8)

        self.update_chart(ax, canvas, f"Integrated OI View for {info.get('symbol', '')}", clear=False)
    
    def update_trending_strikes_chart(self, trending_df, info):
        ax = self.trending_strikes_ax
        canvas = self.trending_strikes_canvas
        ax.clear()
        if trending_df is None or trending_df.empty:
            self.init_chart(ax, "Trending Strikes (By OI Change)")
            canvas.draw()
            return
            
        trending_df = trending_df.sort_values('change', ascending=True)
        colors = ['#27ae60' if x > 0 else '#c0392b' for x in trending_df['change']]
        ax.barh(trending_df['label'], trending_df['change'], color=colors)
        ax.set_xlabel("Change in Open Interest")
        ax.set_ylabel("Strike")
        
        for index, value in enumerate(trending_df['change']):
            ax.text(value, index, f' {value:,.0f}', va='center', ha='left' if value > 0 else 'right', fontsize=8)

        self.update_chart(ax, canvas, f"Top 10 Trending Strikes for {info.get('symbol', '')}", clear=False)

    def update_oi_difference_chart(self, df, info):
        ax = self.oi_difference_ax
        canvas = self.oi_difference_canvas
        ax.clear()
        if df is None or df.empty:
            self.init_chart(ax, "OI Difference (Puts - Calls)")
            canvas.draw()
            return

        strikes = df['strikePrice']
        spot_price = info.get('price', 0)
        oi_diff = df['PE.openInterest'] - df['CE.openInterest']
        colors = ['#27ae60' if x >= 0 else '#c0392b' for x in oi_diff]
        width = 0.8 * (strikes.iloc[1] - strikes.iloc[0] if len(strikes) > 1 else 50)
        
        bars = ax.bar(strikes, oi_diff, color=colors, width=width)

        # --- NEW: Add value labels on bars ---
        for bar in bars:
            yval = bar.get_height()
            va = 'bottom' if yval >= 0 else 'top'
            ax.text(bar.get_x() + bar.get_width()/2.0, yval, self.format_value(yval), 
                    ha='center', va=va, fontsize=7)

        ax.axhline(0, color='black', linewidth=0.8)
        ax.set_ylabel("OI Difference (Put OI - Call OI)")
        ax.set_xlabel("Strike Price")

        # --- NEW: Add vertical line for spot price ---
        if spot_price > 0:
            ax.axvline(x=spot_price, color='#2980b9', linestyle='--', linewidth=1.2, label=f'Spot: {spot_price:,.2f}')
            ax.legend()

        # --- NEW: Explicitly set x-axis ticks to match each bar ---
        ax.set_xticks(strikes)
        ax.set_xticklabels([f'{s:g}' for s in strikes], rotation=45, ha='right', fontsize=8)

        self.update_chart(ax, canvas, f"OI Difference for {info.get('symbol', '')}: Support & Resistance", clear=False)

    def update_pcr_chart(self, pcr_df, info):
        ax = self.pcr_ax
        canvas = self.pcr_canvas
        ax.clear()
        if pcr_df is None or pcr_df.empty:
            self.init_chart(ax, "Put-Call Ratio (PCR)")
            canvas.draw()
            return

        strikes = pcr_df['strikePrice']
        spot_price = info.get('price', 0)
        ax.plot(strikes, pcr_df['pcr_oi'], color='purple', marker='o', linestyle='-', label='PCR by OI')
        ax.plot(strikes, pcr_df['pcr_vol'], color='orange', marker='x', linestyle='--', label='PCR by Volume')
        ax.axhline(1.0, color='red', linewidth=0.8, linestyle=':', label='1.0 Level')
        ax.axhline(0.7, color='gray', linewidth=0.8, linestyle=':', label='0.7 Level')

        # --- NEW: Add vertical line for spot price ---
        if spot_price > 0:
            ax.axvline(x=spot_price, color='#2980b9', linestyle='--', linewidth=1.2, label=f'Spot: {spot_price:,.2f}')

        # --- NEW: Explicitly set x-axis ticks to match each bar ---
        ax.set_xticks(strikes)
        ax.set_xticklabels([f'{s:g}' for s in strikes], rotation=45, ha='right', fontsize=8)

        ax.set_xlabel("Strike Price")
        ax.set_ylabel("Put-Call Ratio")
        ax.legend()
        self.update_chart(ax, canvas, f"Put-Call Ratio (PCR) for {info.get('symbol', '')} by Strike", clear=False)
        
    def update_max_pain_chart(self, max_pain_df, max_pain_strike, info):
        ax = self.max_pain_ax
        canvas = self.max_pain_canvas
        ax.clear()
        if max_pain_df is None or max_pain_df.empty:
            self.init_chart(ax, "Max Pain")
            canvas.draw()
            return
        
        spot_price = info.get('price', 0)

        colors = ['#c0392b' if s == max_pain_strike else '#3498db' for s in max_pain_df['strike']]
        ax.bar(max_pain_df['strike'], max_pain_df['loss'], color=colors)
        ax.axvline(max_pain_strike, color='green', linestyle='--', label=f'Max Pain: {max_pain_strike}')

        # --- NEW: Add vertical line for spot price ---
        if spot_price > 0:
            ax.axvline(x=spot_price, color='#2980b9', linestyle=':', linewidth=1.5, label=f'Spot: {spot_price:,.2f}')

        # --- NEW: Set a reasonable number of x-axis ticks to avoid clutter ---
        strikes = max_pain_df['strike']
        # Select a reasonable number of ticks (e.g., max 15)
        if len(strikes) > 15:
            tick_indices = np.linspace(0, len(strikes) - 1, 15, dtype=int)
            ticks = strikes.iloc[tick_indices]
        else:
            ticks = strikes
        ax.set_xticks(ticks)
        ax.set_xticklabels([f'{t:g}' for t in ticks], rotation=45, ha='right', fontsize=8)


        ax.set_xlabel("Expiry Strike Price")
        ax.set_ylabel("Total Notional Loss for Option Buyers")
        ax.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, p: format(int(x), ',')))
        ax.legend()
        self.update_chart(ax, canvas, f"Max Pain Analysis for {info.get('symbol', '')} (Loss at {max_pain_strike})", clear=False)

    def update_iv_chart(self, df, info):
        """NEW: Creates the Implied Volatility Smile chart."""
        ax = self.implied_volatility_ax
        canvas = self.implied_volatility_canvas
        ax.clear()
        if df is None or df.empty:
            self.init_chart(ax, "Implied Volatility (IV) Smile")
            canvas.draw()
            return
            
        strikes = df['strikePrice']
        spot_price = info.get('price', 0)
        
        # Filter out zero IV values which are common for far OTM options
        ce_iv = df[df['CE.impliedVolatility'] > 0]
        pe_iv = df[df['PE.impliedVolatility'] > 0]
        
        ax.plot(ce_iv['strikePrice'], ce_iv['CE.impliedVolatility'], color='#c0392b', marker='.', linestyle='-', label='Call IV')
        ax.plot(pe_iv['strikePrice'], pe_iv['PE.impliedVolatility'], color='#27ae60', marker='.', linestyle='-', label='Put IV')
        
        if spot_price > 0:
            ax.axvline(x=spot_price, color='#2980b9', linestyle='--', linewidth=1.2, label=f'Spot: {spot_price:,.2f}')

        ax.set_xticks(strikes)
        ax.set_xticklabels([f'{s:g}' for s in strikes], rotation=45, ha='right', fontsize=8)

        ax.set_xlabel("Strike Price")
        ax.set_ylabel("Implied Volatility (%)")
        ax.legend()
        self.update_chart(ax, canvas, f"Implied Volatility (IV) Smile for {info.get('symbol', '')}", clear=False)

    def update_status(self, message):
        self.status_label.config(text=message)

    def fetch_nse_oi_data(self, symbol, asset_type):
        """MODIFIED: Handles both Indices and Equities."""
        option_chain_url = f"https://www.nseindia.com/option-chain"
        if asset_type == "Indices":
            api_url = f"https://www.nseindia.com/api/option-chain-indices?symbol={symbol}"
        else: # Stocks
            api_url = f"https://www.nseindia.com/api/option-chain-equities?symbol={symbol}"
            
        # --- MODIFIED: Use the standard browser header ---
        headers = BROWSER_HEADER.copy()
        headers.update({'Referer': option_chain_url, 'X-Requested-With': 'XMLHttpRequest'})

        try:
            session = requests.Session()
            # Initial visit to the main page to get cookies
            session.get(option_chain_url, headers=headers, timeout=20)
            # Subsequent API call with the session cookies
            api_response = session.get(api_url, headers=headers, timeout=20)
            api_response.raise_for_status()
            return api_response.json()
        except Exception as e:
            print(f"Error fetching NSE OI data for {symbol}: {e}")
            return None

    def fetch_nse_expiry_dates(self, symbol, asset_type):
        """NEW: Fetches only the list of expiry dates from NSE."""
        if asset_type == "Indices":
            api_url = f"https://www.nseindia.com/api/option-chain-indices?symbol={symbol}"
        else: # Stocks
            api_url = f"https://www.nseindia.com/api/option-chain-equities?symbol={symbol}"
        
        # --- MODIFIED: Use the standard browser header ---
        headers = BROWSER_HEADER.copy()
        try:
            session = requests.Session()
            session.get("https://www.nseindia.com/option-chain", headers=headers, timeout=10)
            response = session.get(api_url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get('records', {}).get('expiryDates', [])
        except Exception as e:
            print(f"Error fetching NSE expiry dates for {symbol}: {e}")
            return []

    def fetch_mcx_oi_data(self, symbol, expiry_date=None):
        """REVISED: Fetches MCX data using a direct method with enhanced browser headers."""
        try:
            target_expiry = expiry_date
            if not target_expiry or target_expiry == "Loading...":
                expiries = self.fetch_mcx_expiry_dates(symbol)
                if not expiries: return None
                target_expiry = expiries[0]

            self.update_status(f"Fetching MCX data for {symbol} on {target_expiry}...")
            target_url = f"https://www.mcxindia.com/back-end/api/v1/mcx-option-chain?commodity={symbol}&expiry={target_expiry}"
            
            # --- MODIFIED: Enhanced headers to mimic a browser for MCX ---
            mcx_headers = BROWSER_HEADER.copy()
            mcx_headers.update({
                'Referer': 'https://www.mcxindia.com/market-data/option-chain', # Mimic direct visit
                'X-Requested-With': 'XMLHttpRequest', # Indicate AJAX request
            })

            response = requests.get(target_url, headers=mcx_headers, timeout=20)
            response.raise_for_status()
            return response.json()

        except Exception as e:
            print(f"Error fetching MCX OI data for {symbol}: {e}")
            messagebox.showerror("API Error", f"Failed to fetch MCX data. The site may be blocking requests. Error: {e}")
            return None

    def fetch_mcx_expiry_dates(self, symbol):
        """REVISED: Fetches MCX expiry dates using a direct method with enhanced browser headers."""
        try:
            target_url = f"https://www.mcxindia.com/back-end/api/v1/contracts/by-commodity/{symbol}"
            
            # --- MODIFIED: Enhanced headers to mimic a browser for MCX ---
            mcx_headers = BROWSER_HEADER.copy()
            mcx_headers.update({
                'Referer': 'https://www.mcxindia.com/market-data/option-chain', # Mimic direct visit
                'X-Requested-With': 'XMLHttpRequest', # Indicate AJAX request
            })

            response = requests.get(target_url, headers=mcx_headers, timeout=20)
            response.raise_for_status()
            data = response.json()
            expiries = data.get("data", [])
            return sorted([e['expiryDate'] for e in expiries if 'expiryDate' in e])

        except Exception as e:
            print(f"Error fetching MCX expiry dates for {symbol}: {e}")
            messagebox.showerror("API Error", f"Failed to fetch MCX expiry dates. The site may be blocking requests. Error: {e}")
            return []

    def fetch_crypto_oi_data(self, symbol):
        """NEW: Fetches crypto options data from Deribit for the nearest expiry."""
        base_url = "https://www.deribit.com/api/v2/public"
        currency = symbol.upper()
        
        try:
            # 1. Get all available option instruments to find the nearest expiry
            instruments_url = f"{base_url}/get_instruments?currency={currency}&kind=option&expired=false"
            response = requests.get(instruments_url, headers=BROWSER_HEADER, timeout=10)
            response.raise_for_status()
            instruments = response.json().get('result', [])
            
            if not instruments:
                messagebox.showerror("API Error", f"No active option instruments found for {currency} on Deribit.")
                return None

            # 2. Find the closest expiry timestamp
            now = datetime.now(timezone.utc).timestamp() * 1000
            closest_expiry = min([inst['expiration_timestamp'] for inst in instruments], key=lambda x: abs(x - now))
            
            # 3. Fetch the full option book for that expiry
            book_url = f"{base_url}/get_book_summary_by_currency?currency={currency}&kind=option"
            response = requests.get(book_url, headers=BROWSER_HEADER, timeout=10)
            response.raise_for_status()
            option_book_all_expiries = response.json().get('result', [])

            # --- BUG FIX: Timezone Correction ---
            # Convert the UTC expiry timestamp to a UTC datetime object before formatting.
            # This prevents local timezone interference from creating an incorrect date string.
            expiry_date_str = datetime.utcfromtimestamp(closest_expiry / 1000).strftime('%d%b%y').upper()
            option_book = [b for b in option_book_all_expiries if b['instrument_name'].startswith(f"{currency}-{expiry_date_str}")]

            # 4. Fetch the underlying price (index price)
            ticker_url = f"{base_url}/get_index?currency={currency}"
            response = requests.get(ticker_url, headers=BROWSER_HEADER, timeout=10)
            response.raise_for_status()
            # --- BUG FIX: Incorrect Key Case ---
            # Deribit API returns the index price with an uppercase key (e.g., 'BTC'), not lowercase.
            index_price = response.json().get('result', {}).get(currency.upper(), 0)

            if not option_book or index_price == 0:
                messagebox.showerror("API Error", "Could not fetch complete option book or index price from Deribit.")
                return None

            return {
                "deribit_data": option_book,
                "underlyingValue": index_price,
                "symbol": currency,
                "timestamp": datetime.now().strftime('%I:%M:%S %p, %d-%b-%Y')
            }

        except Exception as e:
            print(f"Error fetching Deribit OI data: {e}")
            messagebox.showerror("API Error", f"Failed to fetch crypto data from Deribit: {e}")
            return None

    def get_strategy_signal(self, df, info):
        spot_price = info['price']
        if spot_price == 0 or df.empty:
            return {"signal": "WAITING FOR DATA", "color": "orange", "reason": "Valid spot price or option chain data not available yet."}
            
        res_strike = df.loc[df['CE.openInterest'].idxmax()]['strikePrice']
        sup_strike = df.loc[df['PE.openInterest'].idxmax()]['strikePrice']
        
        res_doi_series = df.loc[df['strikePrice'] == res_strike, 'CE.changeinOpenInterest']
        sup_doi_series = df.loc[df['strikePrice'] == sup_strike, 'PE.changeinOpenInterest']

        if res_doi_series.empty or sup_doi_series.empty:
            return {"signal": "DATA INCOMPLETE", "color": "orange", "reason": "Could not retrieve Change in OI for key strikes."}
        
        res_doi = res_doi_series.iloc[0]
        sup_doi = sup_doi_series.iloc[0]
        
        proximity_threshold = spot_price * 0.0025
        
        if abs(spot_price - res_strike) <= proximity_threshold:
            if res_doi < 0:
                return {"signal": "BREAKOUT IMMINENT (UP)", "color": "#27ae60", "reason": f"Price near resistance ({res_strike}). Call writers are unwinding (ΔOI is negative), signaling a potential breakout."}
            else:
                return {"signal": "RESISTANCE HOLDING", "color": "#c0392b", "reason": f"Price near resistance ({res_strike}). Call writers are defending (ΔOI is positive), reinforcing the barrier."}
        
        if abs(spot_price - sup_strike) <= proximity_threshold:
            if sup_doi < 0:
                return {"signal": "BREAKDOWN IMMINENT (DOWN)", "color": "#c0392b", "reason": f"Price near support ({sup_strike}). Put writers are unwinding (ΔOI is negative), signaling a potential breakdown."}
            else:
                return {"signal": "SUPPORT HOLDING", "color": "#27ae60", "reason": f"Price near support ({sup_strike}). Put writers are defending (ΔOI is positive), reinforcing the floor."}

        return {"signal": "TRADING IN RANGE", "color": "#3498db", "reason": f"Price is between major Support ({sup_strike}) and Resistance ({res_strike}). Monitor these key levels for action."}

    def calculate_probabilistic_levels(self, df):
        if df.empty: return None
        
        levels = {}

        put_writing = df['PE.changeinOpenInterest'][df['PE.changeinOpenInterest'] > 0].sum()
        call_unwinding = abs(df['CE.changeinOpenInterest'][df['CE.changeinOpenInterest'] < 0].sum())
        bullish_strength = put_writing + call_unwinding

        call_writing = df['CE.changeinOpenInterest'][df['CE.changeinOpenInterest'] > 0].sum()
        put_unwinding = abs(df['PE.changeinOpenInterest'][df['PE.changeinOpenInterest'] < 0].sum())
        bearish_strength = call_writing + put_unwinding

        total_strength = bullish_strength + bearish_strength
        if total_strength > 0:
            levels['prob_bullish'] = bullish_strength / total_strength
            levels['prob_bearish'] = bearish_strength / total_strength
        else:
            levels['prob_bullish'] = 0.5; levels['prob_bearish'] = 0.5

        max_oi_ce_strike = df.loc[df['CE.openInterest'].idxmax()]
        if max_oi_ce_strike['CE.changeinOpenInterest'] < 0:
            levels['reversal_up'] = f"{max_oi_ce_strike['strikePrice']:,.0f}"

        max_oi_pe_strike = df.loc[df['PE.openInterest'].idxmax()]
        if max_oi_pe_strike['PE.changeinOpenInterest'] < 0:
            levels['reversal_down'] = f"{max_oi_pe_strike['strikePrice']:,.0f}"

        strongest_ce_writing = df.loc[df['CE.changeinOpenInterest'].idxmax()]
        if strongest_ce_writing['CE.changeinOpenInterest'] > 0:
            levels['continuation_down'] = f"{strongest_ce_writing['strikePrice']:,.0f}"

        strongest_pe_writing = df.loc[df['PE.changeinOpenInterest'].idxmax()]
        if strongest_pe_writing['PE.changeinOpenInterest'] > 0:
            levels['continuation_up'] = f"{strongest_pe_writing['strikePrice']:,.0f}"

        return levels

    def calculate_bayesian_probability(self, df, info, prob_levels, max_pain_strike):
        """NEW: Calculates a Bayesian probability for the market direction."""
        if df.empty or not info or not prob_levels or not max_pain_strike:
            return {'bullish': 0.5, 'bearish': 0.5, 'reason': 'Incomplete data for Bayesian analysis.'}

        # 1. Prior Belief (start with 50/50)
        prior_bullish = 0.5

        reasons = []

        # 2. Evidence from OI Momentum (prob_levels)
        # Likelihood: If momentum is bullish, how likely is an up move?
        # Let's assume a direct correlation for simplicity.
        likelihood_oi_momentum = prob_levels.get('prob_bullish', 0.5)
        if likelihood_oi_momentum > 0.55:
            reasons.append(f"OI Momentum Bullish ({likelihood_oi_momentum:.0%})")
        elif likelihood_oi_momentum < 0.45:
            reasons.append(f"OI Momentum Bearish ({1-likelihood_oi_momentum:.0%})")
        
        # Bayes' Theorem Update 1
        # P(Bullish|OI) = P(OI|Bullish) * P(Bullish) / P(OI)
        # P(OI) is a normalizing constant, so we can calculate posterior odds
        posterior_bullish_1 = likelihood_oi_momentum * prior_bullish
        posterior_bearish_1 = (1 - likelihood_oi_momentum) * (1 - prior_bullish)
        # Normalize
        if (posterior_bullish_1 + posterior_bearish_1) > 0:
            posterior_bullish_1 /= (posterior_bullish_1 + posterior_bearish_1)


        # 3. Evidence from Total PCR
        total_pe_oi = df['PE.openInterest'].sum()
        total_ce_oi = df['CE.openInterest'].sum()
        pcr = total_pe_oi / total_ce_oi if total_ce_oi > 0 else 1
        # Likelihood: Map PCR to a probability (e.g., using a sigmoid-like function)
        # PCR > 1 is generally bullish, < 0.7 is bearish
        # A simple linear mapping for this range:
        if pcr > 1.2: likelihood_pcr = 0.8 # Very Bullish
        elif pcr > 1.0: likelihood_pcr = 0.65 # Bullish
        elif pcr < 0.7: likelihood_pcr = 0.2 # Very Bearish
        elif pcr < 0.8: likelihood_pcr = 0.35 # Bearish
        else: likelihood_pcr = 0.5 # Neutral
        reasons.append(f"Total PCR {pcr:.2f}")


        # Bayes' Theorem Update 2 (using posterior from step 1 as new prior)
        posterior_bullish_2 = likelihood_pcr * posterior_bullish_1
        posterior_bearish_2 = (1 - likelihood_pcr) * (1 - posterior_bullish_1)
        if (posterior_bullish_2 + posterior_bearish_2) > 0:
            posterior_bullish_2 /= (posterior_bullish_2 + posterior_bearish_2)
            

        # 4. Evidence from Max Pain
        spot_price = info.get('price', 0)
        # Likelihood: Is the price likely to move towards Max Pain?
        # If spot is below max pain, it implies a bullish pull.
        if spot_price > 0:
            if spot_price < max_pain_strike:
                likelihood_max_pain = 0.60 # Slight bullish pull
                reasons.append(f"Max Pain Pull Up ({max_pain_strike})")
            elif spot_price > max_pain_strike:
                likelihood_max_pain = 0.40 # Slight bearish pull
                reasons.append(f"Max Pain Pull Down ({max_pain_strike})")
            else:
                likelihood_max_pain = 0.5 # No pull
        else:
            likelihood_max_pain = 0.5

        # Bayes' Theorem Update 3 (using posterior from step 2 as new prior)
        posterior_bullish_3 = likelihood_max_pain * posterior_bullish_2
        posterior_bearish_3 = (1 - likelihood_max_pain) * (1 - posterior_bullish_2)
        if (posterior_bullish_3 + posterior_bearish_3) > 0:
             posterior_bullish_3 /= (posterior_bullish_3 + posterior_bearish_3)

        prob_bullish = posterior_bullish_3
        prob_bearish = 1 - prob_bullish

        return {'bullish': prob_bullish, 'bearish': prob_bearish, 'reason': ' | '.join(reasons)}

    def analyze_market_structure(self, df, info):
        """
        NEW: A systematic method derived from the provided research paper to 
        determine market movement and strength from the current strike price.
        """
        if df.empty or not info.get('price'):
            return None

        spot_price = info['price']
        reasons = []
        
        # Step 1 & 2: Identify ATM, Primary Support (Put Wall), and Primary Resistance (Call Wall)
        atm_strike_row = df.iloc[(df['strikePrice'] - spot_price).abs().argsort()[:1]]
        if atm_strike_row.empty: return None
        atm_strike = atm_strike_row.iloc[0]['strikePrice']
        
        res_wall_row = df.loc[df['CE.openInterest'].idxmax()]
        sup_wall_row = df.loc[df['PE.openInterest'].idxmax()]
        res_wall_strike = res_wall_row['strikePrice']
        sup_wall_strike = sup_wall_row['strikePrice']
        reasons.append(f"Probable Range defined by Support Wall at {sup_wall_strike:g} and Resistance Wall at {res_wall_strike:g}.")

        # Step 3: Analyze Intraday Pressure at the ATM strike
        atm_ce_change = atm_strike_row['CE.changeinOpenInterest'].iloc[0]
        atm_pe_change = atm_strike_row['PE.changeinOpenInterest'].iloc[0]
        net_atm_pressure = atm_pe_change - atm_ce_change
        
        if net_atm_pressure > 0:
            reasons.append(f"Bullish pressure at ATM ({atm_strike:g}) with net positive OI change ({self.format_value(net_atm_pressure)}).")
        elif net_atm_pressure < 0:
            reasons.append(f"Bearish pressure at ATM ({atm_strike:g}) with net negative OI change ({self.format_value(net_atm_pressure)}).")

        # Step 4: Analyze Strength of the Walls (Buildup vs. Unwinding)
        res_wall_change = res_wall_row['CE.changeinOpenInterest']
        sup_wall_change = sup_wall_row['PE.changeinOpenInterest']
        
        is_res_weakening = res_wall_change < 0
        is_sup_weakening = sup_wall_change < 0

        if is_res_weakening:
            reasons.append(f"CRITICAL: Resistance at {res_wall_strike:g} is WEAKENING (Call Unwinding).")
        else:
            reasons.append(f"Resistance at {res_wall_strike:g} is STRENGTHENING (Call Buildup).")

        if is_sup_weakening:
            reasons.append(f"CRITICAL: Support at {sup_wall_strike:g} is WEAKENING (Put Unwinding).")
        else:
            reasons.append(f"Support at {sup_wall_strike:g} is STRENGTHENING (Put Buildup).")

        # Step 5: Synthesize into a Conviction Score and Hypothesis
        conviction_score = 0
        
        # Base score on ATM pressure (scaled)
        conviction_score += (net_atm_pressure / 50000) * 20 # Scaled contribution
        
        # Major score adjustment for weakening walls
        if is_res_weakening: conviction_score += 40
        if is_sup_weakening: conviction_score -= 40
        
        # Minor score adjustment for strengthening walls
        if not is_res_weakening: conviction_score -= (res_wall_change / 50000) * 10
        if not is_sup_weakening: conviction_score += (sup_wall_change / 50000) * 10

        # Overall Bias from PCR
        total_pe_oi = df['PE.openInterest'].sum()
        total_ce_oi = df['CE.openInterest'].sum()
        pcr = total_pe_oi / total_ce_oi if total_ce_oi > 0 else 1
        if pcr > 1.1: 
            conviction_score += 15
            reasons.append(f"Overall sentiment is Bullish (Total PCR: {pcr:.2f}).")
        elif pcr < 0.8: 
            conviction_score -= 15
            reasons.append(f"Overall sentiment is Bearish (Total PCR: {pcr:.2f}).")

        # Normalize score to be within -100 to 100
        conviction_score = max(-100, min(100, conviction_score))

        # Generate Hypothesis
        hypothesis = "Market is in Range Compression; Awaiting Clear Signal."
        if conviction_score > 30:
            hypothesis = f"Bullish: Price likely to drift towards Resistance ({res_wall_strike:g})."
        elif conviction_score < -30:
            hypothesis = f"Bearish: Price likely to drift towards Support ({sup_wall_strike:g})."
        elif conviction_score > 65:
            hypothesis = f"Strongly Bullish: Conditions favor a potential breakout above Resistance ({res_wall_strike:g})."
        elif conviction_score < -65:
            hypothesis = f"Strongly Bearish: Conditions favor a potential breakdown below Support ({sup_wall_strike:g})."


        return {
            "hypothesis": hypothesis,
            "conviction_score": conviction_score,
            "reasoning": "\n• " + "\n• ".join(reasons)
        }

    def analyze_spot_price_action(self, df, info):
        """NEW: Identifies immediate demand/supply zones (order blocks) around the spot price."""
        if df.empty or not info.get('price'):
            return None

        spot_price = info['price']
        
        # Find strikes immediately below and above the spot price
        strikes_below = df[df['strikePrice'] < spot_price]
        strikes_above = df[df['strikePrice'] > spot_price]

        bullish_block_str = "Not clearly defined"
        bearish_block_str = "Not clearly defined"
        prediction = "Price is consolidating between immediate OI levels."
        
        demand_change = 0
        supply_change = 0
        demand_strike = None
        supply_strike = None

        # Identify Bullish Order Block (Demand) - Strongest Put writing below spot
        if not strikes_below.empty:
            demand_zone_row = strikes_below.loc[strikes_below['PE.changeinOpenInterest'].idxmax()]
            demand_strike = demand_zone_row['strikePrice']
            demand_change = demand_zone_row['PE.changeinOpenInterest']
            if demand_change > 0:
                bullish_block_str = f"{demand_strike:g} (OI Change: +{self.format_value(demand_change)})"

        # Identify Bearish Order Block (Supply) - Strongest Call writing above spot
        if not strikes_above.empty:
            supply_zone_row = strikes_above.loc[strikes_above['CE.changeinOpenInterest'].idxmax()]
            supply_strike = supply_zone_row['strikePrice']
            supply_change = supply_zone_row['CE.changeinOpenInterest']
            if supply_change > 0:
                bearish_block_str = f"{supply_strike:g} (OI Change: +{self.format_value(supply_change)})"
        
        # --- NEW: Identify Swing Zones between major walls ---
        res_wall_strike = df.loc[df['CE.openInterest'].idxmax()]['strikePrice']
        sup_wall_strike = df.loc[df['PE.openInterest'].idxmax()]['strikePrice']
        
        swing_df = df[(df['strikePrice'] > sup_wall_strike) & (df['strikePrice'] < res_wall_strike)]
        
        swing_support_str = "N/A"
        swing_resistance_str = "N/A"

        if not swing_df.empty:
            # Swing Support = Highest Put OI in the swing zone
            swing_sup_row = swing_df.loc[swing_df['PE.openInterest'].idxmax()]
            swing_support_str = f"{swing_sup_row['strikePrice']:g} (OI: {self.format_value(swing_sup_row['PE.openInterest'])})"
            
            # Swing Resistance = Highest Call OI in the swing zone
            swing_res_row = swing_df.loc[swing_df['CE.openInterest'].idxmax()]
            swing_resistance_str = f"{swing_res_row['strikePrice']:g} (OI: {self.format_value(swing_res_row['CE.openInterest'])})"

        # Predict movement based on the strength of the immediate blocks
        if demand_strike and supply_strike:
            if demand_change > supply_change:
                prediction = f"Immediate pressure is upward. Put writers at {demand_strike:g} are providing strong support. A test of the supply zone at {supply_strike:g} is likely."
            elif supply_change > demand_change:
                prediction = f"Immediate pressure is downward. Call writers at {supply_strike:g} are creating a strong barrier. A test of the demand zone at {demand_strike:g} is likely."
            else: # Roughly equal pressure
                prediction = f"A battle is underway. Strong Put writing at {demand_strike:g} is matched by strong Call writing at {supply_strike:g}. Expect volatility within this narrow range."

        return {
            'bullish_block': bullish_block_str,
            'bearish_block': bearish_block_str,
            'prediction': prediction,
            'swing_support': swing_support_str,
            'swing_resistance': swing_resistance_str
        }

    def analyze_oi(self, data, asset_type, requested_symbol, selected_expiry=None):
        """MODIFIED: Handles NSE Indices, NSE Equities, MCX, and Deribit data structures."""
        try:
            # --- Data Normalization ---
            if asset_type == 'Indices' or asset_type == 'Stocks':
                # The NSE API returns data for ALL expiries, so we must filter it.
                all_option_data = data.get('records', {}).get('data', [])
                if not all_option_data:
                    messagebox.showerror("Data Error", "Could not find option data in the NSE response.")
                    return None
                
                # --- CRITICAL: Filter data for the selected expiry date ---
                option_data_list = [d for d in all_option_data if d.get('expiryDate') == selected_expiry]
                
                if not option_data_list:
                    messagebox.showwarning("No Data", f"No option chain data found for the selected expiry: {selected_expiry}")
                    return None

                records = data.get('records', {})
                underlying_value = records.get('underlyingValue', 0)
                
                # BUG FIX: This section is no longer needed as we pass the symbol in.
                # index_symbol = requested_symbol 
                
                # For stocks, the symbol is in a different place
                if asset_type == 'Stocks':
                    # --- BUG FIX: Underlying symbol for stocks is in a different key ---
                    # This check is still useful to confirm we got the right stock data
                    response_symbol = data.get('records', {}).get('underlying', {}).get('symbol', 'N/A')
                    if underlying_value == 0: # Fallback for stocks
                         underlying_value = data.get('records', {}).get('underlying', {}).get('lastPrice', 0)
                
                timestamp_str = records.get('timestamp')
                formatted_time = datetime.strptime(timestamp_str, '%d-%b-%Y %H:%M:%S').strftime('%I:%M:%S %p, %d-%b-%Y') if timestamp_str else 'N/A'
                
                df_raw = pd.json_normalize([d for d in option_data_list if 'CE' in d and 'PE' in d])
                df = pd.DataFrame()
                
                # Ensure all necessary columns exist, fill with 0 or NaN if not
                required_cols = [
                    'strikePrice', 'expiryDate',
                    'CE.openInterest', 'CE.changeinOpenInterest', 'CE.impliedVolatility', 'CE.totalTradedVolume',
                    'PE.openInterest', 'PE.changeinOpenInterest', 'PE.impliedVolatility', 'PE.totalTradedVolume'
                ]
                for col in required_cols:
                    if col in df_raw.columns:
                        df[col] = pd.to_numeric(df_raw[col], errors='coerce')
                    else:
                        df[col] = 0 # Default to 0 if column is missing
                df = df.fillna(0)

            # --- NEW: MCX Data Normalization ---
            elif asset_type == 'MCX':
                option_data_list = data.get("data", [])
                if not option_data_list:
                     messagebox.showerror("Data Error", "Could not find option data in the MCX response.")
                     return None
                
                underlying_value = option_data_list[0].get('underlying', 0)
                formatted_time = datetime.now().strftime('%I:%M:%S %p, %d-%b-%Y') # MCX API doesn't provide a reliable timestamp

                parsed_data = []
                for item in option_data_list:
                    strike = item.get('strikePrice', 0)
                    ce_data = item.get('call', {})
                    pe_data = item.get('put', {})
                    parsed_data.append({
                        'strikePrice': strike,
                        'CE.openInterest': ce_data.get('openInterest', 0),
                        'CE.changeinOpenInterest': ce_data.get('changeinOpenInterest', 0),
                        'CE.impliedVolatility': ce_data.get('impliedVolatility', 0),
                        'CE.totalTradedVolume': ce_data.get('totalTradedVolume', 0),
                        'PE.openInterest': pe_data.get('openInterest', 0),
                        'PE.changeinOpenInterest': pe_data.get('changeinOpenInterest', 0),
                        'PE.impliedVolatility': pe_data.get('impliedVolatility', 0),
                        'PE.totalTradedVolume': pe_data.get('totalTradedVolume', 0),
                    })
                df = pd.DataFrame(parsed_data)


            else: # Crypto (Deribit)
                option_data_list = data['deribit_data']
                underlying_value = data['underlyingValue']
                formatted_time = data['timestamp']
                # BUG FIX: This is now consistent
                # index_symbol = requested_symbol
                
                parsed_data = []
                for item in option_data_list:
                    parts = item['instrument_name'].split('-')
                    parsed_data.append({
                        'strikePrice': float(parts[2]),
                        'type': parts[3],
                        'openInterest': item['open_interest'],
                        'volume': item['volume'],
                        # Deribit provides IV directly in the book summary
                        'impliedVolatility': item.get('ask_iv', item.get('bid_iv', 0)) 
                    })
                
                df_raw = pd.DataFrame(parsed_data)
                
                ce_df = df_raw[df_raw['type'] == 'C'].rename(columns={'openInterest': 'CE.openInterest', 'volume': 'CE.totalTradedVolume', 'impliedVolatility': 'CE.impliedVolatility'})
                pe_df = df_raw[df_raw['type'] == 'P'].rename(columns={'openInterest': 'PE.openInterest', 'volume': 'PE.totalTradedVolume', 'impliedVolatility': 'PE.impliedVolatility'})
                
                df = pd.merge(ce_df, pe_df, on='strikePrice', how='outer').fillna(0)
                
                # Deribit public API doesn't provide change in OI directly, so we set it to 0
                df['CE.changeinOpenInterest'] = 0
                df['PE.changeinOpenInterest'] = 0
                df = df.sort_values(by='strikePrice').reset_index(drop=True)

            info = { 'symbol': requested_symbol, 'price': underlying_value, 'time': formatted_time }

            if df.empty:
                messagebox.showerror("Analysis Error", "Could not process the fetched option data.")
                return None
            
            # --- The rest of the analysis logic is now common for both data sources ---
            strategy_signal = self.get_strategy_signal(df, info)
            prob_levels = self.calculate_probabilistic_levels(df)

            all_strikes = sorted(df['strikePrice'].unique())
            spot_idx = np.searchsorted(all_strikes, underlying_value, side="left")
            
            # Define a range of strikes around the spot price for cleaner charts
            chart_strikes_range = all_strikes[max(0, spot_idx - 10):min(len(all_strikes), spot_idx + 11)]
            full_chart_df = df[df['strikePrice'].isin(chart_strikes_range)].copy()

            spot_strikes_range = all_strikes[max(0, spot_idx - 3):min(len(all_strikes), spot_idx + 4)]
            spot_analysis_df = df[df['strikePrice'].isin(spot_strikes_range)].copy()
            spot_analysis_df['Net Change'] = spot_analysis_df['PE.changeinOpenInterest'] - spot_analysis_df['CE.changeinOpenInterest']
            spot_analysis_df = spot_analysis_df[['strikePrice', 'Net Change']].rename(columns={'strikePrice': 'Strike Price'})
            spot_analysis_df = spot_analysis_df.set_index('Strike Price').reindex(spot_strikes_range).reset_index()

            resistance_df = df[['strikePrice', 'CE.impliedVolatility', 'CE.openInterest', 'CE.changeinOpenInterest']].rename(columns={'strikePrice': 'Strike Price', 'CE.impliedVolatility': 'IV', 'CE.openInterest': 'OI', 'CE.changeinOpenInterest': 'Change in OI'})
            resistance_df['Sentiment'] = resistance_df['Change in OI'].apply(lambda x: 'Bearish' if x > 0 else ('Bullish' if x < 0 else 'Neutral'))
            resistance_df = resistance_df.sort_values(by='OI', ascending=False)

            support_df = df[['strikePrice', 'PE.impliedVolatility', 'PE.openInterest', 'PE.changeinOpenInterest']].rename(columns={'strikePrice': 'Strike Price', 'PE.impliedVolatility': 'IV', 'PE.openInterest': 'OI', 'PE.changeinOpenInterest': 'Change in OI'})
            support_df['Sentiment'] = support_df['Change in OI'].apply(lambda x: 'Bullish' if x > 0 else ('Bearish' if x < 0 else 'Neutral'))
            support_df = support_df.sort_values(by='OI', ascending=False)
            
            ce_change = df[['strikePrice', 'CE.changeinOpenInterest']].rename(columns={'CE.changeinOpenInterest': 'change'}); ce_change['type'] = 'CE'
            pe_change = df[['strikePrice', 'PE.changeinOpenInterest']].rename(columns={'PE.changeinOpenInterest': 'change'}); pe_change['type'] = 'PE'
            all_changes = pd.concat([ce_change, pe_change])
            all_changes['abs_change'] = all_changes['change'].abs()
            top_trending = all_changes.sort_values('abs_change', ascending=False).head(10)
            top_trending['label'] = top_trending['strikePrice'].astype(str) + " " + top_trending['type']

            pcr_df = full_chart_df[['strikePrice', 'PE.openInterest', 'CE.openInterest', 'PE.totalTradedVolume', 'CE.totalTradedVolume']].copy()
            pcr_df['pcr_oi'] = pcr_df['PE.openInterest'] / pcr_df['CE.openInterest']
            pcr_df['pcr_vol'] = pcr_df['PE.totalTradedVolume'] / pcr_df['CE.totalTradedVolume']
            pcr_df.replace([np.inf, -np.inf], np.nan, inplace=True)

            pain_strikes = df['strikePrice'].unique()
            pain_data = []
            for expiry_strike in pain_strikes:
                loss = ((expiry_strike - df['strikePrice']) * df['CE.openInterest']).clip(lower=0).sum() + \
                       ((df['strikePrice'] - expiry_strike) * df['PE.openInterest']).clip(lower=0).sum()
                pain_data.append({'strike': expiry_strike, 'loss': loss})
            max_pain_df = pd.DataFrame(pain_data)
            max_pain_strike = max_pain_df.loc[max_pain_df['loss'].idxmin()]['strike'] if not max_pain_df.empty else 0

            # --- NEW: Calculate Bayesian probability ---
            bayesian_result = self.calculate_bayesian_probability(df, info, prob_levels, max_pain_strike)
            # --- NEW: Perform Market Structure Analysis ---
            structure_analysis = self.analyze_market_structure(df, info)
            # --- NEW: Perform Spot Price Action Analysis ---
            spot_price_analysis = self.analyze_spot_price_action(df, info)

            # --- NEW: Added IV to final columns ---
            final_cols = ['Strike Price', 'IV', 'OI', 'Change in OI', 'Sentiment']
            return (resistance_df.head(15)[final_cols], support_df.head(15)[final_cols], 
                    spot_analysis_df, full_chart_df, top_trending, pcr_df, max_pain_df, max_pain_strike, 
                    info, strategy_signal, prob_levels, bayesian_result, structure_analysis, spot_price_analysis)
            
        except Exception as e:
            import traceback
            print(f"Error during analysis: {e}")
            traceback.print_exc()
            return None
            
    def open_admin_panel(self):
        AdminPanel(self.controller, self.controller.firebase_service)

    def show_about_dialog(self):
        """NEW: Displays the application's about information."""
        about_message = (
            f"OI Analyzer v{CURRENT_VERSION}\n\n" # Use the version variable
            "Designed by: Noby Ali\n"
            "Email: nobyaliyar@gmail.com\n"
            "Website: www.fexia.in"
        )
        messagebox.showinfo("About OI Analyzer", about_message)

    def export_to_csv(self):
        """NEW: Exports the full OI data to a CSV file."""
        if not self.last_analysis_result:
            messagebox.showinfo("No Data", "Please fetch data first before exporting.")
            return

        # Unpack the tuple to get the full DataFrame and info
        (_, _, _, full_chart_df, _, _, _, _, info, _, _, _, _, _) = self.last_analysis_result
        
        if full_chart_df is None or full_chart_df.empty:
            messagebox.showinfo("No Data", "The last fetched data was empty. Cannot export.")
            return
            
        symbol = info.get('symbol', 'data')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"oi_analysis_{symbol}_{timestamp}.csv"

        try:
            filepath = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile=filename,
                title="Save OI Data As"
            )
            if filepath:
                # Select and rename columns for a clean CSV output
                export_df = full_chart_df[[
                    'strikePrice', 
                    'CE.impliedVolatility', 'CE.openInterest', 'CE.changeinOpenInterest', 'CE.totalTradedVolume',
                    'PE.impliedVolatility', 'PE.openInterest', 'PE.changeinOpenInterest', 'PE.totalTradedVolume'
                ]].copy()
                export_df.columns = [
                    'Strike', 
                    'Call_IV', 'Call_OI', 'Call_Chng_OI', 'Call_Volume',
                    'Put_IV', 'Put_OI', 'Put_Chng_OI', 'Put_Volume'
                ]
                export_df.to_csv(filepath, index=False)
                self.update_status(f"Data successfully exported to {os.path.basename(filepath)}")
        except Exception as e:
            messagebox.showerror("Export Error", f"An error occurred while exporting the file:\n{e}")


# --- UI Frames ---
class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        label = ttk.Label(self, text="Welcome to the OI Analyzer", font=('Segoe UI', 16, 'bold'))
        label.pack(pady=20)
        sub_label = ttk.Label(self, text="Please log in with your Google account to continue.")
        sub_label.pack(pady=5)
        
        login_button = ttk.Button(self, text="Login with Google", command=self.controller.login)
        login_button.pack(pady=20, ipady=5, ipadx=10)

class WaitingFrame(ttk.Frame):
    def __init__(self, parent, controller, user_email):
        super().__init__(parent)
        self.controller = controller
        
        label = ttk.Label(self, text="Access Pending", font=('Segoe UI', 16, 'bold'))
        label.pack(pady=20)
        sub_label = ttk.Label(self, text=f"Your account ({user_email}) is waiting for admin approval.", wraplength=350)
        sub_label.pack(pady=5)
        
        logout_button = ttk.Button(self, text="Logout", command=self.controller.logout)
        logout_button.pack(pady=20)

class DeniedFrame(ttk.Frame):
    def __init__(self, parent, controller, user_email):
        super().__init__(parent)
        self.controller = controller

        label = ttk.Label(self, text="Access Denied", font=('Segoe UI', 16, 'bold'), foreground='red')
        label.pack(pady=20)
        sub_label = ttk.Label(self, text=f"Access for your account ({user_email}) has been denied by the administrator.", wraplength=350)
        sub_label.pack(pady=5)
        
        logout_button = ttk.Button(self, text="Logout", command=self.controller.logout)
        logout_button.pack(pady=20)


# --- NEW: Disclaimer Window ---
class DisclaimerFrame(tk.Toplevel):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.title("Disclaimer and Risk Warning")
        self.geometry("600x450")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.on_decline) # Handle closing the window

        # Center the window
        parent.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.rowconfigure(1, weight=1)
        main_frame.columnconfigure(0, weight=1)

        header = ttk.Label(main_frame, text="Disclaimer and Risk Warning", font=('Segoe UI', 14, 'bold'), foreground='red')
        header.grid(row=0, column=0, pady=(0, 10))
        
        disclaimer_text = """
This software, OI Analyzer, is provided for educational and informational purposes only. The data and analysis presented are NOT to be construed as financial or investment advice.

1.  **High Risk Activity**: Trading in financial markets, especially in derivatives (Futures & Options), is a high-risk activity and can result in the loss of your entire capital.

2.  **No Guarantee of Accuracy**: The data is sourced from third-party APIs (e.g., NSE, Deribit). The author does not guarantee the accuracy, timeliness, or completeness of this data. Delays, interruptions, and inaccuracies may occur.

3.  **No Liability**: The author, Noby Ali, and the software, OI Analyzer, shall not be held responsible or liable for any financial losses or damages you may incur as a result of using this software or acting upon the information it provides.

4.  **User's Sole Responsibility**: You are solely responsible for all your investment and trading decisions. Always conduct your own thorough research and consult with a qualified financial advisor before making any trades.

By clicking 'Accept', you acknowledge that you have read, understood, and agree to these terms.
"""
        text_frame = ttk.Frame(main_frame, relief="sunken", borderwidth=1)
        text_frame.grid(row=1, column=0, sticky="nsew", pady=5)
        
        text_widget = tk.Text(text_frame, wrap="word", padx=10, pady=10, font=('Segoe UI', 9), relief="flat", bg=self.cget('bg'))
        text_widget.insert(tk.END, disclaimer_text)
        text_widget.config(state="disabled")
        text_widget.pack(fill=tk.BOTH, expand=True)

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, pady=(10, 0))

        accept_button = ttk.Button(button_frame, text="Accept", command=self.on_accept)
        accept_button.pack(side=tk.LEFT, padx=10)

        decline_button = ttk.Button(button_frame, text="Decline", command=self.on_decline)
        decline_button.pack(side=tk.LEFT, padx=10)

        self.transient(parent)
        self.grab_set()
        parent.wait_window(self)

    def on_accept(self):
        self.destroy()
        self.controller.on_disclaimer_accepted()

    def on_decline(self):
        self.destroy()
        self.controller.on_disclaimer_declined()


class AppController(tk.Tk):
    """Main controller for the application. Manages frames and authentication state."""
    def __init__(self):
        super().__init__()
        self.title("NSE Option Chain Strategy Analyzer")
        # Increased window width to accommodate the new ad panel
        self.geometry("1600x1000")

        self.firebase_service = FirebaseService()
        self.auth_service = AuthService()
        self.current_user = None
        self.current_frame = None

        # --- NEW: Main layout with a PanedWindow to separate content and ads ---
        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # --- NEW: Ads Panel on the left ---
        ads_frame = ttk.Frame(main_pane, width=180, relief=tk.RAISED)
        main_pane.add(ads_frame, weight=0) # weight=0 makes this a fixed-width panel

        # --- Main Content Area (now on the right) ---
        # The self.container holds the main application (Login, MainFrame, etc.)
        self.container = ttk.Frame(main_pane) 
        main_pane.add(self.container, weight=1) # The weight allows this pane to expand

        # --- Ad Placeholder 1 (Now a clickable button) ---
        ad_placeholder_1 = ttk.LabelFrame(ads_frame, text="Advertisement")
        ad_placeholder_1.pack(pady=(10, 5), padx=10, fill=tk.BOTH, expand=True)
        # Use a Button instead of a Label
        ad_button_1 = ttk.Button(ad_placeholder_1, text="Loading Ad...", command=lambda: self.on_ad_click("https://www.fexia.in"))
        ad_button_1.pack(pady=0, padx=0, expand=True, fill=tk.BOTH)
        # Load the ad image onto the button
        self.load_ad_image(ad_button_1, "https://placehold.co/160x300/E8D4FD/5D3FD3?text=Trading+Platform\nAd", (160, 300))

        # --- Ad Placeholder 2 (Now a clickable button) ---
        ad_placeholder_2 = ttk.LabelFrame(ads_frame, text="Advertisement")
        ad_placeholder_2.pack(pady=(5, 10), padx=10, fill=tk.BOTH, expand=True)
        # Use a Button instead of a Label
        ad_button_2 = ttk.Button(ad_placeholder_2, text="Loading Ad...", command=lambda: self.on_ad_click("https://www.google.com"))
        ad_button_2.pack(pady=0, padx=0, expand=True, fill=tk.BOTH)
        # Load the ad image onto the button
        self.load_ad_image(ad_button_2, "https://placehold.co/160x300/D4FDE8/3F9D5D?text=Investment+Tips\nAd", (160, 300))
        # --- End of Ads Panel ---

        # --- Check for updates on startup ---
        self.check_for_updates()

        # --- Add a check to warn user if Admin UID is not configured ---
        if ADMIN_UID == "REPLACE_WITH_YOUR_ADMIN_UID":
            messagebox.showwarning("Admin UID Not Set", 
                                   "The Admin Panel button will not be visible because the ADMIN_UID has not been set in the script.\n\n"
                                   "To fix this, find your User UID in the Firebase Authentication console and update the ADMIN_UID variable in the code.")

        self.check_login_status()

    def load_ad_image(self, ad_label, url, size):
        """Loads an ad image from a URL in a background thread to avoid UI freezes."""
        def _load():
            try:
                # --- MODIFIED: Use the standard browser header ---
                response = requests.get(url, stream=True, headers=BROWSER_HEADER)
                response.raise_for_status()
                
                # Open image using Pillow
                pil_image = Image.open(response.raw)
                # Resize to fit the placeholder
                pil_image = pil_image.resize(size, Image.LANCZOS)
                
                # Convert to Tkinter compatible format
                photo_image = ImageTk.PhotoImage(pil_image)
                
                # Schedule UI update on the main thread
                self.after(0, self.update_ad_label, ad_label, photo_image)

            except Exception as e:
                print(f"Failed to load ad image: {e}")
                # Optionally update the label to show an error
                self.after(0, lambda: ad_label.config(text="Ad failed to load"))

        # Run the loading process in a separate thread
        threading.Thread(target=_load, daemon=True).start()

    def update_ad_label(self, ad_widget, photo_image):
        """Safely updates the ad widget (Button or Label) with the new image on the main UI thread."""
        ad_widget.config(image=photo_image, text="") # Remove the "Loading Ad..." text
        # IMPORTANT: Keep a reference to the image to prevent it from being garbage collected
        ad_widget.image = photo_image

    def on_ad_click(self, url):
        """NEW: Opens a URL in the default web browser when an ad is clicked."""
        try:
            webbrowser.open_new(url)
        except Exception as e:
            print(f"Failed to open URL: {e}")
            messagebox.showerror("Error", f"Could not open the link: {url}")

    def show_frame(self, FrameClass, **kwargs):
        if self.current_frame:
            self.current_frame.destroy()
        
        self.current_frame = FrameClass(self.container, self, **kwargs)
        self.current_frame.pack(fill="both", expand=True)

    def login(self):
        user_info = self.auth_service.login_with_google()
        if user_info:
            self.current_user = user_info
            uid = user_info['id']
            name = user_info.get('name', '')
            email = user_info.get('email', '')

            if uid == ADMIN_UID:
                self.handle_user_status('approved', email)
                return
            
            status, _ = self.firebase_service.get_user_status(uid)
            
            if status is None: # New user
                self.firebase_service.create_user_profile(uid, name, email)
                self.show_frame(WaitingFrame, user_email=email)
            else:
                # --- FIX: Corrected indentation for this line ---
                self.handle_user_status(status, email)

    def logout(self):
        self.auth_service.logout()
        self.current_user = None
        self.show_frame(LoginFrame)
        
    def check_login_status(self):
        if os.path.exists('token.pickle'):
                 self.login()
        else:
                 self.show_frame(LoginFrame)

    def handle_user_status(self, status, email):
        if status == 'approved':
            self.show_disclaimer()
        elif status == 'pending':
            self.show_frame(WaitingFrame, user_email=email)
        elif status == 'denied':
            self.show_frame(DeniedFrame, user_email=email)
        else:
            self.show_frame(LoginFrame)

    # --- NEW: Disclaimer Handling Functions ---
    def show_disclaimer(self):
        """Displays the modal disclaimer window."""
        DisclaimerFrame(self, self)

    def on_disclaimer_accepted(self):
        """Proceeds to the main application after disclaimer acceptance."""
        self.show_frame(MainApplicationFrame, current_user=self.current_user)

    def on_disclaimer_declined(self):
        """Logs the user out if the disclaimer is declined."""
        self.logout()

    # --- NEW: Function to handle application closing ---
    def on_closing(self):
        """Called when the main window is closed."""
        if isinstance(self.current_frame, MainApplicationFrame):
            # This check is no longer needed as we removed the driver
            pass
        self.destroy()


    # --- NEW: OTA Update Functions ---
    def check_for_updates(self):
        """Checks for a new version in a background thread."""
        threading.Thread(target=self._check_version, daemon=True).start()

    def _check_version(self):
        try:
            # --- MODIFIED: Use the standard browser header ---
            response = requests.get(VERSION_URL, timeout=10, headers=BROWSER_HEADER)
            response.raise_for_status()
            version_info = response.json()
            latest_version = version_info.get("version")

            # Compare versions (e.g., "3.1.0" vs "3.0.0")
            if latest_version and tuple(map(int, latest_version.split('.'))) > tuple(map(int, CURRENT_VERSION.split('.'))):
                self.after(0, self.prompt_for_update, version_info)

        except Exception as e:
            print(f"Update check failed: {e}")

    def prompt_for_update(self, version_info):
        latest_version = version_info.get("version")
        release_notes = version_info.get("release_notes", "No release notes provided.")
        
        update_message = (
            f"A new version ({latest_version}) is available!\n\n"
            f"You are currently on version {CURRENT_VERSION}.\n\n"
            f"Release Notes:\n{release_notes}\n\n"
            "Would you like to download and install it now?"
        )
        if messagebox.askyesno("Update Available", update_message):
            self.download_and_install_update(version_info)
    
    def download_and_install_update(self, version_info):
        download_url = version_info.get("url")
        updater_url = version_info.get("updater_url")

        if not download_url or not updater_url:
            messagebox.showerror("Update Error", "Update URL is missing from the version file.")
            return

        # Show a progress window
        progress_win = tk.Toplevel(self)
        progress_win.title("Updating...")
        progress_win.geometry("300x100")
        ttk.Label(progress_win, text="Downloading update, please wait...").pack(pady=10)
        progress_bar = ttk.Progressbar(progress_win, mode='indeterminate')
        progress_bar.pack(pady=10, padx=10, fill=tk.X)
        progress_bar.start()
        self.update_idletasks()


        def _download():
            try:
                # Download the new application file
                new_app_filename = "oi_analyzer_app_new.py"
                # --- MODIFIED: Use the standard browser header ---
                response = requests.get(download_url, stream=True, headers=BROWSER_HEADER)
                response.raise_for_status()
                with open(new_app_filename, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                # Download the updater script
                updater_filename = "updater.py"
                # --- MODIFIED: Use the standard browser header ---
                response_updater = requests.get(updater_url, headers=BROWSER_HEADER)
                response_updater.raise_for_status()
                with open(updater_filename, "w") as f:
                    f.write(response_updater.text)
                
                # Launch the updater and close this app
                # The updater will replace the old file with the new one
                current_app_path = os.path.realpath(sys.argv[0])
                subprocess.Popen([sys.executable, updater_filename, current_app_path, new_app_filename])
                self.after(0, self.destroy)

            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Update Failed", f"Failed to download update: {e}"))
            finally:
                self.after(0, progress_win.destroy)

        threading.Thread(target=_download, daemon=True).start()


if __name__ == '__main__':
    app = AppController()
    app.protocol("WM_DELETE_WINDOW", app.on_closing) # Handle window close event
    app.mainloop()




v