from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash
import requests
import hashlib
import time
import uuid
from datetime import datetime
import os
import json
import sqlite3
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')

# Database initialization
def init_db():
    conn = sqlite3.connect('iptv.db')
    c = conn.cursor()
    
    # Create portals table
    c.execute('''CREATE TABLE IF NOT EXISTS portals
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  url TEXT NOT NULL,
                  mac TEXT,
                  sn TEXT,
                  device_id TEXT,
                  device_id2 TEXT,
                  signature TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  active INTEGER DEFAULT 1)''')
    
    # Create channels table
    c.execute('''CREATE TABLE IF NOT EXISTS channels
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  portal_id INTEGER,
                  name TEXT NOT NULL,
                  stream_url TEXT NOT NULL,
                  logo_url TEXT,
                  category TEXT,
                  epg_id TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (portal_id) REFERENCES portals (id))''')
    
    # Create categories table
    c.execute('''CREATE TABLE IF NOT EXISTS categories
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  portal_id INTEGER,
                  name TEXT NOT NULL,
                  FOREIGN KEY (portal_id) REFERENCES portals (id))''')
    
    conn.commit()
    conn.close()

# Portal authentication and management
class PortalManager:
    def __init__(self):
        self.session_timeout = 3600  # 1 hour
    
    def generate_signature(self, mac, sn, device_id, timestamp):
        """Generate signature for portal authentication"""
        data = f"{mac}:{sn}:{device_id}:{timestamp}"
        return hashlib.md5(data.encode()).hexdigest()
    
    def authenticate_portal(self, portal_data):
        """Authenticate with IPTV portal"""
        try:
            url = portal_data['url'].rstrip('/')
            mac = portal_data.get('mac', '')
            sn = portal_data.get('sn', '')
            device_id = portal_data.get('device_id', '')
            device_id2 = portal_data.get('device_id2', '')
            
            # Generate timestamp and signature
            timestamp = str(int(time.time()))
            signature = portal_data.get('signature', '') or self.generate_signature(mac, sn, device_id, timestamp)
            
            # Prepare authentication parameters
            auth_params = {
                'type': 'stb',
                'action': 'handshake',
                'JsHttpRequest': f'1-xml',
                'mac': mac,
                'sn': sn,
                'device_id': device_id,
                'device_id2': device_id2,
                'signature': signature,
                'timestamp': timestamp
            }
            
            # Make handshake request
            headers = {
                'User-Agent': 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3',
                'X-User-Agent': 'Model: MAG250; Link: WiFi',
                'Authorization': f'Bearer {signature}'
            }
            
            response = requests.get(f"{url}/server/load.php", params=auth_params, headers=headers, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('js', {}).get('token'):
                    return {
                        'success': True,
                        'token': result['js']['token'],
                        'random': result['js'].get('random', ''),
                        'message': 'Authentication successful'
                    }
            
            return {'success': False, 'message': 'Authentication failed'}
            
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    def get_channels(self, portal_id):
        """Get channels from portal"""
        conn = sqlite3.connect('iptv.db')
        c = conn.cursor()
        
        # Get portal info
        c.execute('SELECT * FROM portals WHERE id = ? AND active = 1', (portal_id,))
        portal = c.fetchone()
        
        if not portal:
            conn.close()
            return {'success': False, 'message': 'Portal not found'}
        
        # Get cached channels
        c.execute('SELECT * FROM channels WHERE portal_id = ?', (portal_id,))
        channels = c.fetchall()
        
        conn.close()
        
        if channels:
            return {
                'success': True,
                'channels': [
                    {
                        'id': ch[0],
                        'name': ch[2],
                        'stream_url': ch[3],
                        'logo_url': ch[4],
                        'category': ch[5],
                        'epg_id': ch[6]
                    } for ch in channels
                ]
            }
        
        # If no cached channels, try to fetch from portal
        return self._fetch_channels_from_portal(portal)
    
    def _fetch_channels_from_portal(self, portal):
        """Fetch channels directly from portal API"""
        try:
            # This is a simplified example - actual implementation depends on portal API
            portal_data = {
                'name': portal[1],
                'url': portal[2],
                'mac': portal[3],
                'sn': portal[4],
                'device_id': portal[5],
                'device_id2': portal[6],
                'signature': portal[7]
            }
            
            auth_result = self.authenticate_portal(portal_data)
            if not auth_result['success']:
                return auth_result
            
            # Fetch channels (implementation depends on specific portal API)
            # This is a placeholder - you'd need to implement actual API calls
            return {'success': True, 'channels': []}
            
        except Exception as e:
            return {'success': False, 'message': f'Error fetching channels: {str(e)}'}

portal_manager = PortalManager()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Simple login - in production, use proper authentication
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == 'admin' and password == 'admin':  # Change this!
            session['user_id'] = 1
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('iptv.db')
    c = conn.cursor()
    c.execute('SELECT * FROM portals WHERE active = 1')
    portals = c.fetchall()
    conn.close()
    
    return render_template('dashboard.html', portals=portals)

@app.route('/portals')
@login_required
def portals():
    conn = sqlite3.connect('iptv.db')
    c = conn.cursor()
    c.execute('SELECT * FROM portals ORDER BY created_at DESC')
    portals = c.fetchall()
    conn.close()
    
    return render_template('portals.html', portals=portals)

@app.route('/add_portal', methods=['GET', 'POST'])
@login_required
def add_portal():
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            url = request.form.get('url')
            mac = request.form.get('mac', '')
            sn = request.form.get('sn', '')
            device_id = request.form.get('device_id', '')
            device_id2 = request.form.get('device_id2', '')
            signature = request.form.get('signature', '')
            
            # Test portal connection
            portal_data = {
                'name': name,
                'url': url,
                'mac': mac,
                'sn': sn,
                'device_id': device_id,
                'device_id2': device_id2,
                'signature': signature
            }
            
            auth_result = portal_manager.authenticate_portal(portal_data)
            
            conn = sqlite3.connect('iptv.db')
            c = conn.cursor()
            c.execute('''INSERT INTO portals (name, url, mac, sn, device_id, device_id2, signature)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                      (name, url, mac, sn, device_id, device_id2, signature))
            conn.commit()
            conn.close()
            
            if auth_result['success']:
                flash(f'Portal "{name}" added successfully and authenticated!', 'success')
            else:
                flash(f'Portal "{name}" added but authentication failed: {auth_result["message"]}', 'warning')
            
            return redirect(url_for('portals'))
            
        except Exception as e:
            flash(f'Error adding portal: {str(e)}', 'error')
    
    return render_template('add_portal.html')

@app.route('/test_portal/<int:portal_id>')
@login_required
def test_portal(portal_id):
    conn = sqlite3.connect('iptv.db')
    c = conn.cursor()
    c.execute('SELECT * FROM portals WHERE id = ?', (portal_id,))
    portal = c.fetchone()
    conn.close()
    
    if not portal:
        return jsonify({'success': False, 'message': 'Portal not found'})
    
    portal_data = {
        'name': portal[1],
        'url': portal[2],
        'mac': portal[3],
        'sn': portal[4],
        'device_id': portal[5],
        'device_id2': portal[6],
        'signature': portal[7]
    }
    
    result = portal_manager.authenticate_portal(portal_data)
    return jsonify(result)

@app.route('/channels/<int:portal_id>')
@login_required
def channels(portal_id):
    result = portal_manager.get_channels(portal_id)
    
    if result['success']:
        return render_template('channels.html', 
                             channels=result['channels'], 
                             portal_id=portal_id)
    else:
        flash(f'Error loading channels: {result["message"]}', 'error')
        return redirect(url_for('portals'))

@app.route('/api/portals', methods=['GET'])
@login_required
def api_portals():
    conn = sqlite3.connect('iptv.db')
    c = conn.cursor()
    c.execute('SELECT id, name, url, active FROM portals')
    portals = c.fetchall()
    conn.close()
    
    return jsonify({
        'portals': [
            {
                'id': p[0],
                'name': p[1],
                'url': p[2],
                'active': bool(p[3])
            } for p in portals
        ]
    })

@app.route('/api/channels/<int:portal_id>', methods=['GET'])
@login_required
def api_channels(portal_id):
    result = portal_manager.get_channels(portal_id)
    return jsonify(result)

@app.route('/player/<int:portal_id>/<int:channel_id>')
@login_required
def player(portal_id, channel_id):
    conn = sqlite3.connect('iptv.db')
    c = conn.cursor()
    c.execute('''SELECT c.*, p.name as portal_name 
                 FROM channels c 
                 JOIN portals p ON c.portal_id = p.id 
                 WHERE c.id = ? AND c.portal_id = ?''', (channel_id, portal_id))
    channel = c.fetchone()
    conn.close()
    
    if not channel:
        flash('Channel not found!', 'error')
        return redirect(url_for('channels', portal_id=portal_id))
    
    return render_template('player.html', channel=channel)

@app.route('/m3u/<int:portal_id>')
@login_required
def generate_m3u(portal_id):
    result = portal_manager.get_channels(portal_id)
    
    if not result['success']:
        return "Error generating M3U playlist", 400
    
    m3u_content = "#EXTM3U\n"
    for channel in result['channels']:
        m3u_content += f'#EXTINF:-1 tvg-id="{channel.get("epg_id", "")}" tvg-logo="{channel.get("logo_url", "")}" group-title="{channel.get("category", "")}", {channel["name"]}\n'
        m3u_content += f'{channel["stream_url"]}\n'
    
    response = app.response_class(
        response=m3u_content,
        status=200,
        mimetype='application/x-mpegurl'
    )
    response.headers["Content-Disposition"] = f"attachment; filename=playlist_{portal_id}.m3u"
    return response

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)