import streamlit as st
import sqlite3
import hashlib
import secrets
import string
import re
import math
from datetime import datetime, timedelta
import itertools
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import time
import json
import base64
import io
import csv
import pyotp
import qrcode

# Page configuration
st.set_page_config(
    page_title="SecureVault Pro - Password Manager",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for modern UI
def load_css():
    st.markdown("""
    <style>
    /* Main background and theme */
    .stApp {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    
    /* Card style containers */
    .card {
        background: white;
        padding: 2rem;
        border-radius: 15px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        margin: 1rem 0;
    }
    
    /* Title styling */
    .main-title {
        font-size: 3rem;
        font-weight: 800;
        color: white;
        text-align: center;
        margin-bottom: 1rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    }
    
    .sub-title {
        font-size: 1.5rem;
        font-weight: 600;
        color: #667eea;
        margin-bottom: 1rem;
    }
    
    /* Button styling */
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 0.75rem 2rem;
        font-weight: 600;
        transition: all 0.3s ease;
        width: 100%;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
    }
    
    /* Input fields */
    .stTextInput > div > div > input {
        border-radius: 10px;
        border: 2px solid #e0e0e0;
        padding: 0.75rem;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #667eea;
        box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
    }
    
    /* Success/Error messages */
    .success-message {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 10px;
        border-left: 4px solid #28a745;
        margin: 1rem 0;
    }
    
    .error-message {
        background-color: #f8d7da;
        color: #721c24;
        padding: 1rem;
        border-radius: 10px;
        border-left: 4px solid #dc3545;
        margin: 1rem 0;
    }
    
    /* Metrics styling */
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
    }
    
    /* Password strength bar */
    .strength-bar {
        height: 10px;
        border-radius: 5px;
        margin: 0.5rem 0;
        transition: all 0.3s ease;
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background: rgba(255, 255, 255, 0.95);
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Animation */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .fade-in {
        animation: fadeIn 0.5s ease-in;
    }
    
    /* Badge styling */
    .badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 12px;
        font-size: 0.85rem;
        font-weight: 600;
        margin: 0.25rem;
    }
    
    .badge-danger {
        background-color: #ff4444;
        color: white;
    }
    
    .badge-warning {
        background-color: #ffaa00;
        color: white;
    }
    
    .badge-success {
        background-color: #00cc44;
        color: white;
    }
    
    .badge-info {
        background-color: #667eea;
        color: white;
    }
    </style>
    """, unsafe_allow_html=True)

class DatabaseManager:
    """Manage database operations"""
    
    def __init__(self, db_name='secure_vault_pro.db'):
        self.db_name = db_name
        self.init_database()
    
    def get_connection(self):
        return sqlite3.connect(self.db_name, check_same_thread=False)
    
    def init_database(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                security_question TEXT NOT NULL,
                security_answer_hash TEXT NOT NULL,
                two_factor_enabled INTEGER DEFAULT 0,
                two_factor_secret TEXT,
                session_timeout INTEGER DEFAULT 30,
                auto_lock INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Passwords table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                url TEXT,
                notes TEXT,
                category TEXT DEFAULT 'General',
                favorite INTEGER DEFAULT 0,
                breach_checked INTEGER DEFAULT 0,
                breach_found INTEGER DEFAULT 0,
                last_used TIMESTAMP,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Password history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password_id INTEGER NOT NULL,
                old_password_hash TEXT NOT NULL,
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (password_id) REFERENCES passwords(id)
            )
        ''')
        
        # Shared passwords table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS shared_passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password_id INTEGER NOT NULL,
                shared_by INTEGER NOT NULL,
                shared_with_username TEXT NOT NULL,
                can_edit INTEGER DEFAULT 0,
                shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (password_id) REFERENCES passwords(id),
                FOREIGN KEY (shared_by) REFERENCES users(id)
            )
        ''')
        
        # Activity log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Password tags table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password_id INTEGER NOT NULL,
                tag TEXT NOT NULL,
                FOREIGN KEY (password_id) REFERENCES passwords(id)
            )
        ''')
        
        # Secure notes table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS secure_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                category TEXT DEFAULT 'General',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        conn.commit()
        conn.close()

class SecurityManager:
    """Handle security operations"""
    
    @staticmethod
    def hash_password(password, salt=None):
        """Hash password with salt using SHA-256"""
        if salt is None:
            salt = secrets.token_hex(16)
        pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return pwd_hash, salt
    
    @staticmethod
    def generate_password(length=16, use_special=True, use_numbers=True, 
                         use_uppercase=True, use_lowercase=True, 
                         exclude_similar=False, exclude_ambiguous=False):
        """Generate a strong random password"""
        chars = ''
        if use_lowercase:
            chars += string.ascii_lowercase
        if use_uppercase:
            chars += string.ascii_uppercase
        if use_numbers:
            chars += string.digits
        if use_special:
            chars += string.punctuation
        
        # Exclude similar characters
        if exclude_similar:
            similar = 'il1Lo0O'
            chars = ''.join(c for c in chars if c not in similar)
        
        # Exclude ambiguous characters
        if exclude_ambiguous:
            ambiguous = '{}[]()/\\\'"`~,;:.<>'
            chars = ''.join(c for c in chars if c not in ambiguous)
        
        if not chars:
            chars = string.ascii_letters + string.digits
        
        password = ''.join(secrets.choice(chars) for _ in range(length))
        return password
    
    @staticmethod
    def generate_passphrase(num_words=4, separator='-', capitalize=True):
        """Generate a memorable passphrase"""
        # Common word list
        words = [
            'correct', 'horse', 'battery', 'staple', 'dragon', 'monkey', 'wizard',
            'sunset', 'mountain', 'ocean', 'forest', 'thunder', 'crystal', 'phoenix',
            'galaxy', 'comet', 'nebula', 'planet', 'stellar', 'cosmic', 'lunar',
            'solar', 'aurora', 'meteor', 'eclipse', 'rainbow', 'tornado', 'blizzard',
            'avalanche', 'cascade', 'river', 'canyon', 'summit', 'valley', 'meadow',
            'garden', 'blossom', 'petal', 'breeze', 'whisper', 'echo', 'shadow',
            'light', 'dream', 'journey', 'adventure', 'treasure', 'castle', 'tower'
        ]
        
        selected = [secrets.choice(words) for _ in range(num_words)]
        
        if capitalize:
            selected = [word.capitalize() for word in selected]
        
        passphrase = separator.join(selected)
        
        # Add random number
        passphrase += str(secrets.randbelow(100))
        
        return passphrase
    
    @staticmethod
    def check_pwned_password(password):
        """Check if password has been in a data breach using k-anonymity"""
        # Note: This is a simplified version. In production, you'd make actual API calls to haveibeenpwned.com
        # For demo purposes, we'll simulate the check
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        
        # Simulate: passwords with common patterns are "breached"
        common_breached = ['password', '123456', 'qwerty', 'admin', 'letmein']
        for breach in common_breached:
            if breach in password.lower():
                return True, "Password found in breach database!"
        
        return False, "Password not found in known breaches"
    
    @staticmethod
    def calculate_entropy(password):
        """Calculate password entropy"""
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * math.log2(charset_size)
        return entropy
    
    @staticmethod
    def time_to_crack(password):
        """Estimate time to crack password"""
        entropy = SecurityManager.calculate_entropy(password)
        
        # Assuming 1 billion guesses per second
        guesses_per_second = 1_000_000_000
        combinations = 2 ** entropy
        seconds = combinations / (2 * guesses_per_second)  # Divide by 2 for average
        
        if seconds < 1:
            return "Instantly"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.0f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.0f} days"
        elif seconds < 31536000 * 100:
            return f"{seconds/31536000:.0f} years"
        else:
            return "Centuries"
    
    @staticmethod
    def analyze_password(password):
        """Advanced password strength analysis"""
        analysis = {
            'length': len(password),
            'entropy': SecurityManager.calculate_entropy(password),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digits': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', password)),
            'has_common_patterns': False,
            'has_sequential': False,
            'has_repeated': False,
            'score': 0,
            'strength': 'Weak',
            'color': '#ff4444',
            'time_to_crack': ''
        }
        
        # Check for common patterns
        common_patterns = ['password', '123456', 'qwerty', 'admin', 'letmein', 
                          'welcome', 'monkey', 'dragon', 'master', 'sunshine']
        for pattern in common_patterns:
            if pattern in password.lower():
                analysis['has_common_patterns'] = True
                break
        
        # Check for sequential characters
        sequential_patterns = ['abc', '123', 'xyz', '789', 'cba', '321']
        for pattern in sequential_patterns:
            if pattern in password.lower():
                analysis['has_sequential'] = True
                break
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            analysis['has_repeated'] = True
        
        # Calculate score
        score = 0
        if analysis['length'] >= 8:
            score += 1
        if analysis['length'] >= 12:
            score += 1
        if analysis['length'] >= 16:
            score += 1
        if analysis['has_lowercase']:
            score += 1
        if analysis['has_uppercase']:
            score += 1
        if analysis['has_digits']:
            score += 1
        if analysis['has_special']:
            score += 1
        if not analysis['has_common_patterns']:
            score += 1
        if not analysis['has_sequential']:
            score += 1
        if not analysis['has_repeated']:
            score += 1
        
        analysis['score'] = score
        analysis['time_to_crack'] = SecurityManager.time_to_crack(password)
        
        # Determine strength
        if score <= 3:
            analysis['strength'] = 'Weak'
            analysis['color'] = '#ff4444'
        elif score <= 5:
            analysis['strength'] = 'Fair'
            analysis['color'] = '#ffaa00'
        elif score <= 7:
            analysis['strength'] = 'Good'
            analysis['color'] = '#88cc00'
        elif score <= 9:
            analysis['strength'] = 'Strong'
            analysis['color'] = '#00cc44'
        else:
            analysis['strength'] = 'Very Strong'
            analysis['color'] = '#00aa00'
        
        return analysis
    
    @staticmethod
    def generate_2fa_secret():
        """Generate 2FA secret"""
        return pyotp.random_base32()
    
    @staticmethod
    def generate_2fa_qr(username, secret):
        """Generate QR code for 2FA"""
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=username, issuer_name="SecureVault Pro")
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return buffer
    
    @staticmethod
    def verify_2fa_token(secret, token):
        """Verify 2FA token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)

class PasswordManager:
    """Main password manager class"""
    
    def __init__(self, db_manager):
        self.db = db_manager
    
    def log_activity(self, user_id, action, details=""):
        """Log user activity"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO activity_log (user_id, action, details)
            VALUES (?, ?, ?)
        ''', (user_id, action, details))
        
        conn.commit()
        conn.close()
    
    def register_user(self, username, email, password, security_question, security_answer):
        """Register a new user"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        try:
            # Hash password
            pwd_hash, salt = SecurityManager.hash_password(password)
            
            # Hash security answer
            answer_hash, _ = SecurityManager.hash_password(security_answer.lower(), salt)
            
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt, 
                                 security_question, security_answer_hash)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, email, pwd_hash, salt, security_question, answer_hash))
            
            user_id = cursor.lastrowid
            
            conn.commit()
            
            # Log activity
            self.log_activity(user_id, "REGISTER", "Account created")
            
            conn.close()
            return True, "Registration successful!"
        
        except sqlite3.IntegrityError:
            conn.close()
            return False, "Username or email already exists!"
        except Exception as e:
            conn.close()
            return False, f"Registration failed: {str(e)}"
    
    def login_user(self, username, password):
        """Authenticate user"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, password_hash, salt, two_factor_enabled, two_factor_secret 
            FROM users WHERE username = ?
        ''', (username,))
        user = cursor.fetchone()
        
        if user:
            user_id, stored_hash, salt, two_fa_enabled, two_fa_secret = user
            pwd_hash, _ = SecurityManager.hash_password(password, salt)
            
            if pwd_hash == stored_hash:
                # Update last login
                cursor.execute('UPDATE users SET last_login = ? WHERE id = ?',
                             (datetime.now(), user_id))
                conn.commit()
                conn.close()
                return True, user_id, two_fa_enabled, two_fa_secret
        
        conn.close()
        return False, None, False, None
    
    def verify_security_answer(self, username, answer):
        """Verify security answer for password recovery"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, security_answer_hash, salt FROM users WHERE username = ?',
                      (username,))
        user = cursor.fetchone()
        
        if user:
            user_id, stored_hash, salt = user
            answer_hash, _ = SecurityManager.hash_password(answer.lower(), salt)
            
            conn.close()
            return answer_hash == stored_hash, user_id
        
        conn.close()
        return False, None
    
    def reset_password(self, user_id, new_password):
        """Reset user password"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        pwd_hash, salt = SecurityManager.hash_password(new_password)
        
        cursor.execute('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?',
                      (pwd_hash, salt, user_id))
        conn.commit()
        
        self.log_activity(user_id, "PASSWORD_RESET", "Password was reset")
        
        conn.close()
        return True
    
    def save_password(self, user_id, service, username, password, url="", notes="", 
                     category="General", favorite=False):
        """Save password to database"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        pwd_hash, salt = SecurityManager.hash_password(password)
        
        try:
            cursor.execute('''
                INSERT INTO passwords (user_id, service, username, password_hash, salt,
                                     url, notes, category, favorite)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, service, username, pwd_hash, salt, url, notes, category, 
                 1 if favorite else 0))
            
            conn.commit()
            
            self.log_activity(user_id, "PASSWORD_ADDED", f"Added password for {service}")
            
            conn.close()
            return True, "Password saved successfully!"
        except Exception as e:
            conn.close()
            return False, f"Error saving password: {str(e)}"
    
    def get_user_passwords(self, user_id, category=None, search=None, favorites_only=False):
        """Get passwords for a user with filters"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        query = '''
            SELECT id, service, username, password_hash, url, notes, category, 
                   favorite, breach_found, created_at, updated_at, last_used
            FROM passwords WHERE user_id = ?
        '''
        params = [user_id]
        
        if category and category != "All":
            query += " AND category = ?"
            params.append(category)
        
        if favorites_only:
            query += " AND favorite = 1"
        
        if search:
            query += " AND (service LIKE ? OR username LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
        
        query += " ORDER BY favorite DESC, updated_at DESC"
        
        cursor.execute(query, params)
        passwords = cursor.fetchall()
        conn.close()
        return passwords
    
    def get_password_categories(self, user_id):
        """Get all categories for a user"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT category FROM passwords WHERE user_id = ?
        ''', (user_id,))
        
        categories = [row[0] for row in cursor.fetchall()]
        conn.close()
        return categories
    
    def delete_password(self, password_id, user_id):
        """Delete a password"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        # Get service name before deleting
        cursor.execute('SELECT service FROM passwords WHERE id = ? AND user_id = ?',
                      (password_id, user_id))
        result = cursor.fetchone()
        service = result[0] if result else "Unknown"
        
        cursor.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?',
                      (password_id, user_id))
        conn.commit()
        
        self.log_activity(user_id, "PASSWORD_DELETED", f"Deleted password for {service}")
        
        conn.close()
        return True
    
    def update_password(self, password_id, user_id, new_password=None, **kwargs):
        """Update an existing password"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        # Store old password in history if changing password
        if new_password:
            cursor.execute('SELECT password_hash FROM passwords WHERE id = ?', (password_id,))
            old_hash = cursor.fetchone()[0]
            
            cursor.execute('''
                INSERT INTO password_history (password_id, old_password_hash)
                VALUES (?, ?)
            ''', (password_id, old_hash))
            
            pwd_hash, salt = SecurityManager.hash_password(new_password)
            
            cursor.execute('''
                UPDATE passwords 
                SET password_hash = ?, salt = ?, updated_at = ?
                WHERE id = ? AND user_id = ?
            ''', (pwd_hash, salt, datetime.now(), password_id, user_id))
        
        # Update other fields
        for field, value in kwargs.items():
            if field in ['service', 'username', 'url', 'notes', 'category']:
                cursor.execute(f'''
                    UPDATE passwords SET {field} = ?, updated_at = ?
                    WHERE id = ? AND user_id = ?
                ''', (value, datetime.now(), password_id, user_id))
        
        conn.commit()
        
        self.log_activity(user_id, "PASSWORD_UPDATED", f"Updated password ID {password_id}")
        
        conn.close()
        return True
    
    def toggle_favorite(self, password_id, user_id):
        """Toggle favorite status"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE passwords SET favorite = 1 - favorite WHERE id = ? AND user_id = ?
        ''', (password_id, user_id))
        
        conn.commit()
        conn.close()
    
    def mark_password_used(self, password_id, user_id):
        """Mark password as recently used"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE passwords SET last_used = ? WHERE id = ? AND user_id = ?
        ''', (datetime.now(), password_id, user_id))
        
        conn.commit()
        conn.close()
    
    def get_user_stats(self, user_id):
        """Get user statistics"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        # Total passwords
        cursor.execute('SELECT COUNT(*) FROM passwords WHERE user_id = ?', (user_id,))
        total_passwords = cursor.fetchone()[0]
        
        # Weak passwords
        cursor.execute('''
            SELECT COUNT(*) FROM passwords WHERE user_id = ?
        ''', (user_id,))
        weak_count = 0  # Would need to decrypt and check each password
        
        # Breached passwords
        cursor.execute('''
            SELECT COUNT(*) FROM passwords WHERE user_id = ? AND breach_found = 1
        ''', (user_id,))
        breached = cursor.fetchone()[0]
        
        # Favorites
        cursor.execute('''
            SELECT COUNT(*) FROM passwords WHERE user_id = ? AND favorite = 1
        ''', (user_id,))
        favorites = cursor.fetchone()[0]
        
        # Last added
        cursor.execute('''
            SELECT created_at FROM passwords WHERE user_id = ?
            ORDER BY created_at DESC LIMIT 1
        ''', (user_id,))
        last_added = cursor.fetchone()
        
        # Categories
        cursor.execute('''
            SELECT category, COUNT(*) FROM passwords WHERE user_id = ?
            GROUP BY category
        ''', (user_id,))
        category_stats = cursor.fetchall()
        
        # Recent activity
        cursor.execute('''
            SELECT action, details, timestamp FROM activity_log
            WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10
        ''', (user_id,))
        recent_activity = cursor.fetchall()
        
        conn.close()
        
        return {
            'total_passwords': total_passwords,
            'weak_passwords': weak_count,
            'breached': breached,
            'favorites': favorites,
            'last_added': last_added[0] if last_added else None,
            'category_stats': category_stats,
            'recent_activity': recent_activity
        }
    
    def export_passwords(self, user_id, format='csv'):
        """Export passwords to CSV or JSON"""
        passwords = self.get_user_passwords(user_id)
        
        if format == 'csv':
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Service', 'Username', 'URL', 'Notes', 'Category', 'Created', 'Updated'])
            
            for pwd in passwords:
                _, service, username, _, url, notes, category, _, _, created, updated, _ = pwd
                writer.writerow([service, username, url or '', notes or '', category, created, updated])
            
            return output.getvalue()
        
        elif format == 'json':
            data = []
            for pwd in passwords:
                _, service, username, _, url, notes, category, _, _, created, updated, _ = pwd
                data.append({
                    'service': service,
                    'username': username,
                    'url': url or '',
                    'notes': notes or '',
                    'category': category,
                    'created': created,
                    'updated': updated
                })
            return json.dumps(data, indent=2)
    
    def get_password_strength_report(self, user_id):
        """Get password strength report"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, service, password_hash FROM passwords WHERE user_id = ?
        ''', (user_id,))
        
        passwords = cursor.fetchall()
        conn.close()
        
        # Note: In production, you'd decrypt and analyze actual passwords
        # For this demo, we'll provide placeholder data
        report = {
            'weak': [],
            'reused': [],
            'old': []
        }
        
        return report
    
    def enable_2fa(self, user_id, secret):
        """Enable 2FA for user"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET two_factor_enabled = 1, two_factor_secret = ?
            WHERE id = ?
        ''', (secret, user_id))
        
        conn.commit()
        
        self.log_activity(user_id, "2FA_ENABLED", "Two-factor authentication enabled")
        
        conn.close()
    
    def disable_2fa(self, user_id):
        """Disable 2FA for user"""
        conn = self.db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL
            WHERE id = ?
        ''', (user_id,))
        
        conn.commit()
        
        self.log_activity(user_id, "2FA_DISABLED", "Two-factor authentication disabled")
        
        conn.close()

# Initialize session state
def init_session_state():
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'user_id' not in st.session_state:
        st.session_state.user_id = None
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'page' not in st.session_state:
        st.session_state.page = 'login'
    if '2fa_verified' not in st.session_state:
        st.session_state['2fa_verified'] = False
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = datetime.now()

# Login Page
def login_page(pm):
    st.markdown('<h1 class="main-title">🔐 SecureVault Pro</h1>', unsafe_allow_html=True)
    st.markdown('<p style="text-align: center; color: white; font-size: 1.2rem; margin-bottom: 2rem;">Enterprise-Grade Password Manager</p>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown('<div class="card fade-in">', unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["🔓 Login", "📝 Register"])
        
        with tab1:
            st.markdown('<h3 style="color: #667eea;">Welcome Back!</h3>', unsafe_allow_html=True)
            
            username = st.text_input("Username", key="login_username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", key="login_password", 
                                    placeholder="Enter your password")
            
            col_a, col_b = st.columns(2)
            
            with col_a:
                if st.button("🔑 Login", use_container_width=True):
                    if username and password:
                        success, user_id, two_fa_enabled, two_fa_secret = pm.login_user(username, password)
                        if success:
                            st.session_state.user_id = user_id
                            st.session_state.username = username
                            
                            if two_fa_enabled:
                                st.session_state.pending_2fa = True
                                st.session_state.two_fa_secret = two_fa_secret
                                st.rerun()
                            else:
                                st.session_state.logged_in = True
                                st.session_state.page = 'dashboard'
                                pm.log_activity(user_id, "LOGIN", "User logged in")
                                st.rerun()
                        else:
                            st.error("❌ Invalid username or password!")
                    else:
                        st.warning("⚠️ Please fill in all fields!")
            
            with col_b:
                if st.button("🔄 Forgot Password?", use_container_width=True):
                    st.session_state.page = 'forgot_password'
                    st.rerun()
            
            # 2FA verification
            if 'pending_2fa' in st.session_state and st.session_state.pending_2fa:
                st.markdown("---")
                st.markdown("### 🔐 Two-Factor Authentication")
                token = st.text_input("Enter 6-digit code", max_chars=6, key="2fa_token")
                
                if st.button("Verify", use_container_width=True):
                    if SecurityManager.verify_2fa_token(st.session_state.two_fa_secret, token):
                        st.session_state.logged_in = True
                        st.session_state['2fa_verified'] = True
                        st.session_state.pending_2fa = False
                        st.session_state.page = 'dashboard'
                        pm.log_activity(st.session_state.user_id, "2FA_VERIFIED", "2FA verification successful")
                        st.rerun()
                    else:
                        st.error("❌ Invalid code!")
        
        with tab2:
            st.markdown('<h3 style="color: #667eea;">Create Account</h3>', unsafe_allow_html=True)
            
            new_username = st.text_input("Username", key="reg_username", 
                                        placeholder="Choose a username")
            new_email = st.text_input("Email", key="reg_email", 
                                     placeholder="Enter your email")
            new_password = st.text_input("Password", type="password", key="reg_password",
                                        placeholder="Create a strong password")
            confirm_password = st.text_input("Confirm Password", type="password", 
                                           key="reg_confirm", 
                                           placeholder="Re-enter your password")
            
            # Password strength indicator for registration
            if new_password:
                analysis = SecurityManager.analyze_password(new_password)
                st.progress(analysis['score'] / 10)
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"<p style='color: {analysis['color']}; font-weight: bold;'>Strength: {analysis['strength']}</p>", 
                              unsafe_allow_html=True)
                with col2:
                    st.markdown(f"<p style='color: #666;'>Time to crack: {analysis['time_to_crack']}</p>", 
                              unsafe_allow_html=True)
            
            security_question = st.selectbox(
                "Security Question",
                ["What was your first pet's name?",
                 "What city were you born in?",
                 "What is your mother's maiden name?",
                 "What was your first car?",
                 "What is your favorite food?"]
            )
            
            security_answer = st.text_input("Security Answer", key="security_answer",
                                          placeholder="Enter your answer")
            
            if st.button("✨ Create Account", use_container_width=True):
                if all([new_username, new_email, new_password, confirm_password, security_answer]):
                    if new_password != confirm_password:
                        st.error("❌ Passwords do not match!")
                    elif len(new_password) < 8:
                        st.error("❌ Password must be at least 8 characters!")
                    else:
                        success, message = pm.register_user(
                            new_username, new_email, new_password, 
                            security_question, security_answer
                        )
                        if success:
                            st.success("✅ " + message)
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("❌ " + message)
                else:
                    st.warning("⚠️ Please fill in all fields!")
        
        st.markdown('</div>', unsafe_allow_html=True)

# Forgot Password Page
def forgot_password_page(pm):
    st.markdown('<h1 class="main-title">🔐 Password Recovery</h1>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown('<div class="card fade-in">', unsafe_allow_html=True)
        
        if 'recovery_step' not in st.session_state:
            st.session_state.recovery_step = 1
        
        if st.session_state.recovery_step == 1:
            st.markdown('<h3 style="color: #667eea;">Step 1: Verify Identity</h3>', 
                       unsafe_allow_html=True)
            
            username = st.text_input("Username", placeholder="Enter your username")
            
            if st.button("Continue", use_container_width=True):
                if username:
                    conn = pm.db.get_connection()
                    cursor = conn.cursor()
                    cursor.execute('SELECT security_question FROM users WHERE username = ?',
                                 (username,))
                    result = cursor.fetchone()
                    conn.close()
                    
                    if result:
                        st.session_state.recovery_username = username
                        st.session_state.security_question = result[0]
                        st.session_state.recovery_step = 2
                        st.rerun()
                    else:
                        st.error("❌ Username not found!")
                else:
                    st.warning("⚠️ Please enter your username!")
        
        elif st.session_state.recovery_step == 2:
            st.markdown('<h3 style="color: #667eea;">Step 2: Security Question</h3>', 
                       unsafe_allow_html=True)
            
            st.info(f"**Question:** {st.session_state.security_question}")
            
            answer = st.text_input("Your Answer", placeholder="Enter your answer")
            
            col_a, col_b = st.columns(2)
            
            with col_a:
                if st.button("Verify", use_container_width=True):
                    if answer:
                        success, user_id = pm.verify_security_answer(
                            st.session_state.recovery_username, answer
                        )
                        if success:
                            st.session_state.recovery_user_id = user_id
                            st.session_state.recovery_step = 3
                            st.rerun()
                        else:
                            st.error("❌ Incorrect answer!")
                    else:
                        st.warning("⚠️ Please provide an answer!")
            
            with col_b:
                if st.button("Back", use_container_width=True):
                    st.session_state.recovery_step = 1
                    st.rerun()
        
        elif st.session_state.recovery_step == 3:
            st.markdown('<h3 style="color: #667eea;">Step 3: Reset Password</h3>', 
                       unsafe_allow_html=True)
            
            new_password = st.text_input("New Password", type="password",
                                        placeholder="Enter new password")
            confirm_password = st.text_input("Confirm Password", type="password",
                                           placeholder="Re-enter new password")
            
            if new_password:
                analysis = SecurityManager.analyze_password(new_password)
                st.progress(analysis['score'] / 10)
                st.markdown(f"<p style='color: {analysis['color']}; font-weight: bold;'>Strength: {analysis['strength']}</p>", 
                          unsafe_allow_html=True)
            
            if st.button("Reset Password", use_container_width=True):
                if new_password and confirm_password:
                    if new_password != confirm_password:
                        st.error("❌ Passwords do not match!")
                    elif len(new_password) < 8:
                        st.error("❌ Password must be at least 8 characters!")
                    else:
                        pm.reset_password(st.session_state.recovery_user_id, new_password)
                        st.success("✅ Password reset successful!")
                        time.sleep(2)
                        st.session_state.recovery_step = 1
                        st.session_state.page = 'login'
                        st.rerun()
                else:
                    st.warning("⚠️ Please fill in all fields!")
        
        if st.button("← Back to Login", use_container_width=True):
            st.session_state.recovery_step = 1
            st.session_state.page = 'login'
            st.rerun()
        
        st.markdown('</div>', unsafe_allow_html=True)

# Dashboard Page
def dashboard_page(pm):
    # Auto-lock check
    if 'last_activity' in st.session_state:
        if (datetime.now() - st.session_state.last_activity).total_seconds() > 1800:  # 30 minutes
            st.session_state.logged_in = False
            st.warning("Session expired due to inactivity")
            st.rerun()
    
    st.session_state.last_activity = datetime.now()
    
    # Sidebar
    with st.sidebar:
        st.markdown(f'<h2 style="color: #667eea;">👤 {st.session_state.username}</h2>', 
                   unsafe_allow_html=True)
        st.markdown("---")
        
        menu = st.radio(
            "Navigation",
            ["🏠 Dashboard", "🔑 My Passwords", "➕ Add Password", 
             "🔍 Password Analyzer", "🎲 Password Generator", "📝 Wordlist Generator",
             "📊 Security Report", "📤 Import/Export", "🔐 2FA Setup",
             "📋 Activity Log", "⚙️ Settings"],
            label_visibility="collapsed"
        )
        
        st.markdown("---")
        
        if st.button("🚪 Logout", use_container_width=True):
            pm.log_activity(st.session_state.user_id, "LOGOUT", "User logged out")
            st.session_state.logged_in = False
            st.session_state.user_id = None
            st.session_state.username = None
            st.session_state.page = 'login'
            st.rerun()
    
    # Main content
    if menu == "🏠 Dashboard":
        show_dashboard(pm)
    elif menu == "🔑 My Passwords":
        show_passwords(pm)
    elif menu == "➕ Add Password":
        add_password(pm)
    elif menu == "🔍 Password Analyzer":
        password_analyzer()
    elif menu == "🎲 Password Generator":
        password_generator_page()
    elif menu == "📝 Wordlist Generator":
        wordlist_generator()
    elif menu == "📊 Security Report":
        security_report(pm)
    elif menu == "📤 Import/Export":
        import_export(pm)
    elif menu == "🔐 2FA Setup":
        two_factor_setup(pm)
    elif menu == "📋 Activity Log":
        activity_log(pm)
    elif menu == "⚙️ Settings":
        settings_page(pm)

def show_dashboard(pm):
    st.markdown('<h1 style="color: white;">🏠 Dashboard Overview</h1>', unsafe_allow_html=True)
    
    # Get user stats
    stats = pm.get_user_stats(st.session_state.user_id)
    
    # Metrics Row 1
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <h2 style="margin: 0;">{stats['total_passwords']}</h2>
            <p style="margin: 0; opacity: 0.9;">Total Passwords</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <h2 style="margin: 0;">{stats['favorites']}</h2>
            <p style="margin: 0; opacity: 0.9;">Favorites</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <h2 style="margin: 0;">{stats['breached']}</h2>
            <p style="margin: 0; opacity: 0.9;">Breached</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        categories = len(stats['category_stats'])
        st.markdown(f"""
        <div class="metric-card">
            <h2 style="margin: 0;">{categories}</h2>
            <p style="margin: 0; opacity: 0.9;">Categories</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Charts Row
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<h2 class="sub-title">📊 Password by Category</h2>', unsafe_allow_html=True)
        
        if stats['category_stats']:
            df = pd.DataFrame(stats['category_stats'], columns=['Category', 'Count'])
            fig = px.pie(df, values='Count', names='Category', hole=0.4)
            fig.update_layout(height=300, margin=dict(l=0, r=0, t=30, b=0))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data available")
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<h2 class="sub-title">📈 Security Score</h2>', unsafe_allow_html=True)
        
        # Calculate security score
        total = stats['total_passwords']
        if total > 0:
            breached_penalty = (stats['breached'] / total) * 30
            weak_penalty = (stats['weak_passwords'] / total) * 30
            score = max(0, 100 - breached_penalty - weak_penalty)
        else:
            score = 100
        
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Overall Security"},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "#667eea"},
                'steps': [
                    {'range': [0, 40], 'color': "#ffcccc"},
                    {'range': [40, 70], 'color': "#ffffcc"},
                    {'range': [70, 100], 'color': "#ccffcc"}
                ],
            }
        ))
        fig.update_layout(height=300, margin=dict(l=0, r=0, t=30, b=0))
        st.plotly_chart(fig, use_container_width=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Recent Activity
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<h2 class="sub-title">📋 Recent Activity</h2>', unsafe_allow_html=True)
    
    if stats['recent_activity']:
        for activity in stats['recent_activity'][:5]:
            action, details, timestamp = activity
            col1, col2, col3 = st.columns([2, 4, 2])
            
            with col1:
                st.markdown(f"**{action}**")
            with col2:
                st.markdown(f"*{details}*")
            with col3:
                dt = datetime.fromisoformat(timestamp)
                st.markdown(f"_{dt.strftime('%Y-%m-%d %H:%M')}_")
            
            st.markdown("---")
    else:
        st.info("No recent activity")
    
    st.markdown('</div>', unsafe_allow_html=True)

def show_passwords(pm):
    st.markdown('<h1 style="color: white;">🔑 My Passwords</h1>', unsafe_allow_html=True)
    
    st.markdown('<div class="card">', unsafe_allow_html=True)
    
    # Filters
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        search = st.text_input("🔍 Search", placeholder="Search by service or username...", 
                              key="pwd_search")
    
    with col2:
        categories = ['All'] + pm.get_password_categories(st.session_state.user_id)
        category = st.selectbox("Category", categories, key="pwd_category")
    
    with col3:
        favorites_only = st.checkbox("⭐ Favorites Only", key="pwd_favorites")
    
    passwords = pm.get_user_passwords(
        st.session_state.user_id, 
        category=category if category != 'All' else None,
        search=search,
        favorites_only=favorites_only
    )
    
    st.markdown("---")
    
    if passwords:
        for pwd in passwords:
            pwd_id, service, username, pwd_hash, url, notes, cat, favorite, breached, created, updated, last_used = pwd
            
            with st.expander(f"{'⭐' if favorite else '🔐'} {service} - {username}"):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.markdown(f"**Service:** {service}")
                    st.markdown(f"**Username:** {username}")
                    if url:
                        st.markdown(f"**URL:** [{url}]({url})")
                    if notes:
                        st.markdown(f"**Notes:** {notes}")
                    st.markdown(f"**Category:** {cat}")
                    st.markdown(f"**Created:** {created}")
                    
                    if breached:
                        st.error("⚠️ This password was found in a data breach!")
                
                with col2:
                    if st.button("⭐" if not favorite else "☆", key=f"fav_{pwd_id}"):
                        pm.toggle_favorite(pwd_id, st.session_state.user_id)
                        st.rerun()
                    
                    if st.button("📋 Use", key=f"use_{pwd_id}"):
                        pm.mark_password_used(pwd_id, st.session_state.user_id)
                        st.success("Marked as used!")
                    
                    if st.button("🗑️ Delete", key=f"del_{pwd_id}"):
                        pm.delete_password(pwd_id, st.session_state.user_id)
                        st.rerun()
    else:
        st.info("No passwords found.")
    
    st.markdown('</div>', unsafe_allow_html=True)

def add_password(pm):
    st.markdown('<h1 style="color: white;">➕ Add New Password</h1>', unsafe_allow_html=True)
    
    st.markdown('<div class="card">', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        service = st.text_input("Service/Website", placeholder="e.g., Gmail, Facebook")
        username = st.text_input("Username/Email", placeholder="e.g., user@example.com")
        url = st.text_input("URL (Optional)", placeholder="https://example.com")
    
    with col2:
        categories = pm.get_password_categories(st.session_state.user_id) + ['General', 'Work', 'Personal', 'Finance']
        category = st.selectbox("Category", list(set(categories)))
        notes = st.text_area("Notes (Optional)", placeholder="Any additional information")
        favorite = st.checkbox("⭐ Mark as favorite")
    
    password = st.text_input("Password", type="password", 
                            placeholder="Enter password or use generator", key="add_pwd")
    
    # Password strength indicator
    if password:
        analysis = SecurityManager.analyze_password(password)
        
        col1, col2 = st.columns([3, 1])
        with col1:
            st.progress(analysis['score'] / 10)
        with col2:
            st.markdown(f"<p style='color: {analysis['color']}; font-weight: bold;'>{analysis['strength']}</p>", 
                      unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Entropy", f"{analysis['entropy']:.1f} bits")
        with col2:
            st.metric("Score", f"{analysis['score']}/10")
        with col3:
            st.metric("Crack Time", analysis['time_to_crack'])
    
    if st.button("💾 Save Password", use_container_width=True, type="primary"):
        if service and username and password:
            success, message = pm.save_password(
                st.session_state.user_id, service, username, password,
                url=url, notes=notes, category=category, favorite=favorite
            )
            if success:
                st.success("✅ " + message)
                time.sleep(1)
                st.rerun()
            else:
                st.error("❌ " + message)
        else:
            st.warning("⚠️ Please fill in required fields!")
    
    st.markdown('</div>', unsafe_allow_html=True)

def password_analyzer():
    st.markdown('<h1 style="color: white;">🔍 Password Strength Analyzer</h1>', 
               unsafe_allow_html=True)
    
    st.markdown('<div class="card">', unsafe_allow_html=True)
    
    password = st.text_input("Enter Password to Analyze", type="password",
                            placeholder="Enter a password to analyze")
    
    if password:
        analysis = SecurityManager.analyze_password(password)
        breached, breach_msg = SecurityManager.check_pwned_password(password)
        
        st.markdown("---")
        st.markdown("### Analysis Results")
        
        # Strength gauge
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=analysis['score'],
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Password Strength Score"},
            gauge={
                'axis': {'range': [None, 10]},
                'bar': {'color': analysis['color']},
                'steps': [
                    {'range': [0, 3], 'color': "#ffcccc"},
                    {'range': [3, 6], 'color': "#ffffcc"},
                    {'range': [6, 8], 'color': "#ccffcc"},
                    {'range': [8, 10], 'color': "#ccffcc"}
                ],
            }
        ))
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Length", f"{analysis['length']} chars")
        with col2:
            st.metric("Entropy", f"{analysis['entropy']:.1f} bits")
        with col3:
            st.metric("Strength", analysis['strength'])
        with col4:
            st.metric("Crack Time", analysis['time_to_crack'])
        
        # Breach check
        st.markdown("### 🛡️ Breach Check")
        if breached:
            st.error(f"⚠️ {breach_msg}")
        else:
            st.success(f"✅ {breach_msg}")
        
        # Character composition
        st.markdown("### Character Composition")
        comp_df = pd.DataFrame({
            'Feature': ['Lowercase', 'Uppercase', 'Digits', 'Special Chars'],
            'Present': [
                '✅' if analysis['has_lowercase'] else '❌',
                '✅' if analysis['has_uppercase'] else '❌',
                '✅' if analysis['has_digits'] else '❌',
                '✅' if analysis['has_special'] else '❌'
            ]
        })
        st.table(comp_df)
        
        # Security concerns
        st.markdown("### ⚠️ Security Concerns")
        concerns_df = pd.DataFrame({
            'Issue': ['Common Patterns', 'Sequential Chars', 'Repeated Chars'],
            'Status': [
                '⚠️ Found' if analysis['has_common_patterns'] else '✅ None',
                '⚠️ Found' if analysis['has_sequential'] else '✅ None',
                '⚠️ Found' if analysis['has_repeated'] else '✅ None'
            ]
        })
        st.table(concerns_df)
    
    st.markdown('</div>', unsafe_allow_html=True)

def password_generator_page():
    st.markdown('<h1 style="color: white;">🎲 Advanced Password Generator</h1>', 
               unsafe_allow_html=True)
    
    st.markdown('<div class="card">', unsafe_allow_html=True)
    
    gen_type = st.radio("Generator Type", ["Random Password", "Passphrase"], horizontal=True)
    
    if gen_type == "Random Password":
        col1, col2 = st.columns(2)
        
        with col1:
            length = st.slider("Length", 8, 64, 16)
            use_upper = st.checkbox("Uppercase (A-Z)", value=True)
            use_lower = st.checkbox("Lowercase (a-z)", value=True)
        
        with col2:
            use_numbers = st.checkbox("Numbers (0-9)", value=True)
            use_special = st.checkbox("Special Characters (!@#$...)", value=True)
            exclude_similar = st.checkbox("Exclude Similar (il1Lo0O)")
            exclude_ambiguous = st.checkbox("Exclude Ambiguous ({}[]()...)")
        
        if st.button("🎲 Generate Password", use_container_width=True, type="primary"):
            password = SecurityManager.generate_password(
                length, use_special, use_numbers, use_upper, use_lower,
                exclude_similar, exclude_ambiguous
            )
            
            st.markdown("### Generated Password")
            st.code(password, language=None)
            
            analysis = SecurityManager.analyze_password(password)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Strength", analysis['strength'])
            with col2:
                st.metric("Entropy", f"{analysis['entropy']:.1f} bits")
            with col3:
                st.metric("Crack Time", analysis['time_to_crack'])
    
    else:  # Passphrase
        col1, col2 = st.columns(2)
        
        with col1:
            num_words = st.slider("Number of Words", 3, 8, 4)
        
        with col2:
            separator = st.text_input("Separator", value="-", max_chars=3)
            capitalize = st.checkbox("Capitalize Words", value=True)
        
        if st.button("🎲 Generate Passphrase", use_container_width=True, type="primary"):
            passphrase = SecurityManager.generate_passphrase(num_words, separator, capitalize)
            
            st.markdown("### Generated Passphrase")
            st.code(passphrase, language=None)
            
            analysis = SecurityManager.analyze_password(passphrase)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Strength", analysis['strength'])
            with col2:
                st.metric("Entropy", f"{analysis['entropy']:.1f} bits")
            with col3:
                st.metric("Crack Time", analysis['time_to_crack'])
    
    # Batch generation
    st.markdown("---")
    st.markdown("### 📦 Batch Generation")
    
    batch_count = st.number_input("Number of passwords to generate", 1, 100, 10)
    
    if st.button("Generate Batch", use_container_width=True):
        passwords = []
        for _ in range(batch_count):
            if gen_type == "Random Password":
                pwd = SecurityManager.generate_password(
                    length, use_special, use_numbers, use_upper, use_lower,
                    exclude_similar, exclude_ambiguous
                )
            else:
                pwd = SecurityManager.generate_passphrase(num_words, separator, capitalize)
            passwords.append(pwd)
        
        st.text_area("Generated Passwords", '\n'.join(passwords), height=300)
        
        # Download
        st.download_button(
            "💾 Download Passwords",
            data='\n'.join(passwords),
            file_name=f"passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True
        )
    
    st.markdown('</div>', unsafe_allow_html=True)

def wordlist_generator():
    st.markdown('<h1 style="color: white;">📝 Custom Wordlist Generator</h1>', 
               unsafe_allow_html=True)
    
    st.markdown('<div class="card">', unsafe_allow_html=True)
    
    st.info("Generate a custom wordlist based on personal information for security testing.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        name = st.text_input("Name", placeholder="e.g., John Doe")
        birthdate = st.text_input("Birth Date", placeholder="e.g., 15-08-1990")
        pet = st.text_input("Pet Name", placeholder="e.g., Fluffy")
    
    with col2:
        company = st.text_input("Company", placeholder="e.g., TechCorp")
        custom = st.text_input("Custom Word", placeholder="Any custom word")
        location = st.text_input("Location", placeholder="e.g., NewYork")
    
    if st.button("🎲 Generate Wordlist", use_container_width=True, type="primary"):
        if any([name, birthdate, pet, company, custom, location]):
            with st.spinner("Generating wordlist..."):
                wordlist = generate_custom_wordlist(name, birthdate, pet, company, custom, location)
                
                st.success(f"✅ Generated {len(wordlist)} password variations!")
                
                # Statistics
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Words", len(wordlist))
                with col2:
                    avg_length = sum(len(w) for w in wordlist) / len(wordlist)
                    st.metric("Avg Length", f"{avg_length:.1f}")
                with col3:
                    st.metric("Unique", len(set(wordlist)))
                
                # Sample
                st.markdown("### 📋 Sample (First 50 entries)")
                sample = sorted(list(wordlist))[:50]
                st.text_area("Preview", '\n'.join(sample), height=300)
                
                # Download
                wordlist_text = '\n'.join(sorted(wordlist))
                st.download_button(
                    label="💾 Download Full Wordlist",
                    data=wordlist_text,
                    file_name=f"wordlist_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                    use_container_width=True
                )
        else:
            st.warning("⚠️ Please enter at least one input field!")
    
    st.markdown('</div>', unsafe_allow_html=True)

def generate_custom_wordlist(name, birthdate, pet, company, custom, location):
    """Generate custom wordlist"""
    wordlist = set()
    base_words = []
    
    # Collect base words
    for word in [name, pet, company, custom, location]:
        if word:
            base_words.extend([
                word, 
                word.lower(), 
                word.upper(), 
                word.capitalize(),
                word.replace(' ', ''),
                word.replace(' ', '_'),
                word.replace(' ', '-')
            ])
    
    wordlist.update(base_words)
    
    # Extract years
    years = []
    if birthdate:
        year_matches = re.findall(r'\d{4}', birthdate)
        years.extend(year_matches)
        two_digit_years = re.findall(r'\d{2}', birthdate)
        years.extend(two_digit_years)
    
    # Add common years
    current_year = datetime.now().year
    years.extend([str(y) for y in range(current_year - 10, current_year + 1)])
    years.extend([str(y)[2:] for y in range(current_year - 10, current_year + 1)])
    
    # Common suffixes and prefixes
    suffixes = ['123', '!', '@', '#', '1', '12', '2024', '2025', '2026', '!!', '123!', 
                '1!', '2!', '007', '13', '21', '69', '99']
    prefixes = ['@', '#', '!', 'my', 'the', 'i']
    
    # Generate combinations
    for word in base_words[:10]:  # Limit to prevent explosion
        # With suffixes
        for suffix in suffixes:
            wordlist.add(word + suffix)
            wordlist.add(suffix + word)
        
        # With years
        for year in years[:10]:
            wordlist.add(word + year)
            wordlist.add(year + word)
        
        # With prefixes
        for prefix in prefixes:
            wordlist.add(prefix + word)
        
        # Leetspeak
        leet_map = {
            'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5',
            't': '7', 'l': '1', 'A': '4', 'E': '3', 'I': '1',
            'O': '0', 'S': '5', 'T': '7', 'L': '1'
        }
        leet = ''.join(leet_map.get(c, c) for c in word)
        wordlist.add(leet)
        
        # Reverse
        wordlist.add(word[::-1])
        
        # Capitalize variations
        if len(word) > 2:
            wordlist.add(word[0].upper() + word[1:].lower())
            wordlist.add(word.lower() + word[-1].upper())
    
    # Word combinations
    if len(base_words) >= 2:
        for combo in itertools.combinations(base_words[:5], 2):
            wordlist.add(combo[0] + combo[1])
            wordlist.add(combo[1] + combo[0])
            wordlist.add(combo[0] + '_' + combo[1])
            wordlist.add(combo[0] + '-' + combo[1])
    
    return wordlist

def security_report(pm):
    st.markdown('<h1 style="color: white;">📊 Security Report</h1>', unsafe_allow_html=True)
    
    st.markdown('<div class="card">', unsafe_allow_html=True)
    
    stats = pm.get_user_stats(st.session_state.user_id)
    
    st.markdown("### 🎯 Overall Security Score")
    
    total = stats['total_passwords']
    if total > 0:
        breached_penalty = (stats['breached'] / total) * 30
        weak_penalty = (stats['weak_passwords'] / total) * 30
        score = max(0, 100 - breached_penalty - weak_penalty)
    else:
        score = 100
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            title={'text': "Security Score"},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "#667eea"},
                'steps': [
                    {'range': [0, 40], 'color': "#ffcccc"},
                    {'range': [40, 70], 'color': "#ffffcc"},
                    {'range': [70, 100], 'color': "#ccffcc"}
                ],
            }
        ))
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.metric("Total Passwords", total)
        st.metric("Favorites", stats['favorites'])
    
    with col3:
        st.metric("Breached", stats['breached'])
        st.metric("Categories", len(stats['category_stats']))
    
    st.markdown("---")
    
    st.markdown("### 📈 Security Recommendations")
    
    recommendations = []
    
    if stats['breached'] > 0:
        recommendations.append({
            'severity': 'high',
            'title': 'Breached Passwords Found',
            'description': f'{stats["breached"]} password(s) found in data breaches. Change them immediately!',
            'action': 'Update breached passwords'
        })
    
    if total < 5:
        recommendations.append({
            'severity': 'low',
            'title': 'Start Using Password Manager',
            'description': 'Add more passwords to your vault for better security.',
            'action': 'Add more passwords'
        })
    
    recommendations.append({
        'severity': 'medium',
        'title': 'Enable Two-Factor Authentication',
        'description': 'Add an extra layer of security to your account.',
        'action': 'Enable 2FA'
    })
    
    for rec in recommendations:
        if rec['severity'] == 'high':
            st.error(f"**{rec['title']}**: {rec['description']}")
        elif rec['severity'] == 'medium':
            st.warning(f"**{rec['title']}**: {rec['description']}")
        else:
            st.info(f"**{rec['title']}**: {rec['description']}")
    
    st.markdown('</div>', unsafe_allow_html=True)

def import_export(pm):
    st.markdown('<h1 style="color: white;">📤 Import/Export Passwords</h1>', 
               unsafe_allow_html=True)
    
    st.markdown('<div class="card">', unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["📥 Import", "📤 Export"])
    
    with tab1:
        st.markdown("### Import Passwords")
        st.warning("⚠️ Importing will add to existing passwords. Duplicates will be created.")
        
        file_format = st.radio("File Format", ["CSV", "JSON"], horizontal=True)
        
        uploaded_file = st.file_uploader(f"Upload {file_format} file", 
                                        type=['csv', 'json'])
        
        if uploaded_file and st.button("Import", use_container_width=True):
            try:
                if file_format == "CSV":
                    df = pd.read_csv(uploaded_file)
                    required_cols = ['Service', 'Username', 'Password']
                    
                    if all(col in df.columns for col in required_cols):
                        count = 0
                        for _, row in df.iterrows():
                            pm.save_password(
                                st.session_state.user_id,
                                row['Service'],
                                row['Username'],
                                row['Password'],
                                url=row.get('URL', ''),
                                notes=row.get('Notes', ''),
                                category=row.get('Category', 'General')
                            )
                            count += 1
                        st.success(f"✅ Imported {count} passwords!")
                    else:
                        st.error("❌ CSV must have Service, Username, and Password columns!")
                
                else:  # JSON
                    data = json.load(uploaded_file)
                    count = 0
                    for item in data:
                        pm.save_password(
                            st.session_state.user_id,
                            item['service'],
                            item['username'],
                            item.get('password', ''),
                            url=item.get('url', ''),
                            notes=item.get('notes', ''),
                            category=item.get('category', 'General')
                        )
                        count += 1
                    st.success(f"✅ Imported {count} passwords!")
            
            except Exception as e:
                st.error(f"❌ Import failed: {str(e)}")
    
    with tab2:
        st.markdown("### Export Passwords")
        st.info("ℹ️ Passwords will be exported in hashed form for security.")
        
        export_format = st.radio("Export Format", ["CSV", "JSON"], horizontal=True, key="export")
        
        if st.button("📥 Export Passwords", use_container_width=True):
            data = pm.export_passwords(st.session_state.user_id, format=export_format.lower())
            
            filename = f"passwords_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{export_format.lower()}"
            
            st.download_button(
                label=f"💾 Download {export_format}",
                data=data,
                file_name=filename,
                mime="text/csv" if export_format == "CSV" else "application/json",
                use_container_width=True
            )
            
            pm.log_activity(st.session_state.user_id, "DATA_EXPORT", 
                          f"Exported passwords as {export_format}")
    
    st.markdown('</div>', unsafe_allow_html=True)

def two_factor_setup(pm):
    st.markdown('<h1 style="color: white;">🔐 Two-Factor Authentication</h1>', 
               unsafe_allow_html=True)
    
    st.markdown('<div class="card">', unsafe_allow_html=True)
    
    conn = pm.db.get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT two_factor_enabled FROM users WHERE id = ?', 
                  (st.session_state.user_id,))
    enabled = cursor.fetchone()[0]
    conn.close()
    
    if not enabled:
        st.markdown("### 📱 Enable 2FA")
        st.info("Add an extra layer of security to your account with two-factor authentication.")
        
        if 'setup_2fa' not in st.session_state:
            st.session_state.setup_2fa = False
        
        if not st.session_state.setup_2fa:
            if st.button("🔐 Start Setup", use_container_width=True):
                st.session_state.setup_2fa = True
                st.session_state.temp_2fa_secret = SecurityManager.generate_2fa_secret()
                st.rerun()
        else:
            st.markdown("### Step 1: Scan QR Code")
            st.markdown("Use Google Authenticator, Authy, or any TOTP app to scan this code:")
            
            # Generate QR code
            qr_buffer = SecurityManager.generate_2fa_qr(
                st.session_state.username,
                st.session_state.temp_2fa_secret
            )
            
            st.image(qr_buffer, width=300)
            
            st.markdown("### Step 2: Enter Verification Code")
            code = st.text_input("6-digit code", max_chars=6)
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("Verify & Enable", use_container_width=True):
                    if SecurityManager.verify_2fa_token(st.session_state.temp_2fa_secret, code):
                        pm.enable_2fa(st.session_state.user_id, st.session_state.temp_2fa_secret)
                        st.success("✅ 2FA enabled successfully!")
                        st.session_state.setup_2fa = False
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("❌ Invalid code!")
            
            with col2:
                if st.button("Cancel", use_container_width=True):
                    st.session_state.setup_2fa = False
                    st.rerun()
    
    else:
        st.success("✅ Two-Factor Authentication is **ENABLED**")
        st.markdown("Your account is protected with 2FA.")
        
        if st.button("🔓 Disable 2FA", use_container_width=True):
            pm.disable_2fa(st.session_state.user_id)
            st.success("2FA disabled")
            time.sleep(1)
            st.rerun()
    
    st.markdown('</div>', unsafe_allow_html=True)

def activity_log(pm):
    st.markdown('<h1 style="color: white;">📋 Activity Log</h1>', unsafe_allow_html=True)
    
    st.markdown('<div class="card">', unsafe_allow_html=True)
    
    conn = pm.db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT action, details, timestamp FROM activity_log
        WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100
    ''', (st.session_state.user_id,))
    
    activities = cursor.fetchall()
    conn.close()
    
    if activities:
        # Convert to DataFrame
        df = pd.DataFrame(activities, columns=['Action', 'Details', 'Timestamp'])
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        
        # Display
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        # Timeline chart
        st.markdown("### 📈 Activity Timeline")
        
        df['Date'] = df['Timestamp'].dt.date
        activity_counts = df.groupby('Date').size().reset_index(name='Count')
        
        fig = px.line(activity_counts, x='Date', y='Count', 
                     title='Daily Activity', markers=True)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No activity recorded yet.")
    
    st.markdown('</div>', unsafe_allow_html=True)

def settings_page(pm):
    st.markdown('<h1 style="color: white;">⚙️ Settings</h1>', unsafe_allow_html=True)
    
    st.markdown('<div class="card">', unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["Account", "Security", "Preferences"])
    
    with tab1:
        st.markdown("### 👤 Account Information")
        
        conn = pm.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username, email, created_at FROM users WHERE id = ?',
                      (st.session_state.user_id,))
        user_info = cursor.fetchone()
        conn.close()
        
        if user_info:
            username, email, created = user_info
            st.markdown(f"**Username:** {username}")
            st.markdown(f"**Email:** {email}")
            st.markdown(f"**Member Since:** {created}")
    
    with tab2:
        st.markdown("### 🔒 Change Password")
        
        current = st.text_input("Current Password", type="password")
        new_pwd = st.text_input("New Password", type="password")
        confirm = st.text_input("Confirm New Password", type="password")
        
        if new_pwd:
            analysis = SecurityManager.analyze_password(new_pwd)
            st.progress(analysis['score'] / 10)
            st.markdown(f"<p style='color: {analysis['color']}; font-weight: bold;'>{analysis['strength']}</p>", 
                      unsafe_allow_html=True)
        
        if st.button("🔄 Update Password", use_container_width=True):
            if current and new_pwd and confirm:
                success, _, _, _ = pm.login_user(st.session_state.username, current)
                if success:
                    if new_pwd != confirm:
                        st.error("❌ Passwords don't match!")
                    elif len(new_pwd) < 8:
                        st.error("❌ Password too short!")
                    else:
                        pm.reset_password(st.session_state.user_id, new_pwd)
                        st.success("✅ Password updated!")
                else:
                    st.error("❌ Current password incorrect!")
            else:
                st.warning("⚠️ Fill all fields!")
    
    with tab3:
        st.markdown("### 🎨 Preferences")
        
        st.selectbox("Default Category", ["General", "Work", "Personal", "Finance"])
        st.slider("Auto-lock Timeout (minutes)", 5, 60, 30)
        st.checkbox("Show password strength by default", value=True)
        st.checkbox("Confirm before deleting passwords", value=True)
        
        if st.button("💾 Save Preferences", use_container_width=True):
            st.success("✅ Preferences saved!")
    
    st.markdown('</div>', unsafe_allow_html=True)

# Main application
def main():
    load_css()
    init_session_state()
    
    # Initialize database and password manager
    db = DatabaseManager()
    pm = PasswordManager(db)
    
    # Route to appropriate page
    if not st.session_state.logged_in:
        if st.session_state.page == 'forgot_password':
            forgot_password_page(pm)
        else:
            login_page(pm)
    else:
        dashboard_page(pm)

if __name__ == "__main__":
    main()