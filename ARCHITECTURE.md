# LureNet Architecture & Flow

## Application Flow

```
User Browser
    ↓
http://localhost:5000
    ↓
app.py (main entry point)
    ↓
lurenet.web.app.create_app(engine)
    ↓
Flask Application Instance
    ↓
Routes → Templates → Browser
```

## Detailed Architecture

### 1. Main Entry Point: `app.py`

```python
from lurenet.web.app import create_app

# Creates engine
engine = HoneypotEngine(config)

# Creates Flask app
app, socketio = create_app(engine)

# Runs Flask with SocketIO
socketio.run(app, host='0.0.0.0', port=5000)
```

### 2. Flask App Creation: `lurenet/web/app.py`

```python
def create_app(engine):
    app = Flask(__name__)
    
    # Configure routes
    @app.route('/')
    def dashboard():
        return render_template('dashboard.html', username=session.get('username'))
    
    @app.route('/intelligence')
    def intelligence():
        return render_template('intelligence.html', username=session.get('username'))
    
    # ... more routes
    
    return app, socketio
```

### 3. Template Rendering: `lurenet/web/templates/`

Templates extend from `base.html`:

```
base.html (master template)
    ├── login.html
    ├── dashboard.html
    ├── threats.html
    ├── services.html
    ├── analytics.html
    ├── intelligence.html (NEW)
    ├── yara_scan.html (NEW)
    └── ip_lookup.html (NEW)
```

### 4. Static Files: `lurenet/web/static/`

```
static/
    └── css/
        └── main.css (34KB of modern CSS)
```

## Request Flow Example

### 1. User visits `/intelligence`

```
1. Browser → GET /intelligence
2. app.py receives request
3. Flask routes to intelligence() function
4. Checks @login_required decorator
5. If authenticated:
   - render_template('intelligence.html', username='admin')
   - Template extends base.html
   - Inserts navigation sidebar
   - Renders form and JavaScript
6. Returns HTML to browser
```

### 2. User submits hash analysis

```
1. Browser → POST /api/intel/hash
2. Flask routes to api_analyze_hash()
3. Checks @login_required
4. Imports lurenet.analysis.ThreatIntelligence
5. Calls intel.analyze_hash(file_hash)
6. Returns JSON response
7. JavaScript updates page
```

## Key Components

### Flask App Configuration

```python
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['JSON_AS_ASCII'] = False  # UTF-8 support
```

### Authentication Flow

```
1. User visits any page
2. @login_required decorator checks session
3. If session.get('logged_in'):
   - Allow access
4. Else:
   - Redirect to /login
```

### Template Inheritance

```jinja2
{# base.html #}
<!DOCTYPE html>
<html>
  <head>...</head>
  <body>
    <aside class="sidebar">...</aside>
    <main>
      {% block content %}{% endblock %}
    </main>
  </body>
</html>

{# intelligence.html #}
{% extends "base.html" %}
{% block content %}
  <!-- Page-specific content here -->
{% endblock %}
```

## WebSocket Integration

```python
# Server side (app.py)
@socketio.on('connect')
def handle_connect():
    if 'logged_in' not in session:
        return False
    emit('connected', {'message': 'Connected to LureNet'})

# Client side (base.html)
const socket = io();
socket.on('connected', (data) => {
    console.log('Connected:', data.message);
});
```

## API Endpoints

All API endpoints follow this pattern:

```python
@app.route('/api/intel/hash', methods=['POST'])
@login_required
def api_analyze_hash():
    try:
        data = request.get_json()
        file_hash = data.get('hash', '').strip()
        
        # Import analysis module
        from lurenet.analysis import ThreatIntelligence
        
        # Perform analysis
        intel = ThreatIntelligence()
        result = intel.analyze_hash(file_hash)
        
        # Return JSON
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

## Analysis Module Structure

```
lurenet/analysis/
    ├── __init__.py          # Exports classes
    ├── threat_intel.py      # ThreatIntelligence class
    ├── yara_scanner.py      # YARAScanner class
    └── ip_reputation.py     # IPReputation class
```

## Why It Works

1. **Correct Imports**: `app.py` imports from `lurenet.web.app`
2. **Proper Routes**: All routes defined in `create_app()`
3. **Template Location**: Flask knows templates are in `lurenet/web/templates/`
4. **Static Files**: Flask serves from `lurenet/web/static/`
5. **Session Management**: Properly configured with secure cookies
6. **UTF-8 Support**: All forms have `accept-charset="UTF-8"`

## Testing the Setup

```bash
# 1. Verify everything is configured
python3 verify_setup.py

# 2. Start the application
python3 app.py

# 3. Open browser
# Navigate to http://localhost:5000

# 4. Login
# Username: admin
# Password: LureNet2024!

# 5. Test features
# - Visit /intelligence
# - Visit /yara_scan
# - Visit /ip_lookup
```

## Troubleshooting

### Issue: Templates not found
**Solution**: Check that `lurenet/web/templates/` exists and contains HTML files

### Issue: Routes returning 404
**Solution**: Verify routes are defined in `lurenet/web/app.py`

### Issue: Static files not loading
**Solution**: Check `lurenet/web/static/css/main.css` exists

### Issue: Analysis features error
**Solution**: Verify `lurenet/analysis/` module exists with all required files

---

**Everything is properly configured and ready to use!**
