# LureNet Quick Start Guide

## Overview
LureNet Enterprise v2.0 is now fully configured with a modern, responsive UI and comprehensive threat analysis features.

## Prerequisites
Ensure you have Python 3.8+ and all dependencies installed:
```bash
pip install -r requirements.txt
```

## Starting LureNet

### 1. Verify Setup
First, verify all components are properly configured:
```bash
python3 verify_setup.py
```

You should see:
```
✅ All checks passed! LureNet is properly configured.
```

### 2. Start the Application
```bash
python3 app.py
```

The application will start and show:
```
🎯 LureNet Enterprise v2.0
📊 Dashboard: http://localhost:5000
🔐 Login: admin / LureNet2024!
```

### 3. Access the Dashboard
Open your browser and navigate to:
```
http://localhost:5000
```

**Default Credentials:**
- Username: `admin`
- Password: `LureNet2024!`

## Features

### 📊 Dashboard
- Real-time threat statistics
- Attack distribution charts
- Severity level analysis
- Recent threat events

### ⚠️ Threats
- Comprehensive threat analysis
- Detailed event tracking
- Source IP tracking
- Attack type classification

### 📈 Analytics
- Top attacker analysis
- Geographic distribution
- Threat score calculations

### 🔍 Threat Intelligence
- **Hash Analysis**: Analyze MD5/SHA1/SHA256 hashes
- **URL Scanning**: Check URLs for malicious content

### 🛡️ YARA Scanner
- Scan data with YARA rules
- Malware detection
- Custom rule support

### 🌐 IP Lookup
- Geolocation lookup
- IP reputation analysis
- Recent attacker IPs

### ⚙️ Services
- Monitor honeypot services
- Service status tracking
- Real-time updates

## UI Features

### ✨ Modern Design
- Dark theme optimized for security professionals
- Responsive mobile design
- Professional color palette
- Smooth animations

### 📱 Mobile Support
- Hamburger menu for mobile devices
- Touch-optimized interface
- Responsive breakpoints (768px, 480px)
- Mobile-friendly forms

### ♿ Accessibility
- WCAG 2.1 compliant
- Keyboard navigation support
- Screen reader friendly
- Skip-to-content links
- ARIA labels throughout

### ⚡ Performance
- Resource preloading
- Deferred script loading
- Link prefetching
- Optimized font loading

## Configuration

### Custom Config File
```bash
python3 app.py --config /path/to/custom-config.yaml
```

### Run Without Dashboard
```bash
python3 app.py --no-dashboard
```

### Debug Mode
```bash
python3 app.py --debug
```

## Troubleshooting

### Templates Not Loading
Run the verification script:
```bash
python3 verify_setup.py
```

### Port Already in Use
Change the port in `config.yaml`:
```yaml
dashboard:
  port: 5001  # Change to different port
```

### Dependencies Missing
Reinstall requirements:
```bash
pip install -r requirements.txt --upgrade
```

## Security Notes

1. **Change Default Credentials**: Update `config.yaml` with secure credentials
2. **Enable HTTPS**: Set `SESSION_COOKIE_SECURE = True` in production
3. **Firewall**: Restrict dashboard access to trusted networks
4. **Updates**: Keep dependencies updated regularly

## Browser Support

- ✅ Chrome/Edge (latest)
- ✅ Firefox (latest)
- ✅ Safari (latest)
- ✅ Mobile browsers

## Need Help?

Check the logs for detailed error messages:
```bash
tail -f data/logs/lurenet.log
```

---

**LureNet Enterprise v2.0**  
Professional Honeypot & Threat Intelligence Platform
