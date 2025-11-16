#!/bin/bash
# LureNet Quick Installation Script
# Wrapper around setup.py for quick installation

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    echo -e "${GREEN}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║                 ██╗     ██╗   ██╗██████╗ ███████╗                 ║
║                 ██║     ██║   ██║██╔══██╗██╔════╝                 ║
║                 ██║     ██║   ██║██████╔╝█████╗                   ║
║                 ██║     ██║   ██║██╔══██╗██╔══╝                   ║
║                 ███████╗╚██████╔╝██║  ██║███████╗                 ║
║                 ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝                 ║
║                                                                    ║
║                    ███╗   ██╗███████╗████████╗                    ║
║                    ████╗  ██║██╔════╝╚══██╔══╝                    ║
║                    ██╔██╗ ██║█████╗     ██║                       ║
║                    ██║╚██╗██║██╔══╝     ██║                       ║
║                    ██║ ╚████║███████╗   ██║                       ║
║                    ╚═╝  ╚═══╝╚══════╝   ╚═╝                       ║
║                                                                    ║
║              Advanced Honeypot Platform v2.0.0                     ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

check_python() {
    log_info "Checking Python installation..."

    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        log_info "Please install Python 3.8 or higher and try again"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    log_success "Python $PYTHON_VERSION found"

    # Check if version is 3.8 or higher
    REQUIRED_VERSION="3.8"
    if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
        log_error "Python $PYTHON_VERSION is too old (required: $REQUIRED_VERSION+)"
        exit 1
    fi
}

check_pip() {
    log_info "Checking pip installation..."

    if ! command -v pip3 &> /dev/null; then
        log_warning "pip3 not found, installing..."

        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y python3-pip
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3-pip
        else
            log_error "Cannot install pip automatically. Please install pip3 manually"
            exit 1
        fi
    fi

    log_success "pip3 found"
}

install_system_dependencies() {
    log_info "Checking system dependencies..."

    if [[ $EUID -ne 0 ]] && command -v sudo &> /dev/null; then
        SUDO="sudo"
    else
        SUDO=""
    fi

    if command -v apt-get &> /dev/null; then
        log_info "Detected Debian/Ubuntu system"
        $SUDO apt-get update
        $SUDO apt-get install -y \
            python3-dev \
            python3-venv \
            build-essential \
            libssl-dev \
            libffi-dev \
            git \
            curl \
            wget \
            || log_warning "Some dependencies failed to install"

    elif command -v yum &> /dev/null; then
        log_info "Detected RHEL/CentOS system"
        $SUDO yum install -y \
            python3-devel \
            gcc \
            gcc-c++ \
            make \
            openssl-devel \
            libffi-devel \
            git \
            curl \
            wget \
            || log_warning "Some dependencies failed to install"
    else
        log_warning "Unknown package manager, skipping system dependencies"
    fi
}

run_setup() {
    log_info "Running setup wizard..."

    # Make setup.py executable
    chmod +x setup.py

    # Run setup
    python3 setup.py
}

show_help() {
    cat << EOF
LureNet Installation Script

Usage: $0 [OPTIONS]

Options:
    --quick         Quick installation with default settings
    --no-deps       Skip system dependency installation
    --help          Show this help message

Examples:
    $0              # Interactive installation
    $0 --quick      # Quick installation with defaults
    $0 --no-deps    # Skip dependency installation

EOF
}

quick_install() {
    log_info "Running quick installation..."

    # Create default configuration
    cat > /tmp/lurenet_quick_config.json << EOF
{
    "installation": {
        "directory": "/opt/lurenet",
        "data_directory": "/opt/lurenet/data",
        "log_directory": "/var/log/lurenet"
    },
    "deployment": {
        "mode": "systemd"
    },
    "services": {
        "http": {"enabled": true, "port": 8080},
        "ssh": {"enabled": true, "port": 2222},
        "ftp": {"enabled": true, "port": 2121},
        "smtp": {"enabled": true, "port": 2525},
        "dns": {"enabled": true, "port": 5353},
        "smb": {"enabled": false},
        "ldap": {"enabled": false}
    },
    "database": {
        "type": "sqlite",
        "path": "/opt/lurenet/data/lurenet.db"
    },
    "monitoring": {
        "enabled": true,
        "check_interval": 30,
        "resource_monitoring": true
    },
    "alerts": {
        "email": {"enabled": false},
        "webhook": {"enabled": false}
    },
    "dashboard": {
        "enabled": true,
        "port": 8888,
        "host": "0.0.0.0",
        "enhanced": true
    },
    "security": {
        "rate_limiting": true,
        "ip_blacklist": true,
        "geo_blocking": false,
        "ssl_enabled": false
    }
}
EOF

    log_success "Quick configuration created"
    log_info "You can customize /tmp/lurenet_quick_config.json if needed"
}

# Main execution
main() {
    print_banner

    # Parse arguments
    SKIP_DEPS=false
    QUICK_MODE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-deps)
                SKIP_DEPS=true
                shift
                ;;
            --quick)
                QUICK_MODE=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Check prerequisites
    check_python
    check_pip

    # Install dependencies unless skipped
    if [[ "$SKIP_DEPS" == false ]]; then
        install_system_dependencies
    else
        log_warning "Skipping system dependency installation"
    fi

    # Quick mode or interactive
    if [[ "$QUICK_MODE" == true ]]; then
        quick_install
    fi

    # Run setup wizard
    run_setup

    log_success "Installation complete!"
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
