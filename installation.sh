#!/bin/bash

# installation.sh
# Installs dependencies, Janus WebRTC Server, and compiles the Janus Streaming Monitor Plugin on Ubuntu 24.04

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'  # No Color

# Log functions
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root (use sudo)"
fi

# Check if running on Ubuntu 24.04
if ! lsb_release -d | grep -q "Ubuntu 24.04"; then
    log_error "This script is designed for Ubuntu 24.04"
fi

# Check if source file exists
if [ ! -f "janus_streaming_monitor.c" ]; then
    log_error "janus_streaming_monitor.c not found in current directory"
fi

# Install dependencies
log_info "Installing dependencies..."
apt update
apt install -y build-essential gcc pkg-config \
    libglib2.0-dev libjson-glib-dev libmysqlclient-dev libconfig-dev \
    libmicrohttpd-dev libjansson-dev libssl-dev libsrtp2-dev \
    libsofia-sip-ua-dev libopus-dev libogg-dev libini-config-dev \
    libnice-dev git curl autoconf automake libtool cmake

# Install MySQL server and client
log_info "Installing MySQL server..."
apt install -y mysql-server

# Prompt for MySQL credentials
log_info "Setting up MySQL database..."
read -p "Enter MySQL username for Janus (default: janus): " MYSQL_USER
MYSQL_USER=${MYSQL_USER:-janus}
read -sp "Enter MySQL password for Janus: " MYSQL_PASSWORD
echo
read -p "Enter MySQL database name (default: janus_streams): " MYSQL_DB
MYSQL_DB=${MYSQL_DB:-janus_streams}

# Secure MySQL installation and create database
log_info "Configuring MySQL..."
mysql -u root -e "CREATE DATABASE IF NOT EXISTS ${MYSQL_DB};"
mysql -u root -e "CREATE USER IF NOT EXISTS '${MYSQL_USER}'@'localhost' IDENTIFIED BY '${MYSQL_PASSWORD}';"
mysql -u root -e "GRANT ALL PRIVILEGES ON ${MYSQL_DB}.* TO '${MYSQL_USER}'@'localhost';"
mysql -u root -e "FLUSH PRIVILEGES;"

# Install Janus WebRTC Server
log_info "Installing Janus WebRTC Server..."
if [ -d "janus-gateway" ]; then
    rm -rf janus-gateway
fi
git clone https://github.com/meetecho/janus-gateway.git
cd janus-gateway
sh autogen.sh
./configure --prefix=/usr/local
make
make install
cd ..

# Create configuration file
log_info "Creating plugin configuration file..."
cat > janus.plugin.streamingmonitor.cfg << EOF
[general]
mysql_host = localhost
mysql_user = ${MYSQL_USER}
mysql_password = ${MYSQL_PASSWORD}
mysql_database = ${MYSQL_DB}
mysql_port = 3306
rtp_listen_port = 5004
EOF

# Compile the plugin
log_info "Compiling Janus Streaming Monitor Plugin..."
gcc -fPIC -Wall -g $(pkg-config --cflags glib-2.0 json-glib-1.0 mysqlclient libconfig) \
    -I/usr/local/include/janus \
    -o janus_streamingmonitor.so janus_streaming_monitor.c \
    -shared $(pkg-config --libs glib-2.0 json-glib-1.0 mysqlclient libconfig) \
    -L/usr/local/lib || log_error "Compilation failed"

# Install the plugin
log_info "Installing plugin..."
mkdir -p /usr/local/lib/janus/plugins
cp janus_streamingmonitor.so /usr/local/lib/janus/plugins/
chmod 644 /usr/local/lib/janus/plugins/janus_streamingmonitor.so
mkdir -p /usr/local/etc/janus
cp janus.plugin.streamingmonitor.cfg /usr/local/etc/janus/
chmod 644 /usr/local/etc/janus/janus.plugin.streamingmonitor.cfg

# Configure Janus to load the plugin
log_info "Configuring Janus..."
JANUS_CFG="/usr/local/etc/janus/janus.jcfg"
if [ -f "$JANUS_CFG" ]; then
    if ! grep -q "janus.plugin.streamingmonitor" "$JANUS_CFG"; then
        sed -i '/plugins:/a \    janus.plugin.streamingmonitor = true' "$JANUS_CFG"
    fi
else
    cat > "$JANUS_CFG" << EOF
general: {
    configs_folder = /usr/local/etc/janus
    plugins_folder = /usr/local/lib/janus/plugins
}
plugins: {
    janus.plugin.streamingmonitor = true
}
EOF
fi

# Start Janus
log_info "Starting Janus server..."
janus &

# Wait briefly and check if Janus is running
sleep 2
if pgrep -x "janus" > /dev/null; then
    log_info "Janus server started successfully"
else
    log_error "Failed to start Janus server. Check logs in /usr/local/var/log/janus/"
fi

log_info "Installation complete! Plugin is installed and Janus is running."
log_info "Test the plugin by sending RTP packets to port 5004 or using WebSocket API."