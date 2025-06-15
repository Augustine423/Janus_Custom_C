#!/bin/bash

# Exit on any error
set -e

# Auto-detect public IP of EC2
PUBLIC_IP=$(curl -s https://api.ipify.org || echo "127.0.0.1")
INSTALL_DIR="/home/ubuntu"

# Function to check if a port is in use
check_port() {
    local port=$1
    if sudo netstat -tuln | grep -q ":${port}\b"; then
        echo "Error: Port $port is already in use."
        exit 1
    fi
}

# Step 1: Update the system
echo "Updating system..."
sudo apt update && sudo apt upgrade -y

# Step 2: Install dependencies
echo "Installing dependencies..."
sudo apt install -y \
    build-essential \
    git \
    cmake \
    pkg-config \
    automake \
    libtool \
    gengetopt \
    make \
    gcc \
    g++ \
    nginx \
    libmicrohttpd-dev \
    libjansson-dev \
    libssl-dev \
    libsrtp2-dev \
    libsofia-sip-ua-dev \
    libglib2.0-dev \
    libopus-dev \
    libogg-dev \
    libcurl4-openssl-dev \
    liblua5.3-dev \
    libconfig-dev \
    libnice-dev \
    libwebsockets-dev \
    libspeexdsp-dev \
    libavutil-dev \
    libavcodec-dev \
    libavformat-dev \
    libmysqlclient- dev \
    libjson-glic-dev

# Step 3: Install usrsctp
echo "Installing usrsctp..."
cd $INSTALL_DIR
if [ ! -d "usrsctp" ]; then
    git clone https://github.com/sctplab/usrsctp.git || { echo "Failed to clone usrsctp"; exit 1; }
fi
cd usrsctp
./bootstrap
./configure
make && sudo make install
sudo ldconfig
cd ..

# Step 4: Install libsrtp from source
echo "Installing libsrtp..."
wget https://github.com/cisco/libsrtp/archive/v2.5.0.tar.gz -O libsrtp-2.5.0.tar.gz || { echo "Failed to download libsrtp"; exit 1; }
tar xfv libsrtp-2.5.0.tar.gz
cd libsrtp-2.5.0
./configure --prefix=/usr
make && sudo make install
sudo ldconfig
cd ..

# Step 5: Install Janus Gateway
echo "Installing Janus Gateway..."
if [ ! -d "janus-gateway" ]; then
    git clone https://github.com/meetecho/janus-gateway.git || { echo "Failed to clone janus-gateway"; exit 1; }
fi
cd janus-gateway
sh autogen.sh
./configure --prefix=/opt/janus \
    --enable-websockets \
    --enable-libsrtp2
make
sudo make install
sudo make configs

# Step 6: Ensure logger plugins folder exists and has correct permissions
echo "Ensuring logger plugins folder exists..."
sudo mkdir -p /opt/janus/lib/janus/loggers
sudo chmod 755 /opt/janus/lib/janus/loggers
sudo chown root:root /opt/janus/lib/janus/loggers

# Step 6.1: Create recordings directory and set permissions
echo "Creating recordings directory..."
sudo mkdir -p /opt/janus/recordings
sudo chmod 755 /opt/janus/recordings
sudo chown root:root /opt/janus/recordings

# Step 7: Apply custom Janus core configuration
echo "Applying custom Janus core configuration..."
cat <<EOF | sudo tee /opt/janus/etc/janus/janus.jcfg > /dev/null
general: {
        configs_folder = "/opt/janus/etc/janus"
        plugins_folder = "/opt/janus/lib/janus/plugins"
        transports_folder = "/opt/janus/lib/janus/transports"
        events_folder = "/opt/janus/lib/janus/events"
        loggers_folder = "/opt/janus/lib/janus/loggers"
        debug_level = 4
        admin_secret = "janusoverlord"
        protected_folders = [
                "/bin",
                "/boot",
                "/dev",
                "/etc",
                "/initrd",
                "/lib",
                "/lib32",
                "/lib64",
                "/proc",
                "/sbin",
                "/sys",
                "/usr",
                "/var",
                "/opt/janus/bin",
                "/opt/janus/etc",
                "/opt/janus/include",
                "/opt/janus/lib",
                "/opt/janus/lib32",
                "/opt/janus/lib64",
                "/opt/janus/sbin"
        ]
}

certificates: {
}

media: {
}

nat: {
        stun_server = "stun.l.google.com"
        stun_port = 19302
        nice_debug = false
        full_trickle = true
        ice_lite = true
        ignore_mdns = true
        nat_1_1_mapping = "auto"
}

plugins: {
}

transports: {
        disable = "libjanus_rabbitmq.so"
}

loggers: {
        disable = "libjanus_jsonlog.so"
}

events: {
}
EOF

# Step 8: Apply custom video room plugin configuration
echo "Applying custom video room plugin configuration..."
cat <<EOF | sudo tee /opt/janus/etc/janus/janus.plugin.videoroom.jcfg > /dev/null
general: {
        admin_key = "supersecret"
        events = true
        string_ids = true
}

room-1234: {
        description = "Demo Room"
        secret = "adminpwd"
        publishers = 50
        bitrate = 128000
        fir_freq = 10
        audiocodec = "opus"
        videocodec = "h264"
        record = true
        rec_dir = "/opt/janus/recordings"
        lock_record = true
}
EOF

# Step 9: Apply custom Unix sockets transport configuration
echo "Applying custom Unix sockets transport configuration..."
cat <<EOF | sudo tee /opt/janus/etc/janus/janus.transport.pfunix.jcfg > /dev/null
general: {
        enabled = true
        json = "indented"
        path = "/tmp/janus.sock"
}

admin: {
        admin_enabled = true
        admin_path = "/tmp/janus-admin.sock"
}
EOF

# Step 10: Apply custom WebSockets transport configuration
echo "Applying custom WebSockets transport configuration..."
cat <<EOF | sudo tee /opt/janus/etc/janus/janus.transport.websockets.jcfg > /dev/null
general: {
        json = "indented"
        ws = true
        ws_port = 8188
        wss = false
}

admin: {
        admin_ws = false
        admin_ws_port = 7188
        admin_wss = false
}

cors: {
}

certificates: {
}
EOF

# Step 11: Apply custom streaming plugin configuration
echo "Applying custom streaming plugin configuration..."
cat <<EOF | sudo tee /opt/janus/etc/janus/janus.plugin.streaming.jcfg > /dev/null
general: {
    admin_key = "supersecret"
    #rtp_port_range = "5100-40000"
    events = true
    string_ids = false
}

rtp-sample: {
    type = "rtp"
    id = 1
    description = "MDT Test "
    metadata = "You can use this metadata section to put any info you want!"
    audio = true
    video = true
    audioport = 5002
    audiopt = 111
    audiocodec = "opus"
    videoport = 5004
    videopt = 100
    videocodec = "h264"
    secret = "adminpwd"
}

multistream-test: {
    type = "rtp"
    id = 1234
    description = "Multistream test (1 audio, 50 video)"
    metadata = "This is an example of a multistream mountpoint: you'll get an audio stream and fifty video feeds"
    media = (
        {
            type = "audio"
            mid = "a"
            label = "Audio stream"
            port = 5100
            pt = 111
            codec = "opus"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-a-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v1"
            label = "Drone Video stream #1"
            port = 5101
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v1-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v2"
            label = "Drone Video stream #2"
            port = 5102
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v2-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v3"
            label = "Drone Video stream #3"
            port = 5103
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v3-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v4"
            label = "Drone Video stream #4"
            port = 5104
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v4-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v5"
            label = "Drone Video stream #5"
            port = 5105
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v5-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v6"
            label = "Drone Video stream #6"
            port = 5106
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v6-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v7"
            label = "Drone Video stream #7"
            port = 5107
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v7-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v8"
            label = "Drone Video stream #8"
            port = 5108
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v8-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v9"
            label = "Drone Video stream #9"
            port = 5109
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v9-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v10"
            label = "Drone Video stream #10"
            port = 5110
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v10-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v11"
            label = "Drone Video stream #11"
            port = 5111
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v11-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v12"
            label = "Drone Video stream #12"
            port = 5112
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v12-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v13"
            label = "Drone Video stream #13"
            port = 5113
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v13-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v14"
            label = "Drone Video stream #14"
            port = 5114
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v14-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v15"
            label = "Drone Video stream #15"
            port = 5115
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v15-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v16"
            label = "Drone Video stream #16"
            port = 5116
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v16-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v17"
            label = "Drone Video stream #17"
            port = 5117
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v17-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v18"
            label = "Drone Video stream #18"
            port = 5118
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v18-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v19"
            label = "Drone Video stream #19"
            port = 5119
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v19-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v20"
            label = "Drone Video stream #20"
            port = 5120
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v20-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v21"
            label = "Drone Video stream #21"
            port = 5121
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v21-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v22"
            label = "Drone Video stream #22"
            port = 5122
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v22-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v23"
            label = "Drone Video stream #23"
            port = 5123
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v23-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v24"
            label = "Drone Video stream #24"
            port = 5124
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v24-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v25"
            label = "Drone Video stream #25"
            port = 5125
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v25-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v26"
            label = "Drone Video stream #26"
            port = 5126
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v26-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v27"
            label = "Drone Video stream #27"
            port = 5127
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v27-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v28"
            label = "Drone Video stream #28"
            port = 5128
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v28-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v29"
            label = "Drone Video stream #29"
            port = 5129
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v29-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v30"
            label = "Drone Video stream #30"
            port = 5130
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v30-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v31"
            label = "Drone Video stream #31"
            port = 5131
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v31-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v32"
            label = "Drone Video stream #32"
            port = 5132
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v32-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v33"
            label = "Drone Video stream #33"
            port = 5133
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v33-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v34"
            label = "Drone Video stream #34"
            port = 5134
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v34-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v35"
            label = "Drone Video stream #35"
            port = 5135
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v35-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v36"
            label = "Drone Video stream #36"
            port = 5136
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v36-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v37"
            label = "Drone Video stream #37"
            port = 5137
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v37-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v38"
            label = "Drone Video stream #38"
            port = 5138
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v38-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v39"
            label = "Drone Video stream #39"
            port = 5139
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v39-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v40"
            label = "Drone Video stream #40"
            port = 5140
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v40-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v41"
            label = "Drone Video stream #41"
            port = 5141
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v41-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v42"
            label = "Drone Video stream #42"
            port = 5142
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v42-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v43"
            label = "Drone Video stream #43"
            port = 5143
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v43-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v44"
            label = "Drone Video stream #44"
            port = 5144
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v44-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v45"
            label = "Drone Video stream #45"
            port = 5145
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v45-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v46"
            label = "Drone Video stream #46"
            port = 5146
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v46-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v47"
            label = "Drone Video stream #47"
            port = 5147
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v47-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v48"
            label = "Drone Video stream #48"
            port = 5148
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v48-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v49"
            label = "Drone Video stream #49"
            port = 5149
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v49-%Y%m%d%H%M%S.mjr"
        },
        {
            type = "video"
            mid = "v50"
            label = "Drone Video stream #50"
            port = 5150
            pt = 100
            codec = "h264"
            record = true
            recfile = "/opt/janus/recordings/multistream-test-v50-%Y%m%d%H%M%S.mjr"
        }
    )
    secret = "adminpwd"
}

file-live-sample: {
    type = "live"
    id = 2
    description = "a-law file source (radio broadcast)"
    filename = "/opt/janus/share/janus/streams/radio.alaw"
    audio = true
    video = false
    secret = "adminpwd"
}

file-ondemand-sample: {
    type = "ondemand"
    id = 3
    description = "mu-law file source (music)"
    filename = "/opt/janus/share/janus/streams/music.mulaw"
    audio = true
    video = false
    secret = "adminpwd"
}
EOF

# Step 12: Copy demo files to nginx web root
echo "Copying demo files to /var/www/html..."
sudo cp -r /opt/janus/share/janus/html/* /var/www/html/

# Step 13: Verify installation
echo "Verifying Janus installation..."
/opt/janus/bin/janus --version



# Step 14: Test Janus with NAT setting
echo "Starting Janus with NAT 1:1 mapping ($PUBLIC_IP)..."
/opt/janus/bin/janus --nat-1-1=$PUBLIC_IP -d 5 &

# Wait a few seconds for Janus to start
sleep 5

# Step 15: Create systemd service for Janus
echo "Creating systemd service for Janus..."
cat <<EOF | sudo tee /etc/systemd/system/janus.service > /dev/null
[Unit]
Description=Janus WebRTC Gateway
After=network.target

[Service]
ExecStart=/opt/janus/bin/janus --nat-1-1=$PUBLIC_IP
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable janus
sudo systemctl start janus