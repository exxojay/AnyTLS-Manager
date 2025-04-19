#!/usr/bin/env bash
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 颜色定义
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Yellow_font_prefix="\033[0;33m" && Cyan_font_prefix="\033[0;36m" && RESET="\033[0m"

# 信息前缀
INFO="${Green_font_prefix}[信息]${RESET}"
ERROR="${Red_font_prefix}[错误]${RESET}"
WARNING="${Yellow_font_prefix}[警告]${RESET}"

# Global variables
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="anytls-server"
CONFIG_DIR="/etc/anytls"
CONFIG_FILE="${CONFIG_DIR}/config"
SERVICE_FILE="/etc/systemd/system/anytls.service"
LISTEN_ADDR="[::]"  # Default listen address
LISTEN_PORT="8443"  # Default listen port
PASSWORD=""
TMP_DIR="/tmp/anytls"
RELEASE=""
VERSION=""          # Stores downloaded version
SNI=""              # Default uses server IP as SNI
INSECURE="1"        # Default enables insecure connection

# Check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${ERROR} Please run as root or with sudo"
        exit 1
    fi
}

# Check system type
check_system_type() {
    if [[ -f /etc/redhat-release ]]; then
        RELEASE="centos"
    elif grep -q -E -i "debian|ubuntu" /etc/issue; then
        RELEASE="debian"
    elif grep -q -E -i "centos|red hat|redhat" /etc/issue; then
        RELEASE="centos"
    elif grep -q -E -i "debian|ubuntu" /proc/version; then
        RELEASE="debian"
    else
        RELEASE="unknown"
    fi
    if [[ "$RELEASE" == "unknown" ]]; then
        echo -e "${ERROR} Unrecognized system distribution, please check compatibility"
        exit 1
    fi
    echo -e "${INFO} Detected system: $RELEASE"
}

# Install required tools
install_tools() {
    local missing_tools=()
    for tool in wget curl unzip openssl; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        echo -e "${INFO} All required tools are installed"
        return 0
    fi

    echo -e "${INFO} Missing tools detected: ${missing_tools[*]}, installing..."
    check_system_type
    case "$RELEASE" in
        debian)
            apt update && apt install -y "${missing_tools[@]}" || {
                echo -e "${ERROR} Failed to install dependencies"
                exit 1
            }
            ;;
        centos)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y "${missing_tools[@]}" || {
                    echo -e "${ERROR} Failed to install dependencies"
                    exit 1
                }
            else
                yum install -y "${missing_tools[@]}" || {
                    echo -e "${ERROR} Failed to install dependencies"
                    exit 1
                }
            fi
            ;;
        *)
            echo -e "${WARNING} Unknown distribution, attempting apt install..."
            apt update && apt install -y "${missing_tools[@]}" || {
                echo -e "${ERROR} Failed to install dependencies"
                exit 1
            }
            ;;
    esac
    echo -e "${INFO} Dependencies installed"
}

# Get system architecture
get_system_architecture() {
    case "$(uname -m)" in
        x86_64) echo "amd64" ;;
        aarch64) echo "arm64" ;;
        *) echo -e "${ERROR} Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
}

# Get latest version (falls back to 0.0.5 if failed), ensures no 'v' prefix
get_latest_version() {
    local version
    version=$(curl -s "https://api.github.com/repos/anytls/anytls-go/releases/latest" | grep -oP '"tag_name": "\K[^"]+')
    version=${version#v}  # Remove potential v prefix
    if [[ -z "$version" ]]; then
        echo -e "${WARNING} Failed to get latest version, using default 0.0.5"
        echo "0.0.5"
    else
        echo "$version"
    fi
}

# Download and extract anytls binary
download_anytls() {
    VERSION=$(get_latest_version)  # Set global version
    local arch_str=$(get_system_architecture)
    local zip_file="anytls_${VERSION}_linux_${arch_str}.zip"
    local download_url="https://github.com/anytls/anytls-go/releases/download/v${VERSION}/${zip_file}"
    
    echo -e "${INFO} Downloading ${zip_file}..."
    mkdir -p "${TMP_DIR}"
    wget -O "${TMP_DIR}/${zip_file}" "$download_url" || {
        echo -e "${ERROR} Download failed, check network or URL"
        exit 1
    }
    
    echo -e "${INFO} Extracting ${zip_file}..."
    unzip -o "${TMP_DIR}/${zip_file}" -d "${TMP_DIR}" || {
        echo -e "${ERROR} Extraction failed, ensure unzip is installed"
        exit 1
    }
    
    mv "${TMP_DIR}/anytls-server" "${INSTALL_DIR}/"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    
    rm -rf "${TMP_DIR}"
    echo -e "${INFO} Download and installation complete"
}

# Check if port is in use
check_port_in_use() {
    if [ -n "$(ss -ltnH "sport = :$1")" ]; then
        return 0  # Port in use
    else
        return 1  # Port available
    fi
}

# Configure firewall rules
configure_firewall() {
    if command -v ufw >/dev/null && ufw status | grep -q "active"; then
        ufw allow "$LISTEN_PORT/tcp" && echo -e "${INFO} $LISTEN_PORT/tcp allowed"
    elif command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --add-port="$LISTEN_PORT/tcp" --permanent && firewall-cmd --reload && echo -e "${INFO} $LISTEN_PORT/tcp allowed"
    else
        echo -e "${WARNING} No active firewall detected (ufw/firewalld), manually allow port $LISTEN_PORT"
    fi
}

# Remove firewall rules
remove_firewall_rules() {
    local port=$1
    if [ -z "$port" ]; then
        echo -e "${ERROR} No port provided, cannot remove rules"
        return 1
    fi
    if command -v ufw >/dev/null && ufw status | grep -q "active"; then
        ufw delete allow "$port/tcp" && echo -e "${INFO} Removed ufw rule for $port/tcp"
    elif command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --remove-port="$port/tcp" --permanent && firewall-cmd --reload && echo -e "${INFO} Removed firewalld rule for $port/tcp"
    else
        echo -e "${WARNING} No active firewall, no rules to remove"
    fi
    return 0
}

# Configure listen port and password
configure_anytls() {
    local input_port server_ips ip_array default_port="8443"

    # Configure listen port
    while true; do
        read -rp "Enter listen port (default: ${default_port}): " input_port
        input_port="${input_port:-$default_port}"  # Use default if empty
        if ! [[ "$input_port" =~ ^[0-9]+$ ]] || [ "$input_port" -lt 1 ] || [ "$input_port" -gt 65535 ]; then
            echo -e "${ERROR} Port must be 1-65535"
        elif check_port_in_use "$input_port"; then
            echo -e "${ERROR} Port ${input_port} in use, choose another"
        else
            LISTEN_PORT="$input_port"  # Only update if valid
            break
        fi
    done

    # Configure password
    read -rp "Enter AnyTLS password (empty for auto-generate): " input_password
    if [[ -z "$input_password" ]]; then
        PASSWORD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 16)
        echo -e "${Cyan_font_prefix}Auto-generated password: ${PASSWORD}${RESET}"
    else
        PASSWORD="$input_password"
    #done

    # Set defaults and optimize SNI
    server_ips=$(get_server_ip) || { echo -e "${ERROR} Failed to get server IP"; exit 1; }
    IFS=' ' read -r -a ip_array <<< "$server_ips"
    SNI="${ip_array[0]}"  # Default to first IP (usually IPv4)
    INSECURE="1"          # Default enable insecure

    # Configure firewall
    configure_firewall

    # Show current config
    echo -e "${INFO} Configuration:"
    echo -e "  Listen address: ${LISTEN_ADDR}:${LISTEN_PORT}"
    echo -e "  Password: ${PASSWORD}"
    echo -e "  Default SNI: ${SNI}"
    echo -e "  Insecure: ${INSECURE} (1=enable, 0=disable)"
}

# Save config to file
save_config() {
    mkdir -p "${CONFIG_DIR}"
    cat > "$CONFIG_FILE" <<EOF
listen_addr=${LISTEN_ADDR}
listen_port=${LISTEN_PORT}
password=${PASSWORD}
version=${VERSION}
sni=${SNI}
insecure=${INSECURE}
EOF
    echo -e "${INFO} Config saved to ${CONFIG_FILE}"
}

# Create/update systemd service
create_or_update_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=AnyTLS Server Service
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
Type=simple
User=root
Restart=on-failure
RestartSec=5s
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -l ${LISTEN_ADDR}:${LISTEN_PORT} -p ${PASSWORD}

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable anytls
    echo -e "${INFO} systemd service created/updated"
}

# Start service
start_service() {
    systemctl start anytls
    sleep 2
    if systemctl is-active --quiet anytls; then
        echo -e "${INFO} AnyTLS service started"
    else
        echo -e "${ERROR} Failed to start, check logs"
        journalctl -u anytls -n 20 --no-pager
    fi
}

# Stop service
stop_service() {
    systemctl stop anytls
    echo -e "${INFO} AnyTLS service stopped"
}

# Restart service
restart_service() {
    systemctl restart anytls
    sleep 2
    if systemctl is-active --quiet anytls; then
        echo -e "${INFO} AnyTLS service restarted"
    else
        echo -e "${ERROR} Failed to restart, check logs"
        journalctl -u anytls -n 20 --no-pager
    fi
}

# Get server public IP
get_server_ip() {
    local ipv4=""
    local ipv6=""

    if command -v ip >/dev/null 2>&1; then
        ipv4=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | grep -v '^127\.' | head -n 1)
        ipv6=$(ip -6 addr show scope global | grep -oP '(?<=inet6\s)[0-9a-f:]+' | grep -v '^fe80:' | head -n 1)
    elif command -v ifconfig >/dev/null 2>&1; then
        ipv4=$(ifconfig | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | grep -v '^127\.' | head -n 1)
        ipv6=$(ifconfig | grep -oP '(?<=inet6\s)[0-9a-f:]+' | grep -v '^fe80:' | head -n 1)
    fi

    if [[ -z "$ipv4" && -z "$ipv6" ]]; then
        ipv4=$(curl -s -4 ip.sb 2>/dev/null)
        ipv6=$(curl -s -6 ip.sb 2>/dev/null)
    fi

    if [[ -n "$ipv4" && -n "$ipv6" ]]; then
        echo "$ipv4 $ipv6"
    elif [[ -n "$ipv4" ]]; then
        echo "$ipv4"
    elif [[ -n "$ipv6" ]]; then
        echo "$ipv6"
    else
        echo -e "${ERROR} Failed to get server IP"
        return 1
    fi
    return 0
}

# View config
view_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # Read config
        local listen_port=$(grep '^listen_port=' "$CONFIG_FILE" | cut -d'=' -f2)
        local password=$(grep '^password=' "$CONFIG_FILE" | cut -d'=' -f2)
        local sni=$(grep '^sni=' "$CONFIG_FILE" | cut -d'=' -f2)
        local insecure=$(grep '^insecure=' "$CONFIG_FILE" | cut -d'=' -f2)
        local version=$(grep '^version=' "$CONFIG_FILE" | cut -d'=' -f2)
        local server_ips=$(get_server_ip) || { echo -e "${ERROR} Failed to get server IP"; return 1; }

        # Output basic config
        echo -e "${Cyan_font_prefix}AnyTLS Config:${RESET}"
        echo -e "Server IP: ${server_ips}"
        echo -e "Listen: ${LISTEN_ADDR}:${listen_port}"
        echo -e "Password: ${password}"
        echo -e "SNI: ${sni}"
        echo -e "Insecure: ${insecure} (1=enable, 0=disable)"
        echo -e "Version: ${version}"

        # Generate URI for dual-stack IPs
        IFS=' ' read -r -a ip_array <<< "$server_ips"
        for server_ip in "${ip_array[@]}"; do
            local ip_type="IPv4"
            local display_ip="$server_ip"
            if [[ "$server_ip" =~ : ]]; then
                ip_type="IPv6"
                display_ip="[$server_ip]"
            fi
            
            local uri="anytls://${password}@${display_ip}:${listen_port}/?"
            if [[ -n "$sni" ]]; then
                uri="${uri}sni=${sni}"
                [[ "$insecure" == "1" ]] && uri="${uri}&insecure=1" || uri="${uri}&insecure=0"
            else
                uri="${uri}insecure=${insecure}"
            fi
            echo -e "\n${Cyan_font_prefix}AnyTLS URI ($ip_type):${RESET}"
            echo -e "${Yellow_font_prefix}${uri}${RESET}"
        done

        # Add Mihomo/Sing-box config
        echo -e "\n${Green_font_prefix}=== Mihomo & Sing-box Config ===${RESET}"
        generate_anytls_config "$server_ips" "$listen_port" "$password" "$sni"
    else
        echo -e "${ERROR} Config not found, install AnyTLS first"
    fi
}

# Modify config
set_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${ERROR} Config not found, install AnyTLS first"
        return
    fi
    # Read current version and config
    local current_version=$(grep '^version=' "$CONFIG_FILE" | cut -d'=' -f2)
    SNI=$(grep '^sni=' "$CONFIG_FILE" | cut -d'=' -f2)
    INSECURE=$(grep '^insecure=' "$CONFIG_FILE" | cut -d'=' -f2)
    echo -e "What to modify?\n1. Change listen port\n2. Change password\n3. Change all"
    read -rp "Select: " choice
    case "$choice" in
        1)
            configure_port
            configure_firewall
            ;;
        2)
            configure_password
            ;;
        3)
            configure_anytls
            ;;
        *)
            echo -e "${ERROR} Invalid choice"
            return
            ;;
    esac
    # Save config preserving version/sni/insecure
    mkdir -p "${CONFIG_DIR}"
    cat > "$CONFIG_FILE" <<EOF
listen_addr=${LISTEN_ADDR}
listen_port=${LISTEN_PORT}
password=${PASSWORD}
version=${current_version}
sni=${SNI}
insecure=${INSECURE}
EOF
    echo -e "${INFO} Config updated at ${CONFIG_FILE}"
    create_or_update_service
    restart_service
}

configure_port() {
    local input_port
    while true; do
        read -rp "Enter new port (current: ${LISTEN_PORT}): " input_port
        if ! [[ "$input_port" =~ ^[0-9]+$ ]] || [ "$input_port" -lt 1 ] || [ "$input_port" -gt 65535 ]; then
            echo -e "${ERROR} Port must be 1-65535"
        elif check_port_in_use "$input_port"; then
            echo -e "${ERROR} Port ${input_port} in use"
        else
            LISTEN_PORT="$input_port"
            break
        fi
    done
}

configure_password() {
    read -rp "Enter new password (empty to auto-generate): " input_password
    if [[ -z "$input_password" ]]; then
        PASSWORD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 16)
        echo -e "${Cyan_font_prefix}Auto-generated: ${PASSWORD}${RESET}"
    else
        PASSWORD="$input_password"
    fi
}

# Uninstall AnyTLS
uninstall_anytls() {
    echo -e "${WARNING} Uninstalling AnyTLS..."
    read -rp "Confirm? (y/n): " confirm
    if [[ "${confirm,,}" == "y" ]]; then
        systemctl stop anytls
        systemctl disable anytls
        if [[ -f "$CONFIG_FILE" ]]; then
            local port=$(grep '^listen_port=' "$CONFIG_FILE" | cut -d'=' -f2)
            remove_firewall_rules "$port"
        else
            echo -e "${WARNING} Can't read config, skipping firewall rules"
        fi
        rm -f "${INSTALL_DIR}/${BINARY_NAME}"
        rm -rf "${CONFIG_DIR}"
        rm -f "${SERVICE_FILE}"
        systemctl daemon-reload
        echo -e "${INFO} AnyTLS uninstalled"
    else
        echo -e "${WARNING} Cancelled"
    fi
}

# Upgrade AnyTLS
upgrade_anytls() {
    local current_version latest_version
    if [[ -f "$CONFIG_FILE" ]]; then
        current_version=$(grep '^version=' "$CONFIG_FILE" | cut -d'=' -f2)
        current_version=${current_version:-"unknown"}
    else
        current_version="not installed"
    fi
    latest_version=$(get_latest_version)

    if [[ "$current_version" == "$latest_version" ]]; then
        echo -e "${INFO} Already latest version ($current_version)"
    else
        echo -e "${INFO} New version available: current $current_version, latest $latest_version"
        read -rp "Upgrade? (y/n): " choice
        if [[ "${choice,,}" == "y" ]]; then
            echo -e "${INFO} Upgrading..."
            systemctl stop anytls
            download_anytls  # Downloads new version and updates VERSION
            save_config      # Updates version in config
            create_or_update_service
            systemctl start anytls
            if systemctl is-active --quiet anytls; then
                echo -e "${INFO} Upgrade successful"
            else
                echo -e "${ERROR} Failed to start after upgrade"
                journalctl -u anytls -n 20 --no-pager
            fi
        else
            echo -e "${WARNING} Upgrade cancelled"
        fi
    fi
}

# Generate AnyTLS config (Mihomo/Sing-box only)
generate_anytls_config() {
    local server_ips="$1"
    local listen_port="$2"
    local password="$3"
    local sni="$4"
    IFS=' ' read -r -a ip_array <<< "$server_ips"
    
    for server_ip in "${ip_array[@]}"; do
        local ip_type="IPv4"
        local display_ip="$server_ip"
        if [[ "$server_ip" =~ : ]]; then
            ip_type="IPv6"
            display_ip="[$server_ip]"
        fi
        
        echo -e "\n${Yellow_font_prefix}================== Config ($ip_type) ==================${RESET}"

        echo -e "\n${Yellow_font_prefix}------------------ Mihomo Config ($ip_type) ------------------${RESET}"
        echo -e "${Green_font_prefix}proxies:${RESET}"
        echo -e "  - name: anytls-$ip_type"
        echo -e "    type: anytls"
        echo -e "    server: ${display_ip}"
        echo -e "    port: ${listen_port}"
        echo -e "    password: \"${password}\""
        echo -e "    client-fingerprint: chrome"
        echo -e "    udp: true"
        echo -e "    sni: \"${sni}\""
        echo -e "    alpn:"
        echo -e "      - h2"
        echo -e "      - http/1.1"
        echo -e "    skip-cert-verify: true"

        echo -e "\n${Yellow_font_prefix}------------------ Sing-box Config ($ip_type) ------------------${RESET}"
        echo -e "${Green_font_prefix}{${RESET}"
        echo -e "  \"type\": \"anytls\","
        echo -e "  \"tag\": \"anytls-out-$ip_type\","
        echo -e "  \"server\": \"${server_ip}\","
        echo -e "  \"server_port\": ${listen_port},"
        echo -e "  \"password\": \"${password}\","
        echo -e "  \"idle_session_check_interval\": \"30s\","
        echo -e "  \"idle_session_timeout\": \"30s\","
        echo -e "  \"min_idle_session\": 5,"
        echo -e "  \"tls\": {"
        echo -e "    \"enabled\": true,"
        echo -e "    \"server_name\": \"${sni}\","
        echo -e "    \"insecure\": true"
        echo -e "  }"
        echo -e "}"
    done
}

# Install AnyTLS
install_anytls() {
    install_tools
    download_anytls  # Sets VERSION globally
    configure_anytls
    save_config      # Saves with version
    create_or_update_service
    start_service

    # Clear and show config
    clear
    echo -e "${Green_font_prefix}=== AnyTLS Installed ===${RESET}"
    local server_ip=$(get_server_ip) || { echo -e "${ERROR} Failed to get server IP"; exit 1; }
    generate_anytls_config "$server_ip" "$LISTEN_PORT" "$PASSWORD" "$SNI"
}

# Main menu (consistent with shadowtls_manager structure)
main_menu() {
    while true; do
        clear
        echo -e "\n${Cyan_font_prefix}AnyTLS Management${RESET}"
        echo -e "=================================="
        echo -e " Installation & Updates"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}1. Install AnyTLS${RESET}"
        echo -e "${Yellow_font_prefix}2. Upgrade AnyTLS${RESET}"
        echo -e "${Yellow_font_prefix}3. Uninstall AnyTLS${RESET}"
        echo -e "=================================="
        echo -e " Configuration"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}4. View Config${RESET}"
        echo -e "${Yellow_font_prefix}5. Modify Config${RESET}"
        echo -e "=================================="
        echo -e " Service Control"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}6. Start AnyTLS${RESET}"
        echo -e "${Yellow_font_prefix}7. Stop AnyTLS${RESET}"
        echo -e "${Yellow_font_prefix}8. Restart AnyTLS${RESET}"
        echo -e "=================================="
        echo -e " Exit"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}0. Exit${RESET}"
        
        # Check AnyTLS status
        if [[ -e "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
            if systemctl is-active --quiet anytls; then
                echo -e " Status: ${Green_font_prefix}Installed & Running${RESET}"
            else
                echo -e " Status: ${Green_font_prefix}Installed${RESET} but ${Red_font_prefix}Stopped${RESET}"
            fi
        else
            echo -e " Status: ${Red_font_prefix}Not Installed${RESET}"
        fi
        
        read -rp "Select [0-8]: " choice
        case "$choice" in
            1) install_anytls ;;
            2) upgrade_anytls ;;
            3) uninstall_anytls ;;
            4) view_config ;;
            5) set_config ;;
            6) start_service ;;
            7) stop_service ;;
            8) restart_service ;;
            0) exit 0 ;;
            *) echo -e "${ERROR} Invalid choice" ;;
        esac
        echo -e "\nPress any key to return..."
        read -n1 -s
    done
}

# Execute
check_root
main_menu
