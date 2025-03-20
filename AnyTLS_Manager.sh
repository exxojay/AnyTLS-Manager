#!/usr/bin/env bash
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 颜色定义
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Yellow_font_prefix="\033[0;33m" && Cyan_font_prefix="\033[0;36m" && RESET="\033[0m"

# 信息前缀
INFO="${Green_font_prefix}[信息]${RESET}"
ERROR="${Red_font_prefix}[错误]${RESET}"
WARNING="${Yellow_font_prefix}[警告]${RESET}"

# 全局变量
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="anytls-server"
CONFIG_DIR="/etc/anytls"
CONFIG_FILE="${CONFIG_DIR}/config"
SERVICE_FILE="/etc/systemd/system/anytls.service"
LISTEN_ADDR="[::]"  # 默认监听地址
LISTEN_PORT="8443"  # 默认监听端口
PASSWORD=""
TMP_DIR="/tmp/anytls"
RELEASE=""
VERSION=""          # 用于存储下载的版本号
SNI=""              # 默认使用本机 IP 作为 SNI
INSECURE="1"        # 默认启用不安全连接

# 检查是否以 root 权限运行
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${ERROR} 请以 root 或使用 sudo 运行此脚本"
        exit 1
    fi
}

# 检查系统发行版类型
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
        echo -e "${ERROR} 无法识别的系统发行版，请检查兼容性"
        exit 1
    fi
    echo -e "${INFO} 检测到系统发行版: $RELEASE"
}

# 检查并安装依赖工具
install_tools() {
    local missing_tools=()
    for tool in wget curl unzip openssl; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        echo -e "${INFO} 所有依赖工具已安装"
        return 0
    fi

    echo -e "${INFO} 检测到缺少工具: ${missing_tools[*]}，开始安装..."
    check_system_type
    case "$RELEASE" in
        debian)
            apt update && apt install -y "${missing_tools[@]}" || {
                echo -e "${ERROR} 安装依赖失败"
                exit 1
            }
            ;;
        centos)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y "${missing_tools[@]}" || {
                    echo -e "${ERROR} 安装依赖失败"
                    exit 1
                }
            else
                yum install -y "${missing_tools[@]}" || {
                    echo -e "${ERROR} 安装依赖失败"
                    exit 1
                }
            fi
            ;;
        *)
            echo -e "${WARNING} 未知发行版，尝试使用 apt 安装..."
            apt update && apt install -y "${missing_tools[@]}" || {
                echo -e "${ERROR} 安装依赖失败"
                exit 1
            }
            ;;
    esac
    echo -e "${INFO} 依赖工具安装完成"
}

# 检查系统架构
get_system_architecture() {
    case "$(uname -m)" in
        x86_64) echo "amd64" ;;
        aarch64) echo "arm64" ;;
        *) echo -e "${ERROR} 不支持的系统架构: $(uname -m)"; exit 1 ;;
    esac
}

# 获取最新版本号，失败时回退到默认版本 0.0.5，确保不含 v 前缀
get_latest_version() {
    local version
    version=$(curl -s "https://api.github.com/repos/anytls/anytls-go/releases/latest" | grep -oP '"tag_name": "\K[^"]+')
    version=${version#v}  # 去掉可能的 v 前缀
    if [[ -z "$version" ]]; then
        echo -e "${WARNING} 无法获取最新版本，使用默认版本 0.0.5"
        echo "0.0.5"
    else
        echo "$version"
    fi
}

# 下载并解压 anytls 二进制文件
download_anytls() {
    VERSION=$(get_latest_version)  # 设置全局版本号
    local arch_str=$(get_system_architecture)
    local zip_file="anytls_${VERSION}_linux_${arch_str}.zip"
    local download_url="https://github.com/anytls/anytls-go/releases/download/v${VERSION}/${zip_file}"
    
    echo -e "${INFO} 正在下载 ${zip_file} ..."
    mkdir -p "${TMP_DIR}"
    wget -O "${TMP_DIR}/${zip_file}" "$download_url" || {
        echo -e "${ERROR} 下载失败，请检查网络或 URL"
        exit 1
    }
    
    echo -e "${INFO} 解压 ${zip_file} ..."
    unzip -o "${TMP_DIR}/${zip_file}" -d "${TMP_DIR}" || {
        echo -e "${ERROR} 解压失败，请确保 unzip 已安装"
        exit 1
    }
    
    mv "${TMP_DIR}/anytls-server" "${INSTALL_DIR}/"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    
    rm -rf "${TMP_DIR}"
    echo -e "${INFO} 下载并安装完成"
}

# 检测端口是否被占用
check_port_in_use() {
    if [ -n "$(ss -ltnH "sport = :$1")" ]; then
        return 0  # 端口被占用
    else
        return 1  # 端口未被占用
    fi
}

# 配置监听端口和密码
configure_anytls() {
    local input_port
    while true; do
        read -rp "请输入监听端口 (默认: ${LISTEN_PORT}): " input_port
        LISTEN_PORT="${input_port:-$LISTEN_PORT}"
        if ! [[ "$LISTEN_PORT" =~ ^[0-9]+$ ]] || [ "$LISTEN_PORT" -lt 1 ] || [ "$LISTEN_PORT" -gt 65535 ]; then
            echo -e "${ERROR} 端口号必须是 1-65535 之间的数字"
        elif check_port_in_use "$LISTEN_PORT"; then
            echo -e "${ERROR} 端口 ${LISTEN_PORT} 已被占用，请选择其他端口"
        else
            break
        fi
    done

    read -rp "请输入 AnyTLS 密码 (留空则自动生成): " input_password
    if [[ -z "$input_password" ]]; then
        PASSWORD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 16)
        echo -e "${Cyan_font_prefix}自动生成的密码为: ${PASSWORD}${RESET}"
    else
        PASSWORD="$input_password"
    fi

    # 设置默认值
    SNI=$(get_server_ip)  # 默认使用本机 IP 作为 SNI
    INSECURE="1"          # 默认启用不安全连接
}

# 保存配置到文件
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
    echo -e "${INFO} 配置已保存至 ${CONFIG_FILE}"
}

# 创建或更新 systemd 服务文件
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
    echo -e "${INFO} systemd 服务已创建或更新"
}

# 启动服务
start_service() {
    systemctl start anytls
    sleep 2
    if systemctl is-active --quiet anytls; then
        echo -e "${INFO} AnyTLS 服务已启动"
    else
        echo -e "${ERROR} AnyTLS 服务启动失败，请检查日志"
        journalctl -u anytls -n 20 --no-pager
    fi
}

# 停止服务
stop_service() {
    systemctl stop anytls
    echo -e "${INFO} AnyTLS 服务已停止"
}

# 重启服务
restart_service() {
    systemctl restart anytls
    sleep 2
    if systemctl is-active --quiet anytls; then
        echo -e "${INFO} AnyTLS 服务已重启"
    else
        echo -e "${ERROR} AnyTLS 服务重启失败，请检查日志"
        journalctl -u anytls -n 20 --no-pager
    fi
}

# 获取 VPS 的公网 IP 地址
get_server_ip() {
    local ip
    ip=$(hostname -I | awk '{print $1}')
    echo "${ip:-无法获取IP}"
}

# 查看配置
view_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "${Cyan_font_prefix}AnyTLS 配置信息：${RESET}"
        cat "$CONFIG_FILE"
        
        # 读取配置参数
        local listen_port=$(grep '^listen_port=' "$CONFIG_FILE" | cut -d'=' -f2)
        local password=$(grep '^password=' "$CONFIG_FILE" | cut -d'=' -f2)
        local sni=$(grep '^sni=' "$CONFIG_FILE" | cut -d'=' -f2)
        local insecure=$(grep '^insecure=' "$CONFIG_FILE" | cut -d'=' -f2)
        local server_ip=$(get_server_ip)
        
        # 构造 AnyTLS URI
        local uri="anytls://${password}@${server_ip}:${listen_port}/?"
        if [[ -n "$sni" ]]; then
            uri="${uri}sni=${sni}"
            [[ "$insecure" == "1" ]] && uri="${uri}&insecure=1" || uri="${uri}&insecure=0"
        else
            uri="${uri}insecure=${insecure}"
        fi
        echo -e "\n${Yellow_font_prefix}[提示] SNI 默认设置为本机 IP，insecure 默认启用${RESET}"
        echo -e "${Cyan_font_prefix}AnyTLS URI：${RESET}"
        echo -e "${Yellow_font_prefix}${uri}${RESET}"
    else
        echo -e "${ERROR} 未找到配置文件，请先安装 AnyTLS"
    fi
}

# 修改配置
set_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${ERROR} 未找到配置文件，请先安装 AnyTLS"
        return
    fi
    # 读取当前版本号和已有配置
    local current_version=$(grep '^version=' "$CONFIG_FILE" | cut -d'=' -f2)
    SNI=$(grep '^sni=' "$CONFIG_FILE" | cut -d'=' -f2)
    INSECURE=$(grep '^insecure=' "$CONFIG_FILE" | cut -d'=' -f2)
    echo -e "你要修改什么？\n1. 修改监听端口\n2. 修改密码\n3. 修改全部配置"
    read -rp "选择操作: " choice
    case "$choice" in
        1)
            configure_port
            ;;
        2)
            configure_password
            ;;
        3)
            configure_anytls
            ;;
        *)
            echo -e "${ERROR} 无效的选择"
            return
            ;;
    esac
    # 保存配置时保留版本号、sni 和 insecure
    mkdir -p "${CONFIG_DIR}"
    cat > "$CONFIG_FILE" <<EOF
listen_addr=${LISTEN_ADDR}
listen_port=${LISTEN_PORT}
password=${PASSWORD}
version=${current_version}
sni=${SNI}
insecure=${INSECURE}
EOF
    echo -e "${INFO} 配置已更新至 ${CONFIG_FILE}"
    create_or_update_service
    restart_service
}

configure_port() {
    local input_port
    while true; do
        read -rp "请输入新的监听端口 (当前: ${LISTEN_PORT}): " input_port
        if ! [[ "$input_port" =~ ^[0-9]+$ ]] || [ "$input_port" -lt 1 ] || [ "$input_port" -gt 65535 ]; then
            echo -e "${ERROR} 端口号必须是 1-65535 之间的数字"
        elif check_port_in_use "$input_port"; then
            echo -e "${ERROR} 端口 ${input_port} 已被占用，请选择其他端口"
        else
            LISTEN_PORT="$input_port"
            break
        fi
    done
}

configure_password() {
    read -rp "请输入新的 AnyTLS 密码 (留空则自动生成): " input_password
    if [[ -z "$input_password" ]]; then
        PASSWORD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 16)
        echo -e "${Cyan_font_prefix}自动生成的密码为: ${PASSWORD}${RESET}"
    else
        PASSWORD="$input_password"
    fi
}

# 卸载 AnyTLS
uninstall_anytls() {
    echo -e "${WARNING} 正在卸载 AnyTLS..."
    read -rp "确认卸载吗？(y/n): " confirm
    if [[ "${confirm,,}" == "y" ]]; then
        systemctl stop anytls
        systemctl disable anytls
        rm -f "${INSTALL_DIR}/${BINARY_NAME}"
        rm -rf "${CONFIG_DIR}"
        rm -f "${SERVICE_FILE}"
        systemctl daemon-reload
        echo -e "${INFO} AnyTLS 已成功卸载"
    else
        echo -e "${WARNING} 取消卸载"
    fi
}

# 升级 AnyTLS
upgrade_anytls() {
    local current_version latest_version
    # 从配置文件读取当前版本
    if [[ -f "$CONFIG_FILE" ]]; then
        current_version=$(grep '^version=' "$CONFIG_FILE" | cut -d'=' -f2)
        current_version=${current_version:-"未知"}
    else
        current_version="未安装"
    fi
    latest_version=$(get_latest_version)

    if [[ "$current_version" == "$latest_version" ]]; then
        echo -e "${INFO} 当前已是最新版本 ($current_version)，无需升级。"
    else
        echo -e "${INFO} 检测到新版本：当前版本 $current_version，最新版本 $latest_version。"
        read -rp "是否升级到最新版本？(y/n): " choice
        if [[ "${choice,,}" == "y" ]]; then
            echo -e "${INFO} 正在升级 AnyTLS..."
            systemctl stop anytls
            download_anytls  # 下载新版本并更新 VERSION
            save_config      # 更新配置文件中的版本号
            create_or_update_service
            systemctl start anytls
            if systemctl is-active --quiet anytls; then
                echo -e "${INFO} AnyTLS 已成功升级并启动"
            else
                echo -e "${ERROR} AnyTLS 升级后启动失败，请检查日志"
                journalctl -u anytls -n 20 --no-pager
            fi
        else
            echo -e "${WARNING} 取消升级"
        fi
    fi
}

# 安装 AnyTLS
install_anytls() {
    install_tools
    download_anytls  # VERSION 会被设置为全局变量
    configure_anytls
    save_config      # 保存配置时包含版本号
    create_or_update_service
    start_service
}

# 主菜单（与 shadowtls_manager 结构一致）
main_menu() {
    while true; do
        clear
        echo -e "\n${Cyan_font_prefix}AnyTLS 管理菜单${RESET}"
        echo -e "=================================="
        echo -e " 安装与更新"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}1. 安装 AnyTLS${RESET}"
        echo -e "${Yellow_font_prefix}2. 升级 AnyTLS${RESET}"
        echo -e "${Yellow_font_prefix}3. 卸载 AnyTLS${RESET}"
        echo -e "=================================="
        echo -e " 配置管理"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}4. 查看 AnyTLS 配置信息${RESET}"
        echo -e "${Yellow_font_prefix}5. 修改 AnyTLS 配置${RESET}"
        echo -e "=================================="
        echo -e " 服务控制"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}6. 启动 AnyTLS${RESET}"
        echo -e "${Yellow_font_prefix}7. 停止 AnyTLS${RESET}"
        echo -e "${Yellow_font_prefix}8. 重启 AnyTLS${RESET}"
        echo -e "=================================="
        echo -e " 退出"
        echo -e "=================================="
        echo -e "${Yellow_font_prefix}0. 退出${RESET}"
        
        # 检测 AnyTLS 运行状态
        if [[ -e "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
            if systemctl is-active --quiet anytls; then
                echo -e " 当前状态：${Green_font_prefix}已安装并已启动${RESET}"
            else
                echo -e " 当前状态：${Green_font_prefix}已安装${RESET} 但 ${Red_font_prefix}未启动${RESET}"
            fi
        else
            echo -e " 当前状态：${Red_font_prefix}未安装${RESET}"
        fi
        
        read -rp "请选择操作 [0-8]: " choice
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
            *) echo -e "${ERROR} 无效的选择" ;;
        esac
        echo -e "\n按任意键返回主菜单..."
        read -n1 -s
    done
}

# 执行主菜单
check_root
main_menu