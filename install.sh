#!/bin/bash

# OpenVPN 自动安装脚本
# 基于 install.md 文档中的步骤自动化安装和配置 OpenVPN 服务器
# 支持 Ubuntu/Debian 和 CentOS/RHEL 系统
#
# 版本: 1.13
# 最后更新: 2025-05-25
#
# 更新日志:
# - 1.13:
#   - 增强卸载功能，确保完全清理所有OpenVPN相关文件和配置
#   - 改进卸载过程，删除所有OpenVPN相关文件和配置
#   - 增强防火墙规则清理，移除所有网络接口上的相关规则
#   - 添加系统服务文件和网络接口脚本的清理
#   - 添加IP转发设置的恢复
#   - 添加客户端配置文件、运行时文件和TUN/TAP设备的清理
#   - 添加备份文件和临时文件的清理
#   - 更新文档以反映增强的卸载功能
# - 1.12:
#   - 增强ta.key文件处理和连接可靠性
#   - 改进ta.key文件验证和生成流程，防止自动重新生成导致的连接问题
#   - 添加"更新客户端ta.key"功能，解决客户端与服务器ta.key不匹配问题
#   - 添加连接问题诊断功能，帮助识别和解决ta.key不匹配等连接问题
#   - 优化连接流程，提高连接成功率
#   - 添加ta.key更新提示，确保用户知道何时需要更新客户端配置
# - 1.11:
#   - 跳过OpenVPN配置文件验证，忽略压缩和ta.key相关警告
#   - 简化服务启动流程，提高稳定性
# - 1.10:
#   - 修复配置文件验证失败问题
#   - 添加topology subnet选项，解决拓扑警告
#   - 增强ta.key文件处理，自动检测并重新生成
#   - 改进配置验证功能
# - 1.9:
#   - 提高与OpenVPN 2.6.12版本的兼容性
#   - 移除不再支持的ncp-disable选项
#   - 更新文档中的相关描述
#   - 确保服务器和客户端配置的一致性
# - 1.8:
#   - 增强脚本的错误处理和诊断能力
#   - 添加配置文件验证功能
#   - 提高与不同OpenVPN版本的兼容性
#   - 优化服务启动流程
#   - 改进客户端配置生成
# - 1.7:
#   - 优化脚本性能和可靠性
#   - 增强脚本的灵活性和功能
#   - 改进用户交互体验
#   - 增强安全性选项
#   - 添加高级网络配置选项
# - 1.6:
#   - 添加功能：安装时可以手动选择 UDP/TCP 传输协议
#   - 添加功能：检测已安装状态并提供三个选项（生成新配置、修复安装、完全卸载）
#   - 更新文档以反映新功能
# - 1.5:
#   - 添加功能：客户端配置文件默认保存在当前脚本执行目录
#   - 添加功能：支持自定义生成的配置文件名称
#   - 更新文档以反映新功能
# - 1.4:
#   - 增强防火墙配置，确保 OpenVPN 端口在所有防火墙系统中正确开启
#   - 添加防火墙端口检查，避免重复规则
# - 1.3:
#   - 修复证书生成过程中的确认输入问题
#   - 优化脚本行尾为 Linux 风格 (LF)
# - 1.2:
#   - 添加已存在 OpenVPN 安装检查
#   - 添加所有用户输入参数的验证
#   - 添加错误处理和清理机制
#   - 改进脚本的幂等性，支持多次运行
#   - 添加信号处理以确保清理
# - 1.1: 
#   - 添加客户端名称参数验证
#   - 修复网络接口硬编码问题，动态检测主网络接口
#   - 修复 UFW 配置中的网络接口硬编码
#   - 添加客户端证书和密钥文件存在性检查
#   - 改进客户端配置生成，从服务器配置中读取实际设置
#   - 添加必要命令检查和自动安装缺失命令

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

# 日志文件
LOG_FILE="/var/log/openvpn-install.log"

# 失败命令日志
FAILED_COMMANDS=""

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 默认设置
PORT=1194
PROTOCOL=udp
PROTOCOL_SET_BY_ARG=false
DNS1="8.8.8.8"
DNS2="8.8.4.4"
CIPHER="AES-256-CBC"
AUTH="SHA256"
COMPRESS="lz4-v2"
SERVER_NAME="server"
CLIENT_NAME="client1"
VPN_SUBNET="10.8.0.0"
VPN_NETMASK="255.255.255.0"
OUTPUT_DIR="$SCRIPT_DIR"  # 默认输出目录为脚本所在目录
OUTPUT_FILE=""  # 默认输出文件名为空，将使用客户端名称
OUTPUT_FILE_SET_BY_ARG=false
MOBILE_DEVICE=false  # 默认为桌面端配置

# 高级设置
TLS_VERSION="1.2"  # TLS 版本 (1.2, 1.3)
KEEPALIVE_PING=10  # 保持连接 ping 间隔（秒）
KEEPALIVE_TIMEOUT=120  # 保持连接超时（秒）
LOG_LEVEL=3  # 日志级别 (0-9)，0 为静默，9 为最详细
ENABLE_IPV6=false  # 是否启用 IPv6 支持
MAX_CLIENTS=100  # 最大客户端连接数
DUPLICATE_CN=false  # 是否允许重复的 Common Name
PUSH_BLOCK_DNS=false  # 是否阻止 DNS 泄漏
CLIENT_TO_CLIENT=false  # 是否允许客户端之间通信

# 临时文件和目录
TEMP_DIR=""

# 函数: 清理临时文件和中断的安装
cleanup() {
    log "${BLUE}执行清理操作...${NC}"

    # 如果存在临时目录，则删除
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
        log "${GREEN}已删除临时目录${NC}"
    fi

    log "${GREEN}清理完成${NC}"
}

# 设置信号处理
trap cleanup EXIT INT TERM

# 函数: 显示帮助信息
show_help() {
    echo -e "${BLUE}OpenVPN 自动安装脚本${NC}"
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help                显示此帮助信息"
    echo "  -p, --port PORT           设置 OpenVPN 端口 (默认: 1194)"
    echo "  -t, --protocol            设置协议 (仅支持UDP，为避免中国运营商封锁)"
    echo "  -c, --client NAME         设置客户端名称 (默认: client1)"
    echo "  -d, --dns DNS1,DNS2       设置 DNS 服务器 (默认: 8.8.8.8,8.8.4.4)"
    echo "  -s, --subnet SUBNET       设置 VPN 子网 (默认: 10.8.0.0)"
    echo "  -m, --netmask NETMASK     设置 VPN 子网掩码 (默认: 255.255.255.0)"
    echo "  -e, --cipher CIPHER       设置加密算法 (默认: AES-256-CBC)"
    echo "  -a, --auth AUTH           设置认证算法 (默认: SHA256)"
    echo "  -o, --output-dir DIR      设置客户端配置文件输出目录 (默认: 脚本所在目录)"
    echo "  -f, --output-file FILE    设置客户端配置文件名称 (默认: <客户端名称>.ovpn)"
    echo ""
    echo "高级选项:"
    echo "  --tls-version VERSION     设置 TLS 版本 (1.2, 1.3) (默认: 1.2)"
    echo "  --keepalive PING,TIMEOUT  设置保持连接参数 (默认: 10,120)"
    echo "  --log-level LEVEL         设置日志级别 (0-9) (默认: 3)"
    echo "  --enable-ipv6             启用 IPv6 支持"
    echo "  --max-clients NUMBER      设置最大客户端连接数 (默认: 100)"
    echo "  --duplicate-cn            允许重复的 Common Name (多个客户端使用同一个证书)"
    echo "  --push-block-dns          阻止 DNS 泄漏"
    echo "  --client-to-client        允许客户端之间通信"
    echo "  --mobile-device           生成移动设备专用配置 (避免使用不支持的 fragment 指令)"
    echo ""
    echo "示例:"
    echo "  $0 --port 12345 --client myvpn"
    echo "  $0 --client myvpn --output-dir /home/user --output-file config.ovpn"
    echo "  $0 --tls-version 1.3 --keepalive 10,60 --enable-ipv6 --client-to-client"
    echo ""
    echo "功能说明:"
    echo "  1. 脚本默认使用UDP协议，并推荐使用随机端口以避免中国运营商封锁"
    echo "  2. 如果检测到 OpenVPN 已安装，脚本将显示以下菜单选项:"
    echo "     - 生成新的客户端配置文件"
    echo "     - 修复当前安装"
    echo "     - 完全卸载 OpenVPN"
    echo ""
}

# 函数: 记录日志
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# 函数: 执行命令并记录失败
run_cmd() {
    local cmd="$1"
    local desc="$2"

    # 执行命令
    eval "$cmd"
    local status=$?

    # 如果命令失败，记录到失败命令日志
    if [ $status -ne 0 ]; then
        local error_msg="${RED}命令失败: ${desc}${NC}"
        log "$error_msg"
        FAILED_COMMANDS="${FAILED_COMMANDS}• ${desc} (命令: $cmd)\n"
        return 1
    fi

    return 0
}

# 函数: 检查 IP 转发是否启用，如果未启用则自动启用
check_ip_forwarding() {
    log "${BLUE}检查 IP 转发是否启用...${NC}"

    # 检查当前 IP 转发状态
    local ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)

    if [ "$ip_forward" = "1" ]; then
        log "${GREEN}IP 转发已启用${NC}"
        return 0
    else
        log "${YELLOW}IP 转发未启用，尝试自动启用...${NC}"

        # 立即启用 IP 转发（两种方法）
        log "${BLUE}立即启用 IP 转发...${NC}"
        # 使用 bash -c 来确保重定向正确处理
        run_cmd "bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'" "直接写入 /proc/sys/net/ipv4/ip_forward" || {
            log "${YELLOW}警告: 无法直接写入 /proc/sys/net/ipv4/ip_forward，尝试使用 sysctl 命令${NC}"
        }

        run_cmd "sysctl -w net.ipv4.ip_forward=1" "使用 sysctl 命令设置 IP 转发" || {
            log "${YELLOW}警告: 使用 sysctl 命令设置 IP 转发失败${NC}"
        }

        # 确保重启后依然生效
        if ! grep -q "^net.ipv4.ip_forward\s*=\s*1" /etc/sysctl.conf; then
            log "${BLUE}在 /etc/sysctl.conf 中添加 IP 转发设置...${NC}"
            echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
        fi

        # 应用设置
        log "${BLUE}应用 IP 转发设置...${NC}"
        run_cmd "sysctl -p" "应用 IP 转发设置" || {
            log "${YELLOW}警告: 无法通过 sysctl -p 应用设置${NC}"
        }

        # 再次检查是否已启用
        ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
        if [ "$ip_forward" = "1" ]; then
            log "${GREEN}IP 转发已成功启用${NC}"
            return 0
        else
            log "${RED}尝试启用 IP 转发失败${NC}"
            FAILED_COMMANDS="${FAILED_COMMANDS}• 尝试启用 IP 转发失败，请手动检查系统配置\n"
            return 1
        fi
    fi
}

# 函数: 错误处理
error_exit() {
    log "${RED}错误: $1${NC}"
    exit 1
}

# 函数: 验证输入参数
validate_inputs() {
    log "${BLUE}验证输入参数...${NC}"

    # 验证端口号
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        error_exit "端口号必须是 1-65535 之间的数字"
    fi

    # 验证协议
    if [[ "$PROTOCOL" != "udp" && "$PROTOCOL" != "tcp" ]]; then
        error_exit "协议必须是 udp 或 tcp"
    fi

    # 验证客户端名称 (只允许字母、数字、下划线和连字符)
    if ! [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        error_exit "客户端名称只能包含字母、数字、下划线和连字符"
    fi

    # 验证 DNS 服务器
    if ! [[ "$DNS1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error_exit "DNS1 必须是有效的 IP 地址"
    fi

    if ! [[ "$DNS2" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error_exit "DNS2 必须是有效的 IP 地址"
    fi

    # 验证子网
    if ! [[ "$VPN_SUBNET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error_exit "VPN 子网必须是有效的 IP 地址"
    fi

    # 验证子网掩码
    if ! [[ "$VPN_NETMASK" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error_exit "VPN 子网掩码必须是有效的 IP 地址格式"
    fi

    # 验证输出目录
    if [ ! -d "$OUTPUT_DIR" ]; then
        log "${YELLOW}警告: 输出目录 $OUTPUT_DIR 不存在，将尝试创建${NC}"
        mkdir -p "$OUTPUT_DIR" || error_exit "无法创建输出目录: $OUTPUT_DIR"
    fi

    # 验证输出目录是否可写
    if [ ! -w "$OUTPUT_DIR" ]; then
        error_exit "输出目录 $OUTPUT_DIR 不可写"
    fi

    # 如果指定了输出文件名，验证文件名是否合法
    if [ -n "$OUTPUT_FILE" ]; then
        if [[ "$OUTPUT_FILE" != *.ovpn ]]; then
            log "${YELLOW}警告: 输出文件名 $OUTPUT_FILE 没有 .ovpn 扩展名，将自动添加${NC}"
            OUTPUT_FILE="${OUTPUT_FILE}.ovpn"
        fi
    fi

    # 验证 TLS 版本
    if [[ "$TLS_VERSION" != "1.2" && "$TLS_VERSION" != "1.3" ]]; then
        error_exit "TLS 版本必须是 1.2 或 1.3"
    fi

    # 验证保持连接参数
    if ! [[ "$KEEPALIVE_PING" =~ ^[0-9]+$ ]] || [ "$KEEPALIVE_PING" -lt 1 ]; then
        error_exit "保持连接 ping 间隔必须是大于 0 的数字"
    fi

    if ! [[ "$KEEPALIVE_TIMEOUT" =~ ^[0-9]+$ ]] || [ "$KEEPALIVE_TIMEOUT" -lt 1 ]; then
        error_exit "保持连接超时必须是大于 0 的数字"
    fi

    # 验证日志级别
    if ! [[ "$LOG_LEVEL" =~ ^[0-9]$ ]] || [ "$LOG_LEVEL" -lt 0 ] || [ "$LOG_LEVEL" -gt 9 ]; then
        error_exit "日志级别必须是 0-9 之间的数字"
    fi

    # 验证最大客户端连接数
    if ! [[ "$MAX_CLIENTS" =~ ^[0-9]+$ ]] || [ "$MAX_CLIENTS" -lt 1 ]; then
        error_exit "最大客户端连接数必须是大于 0 的数字"
    fi

    # 验证布尔值选项
    if [[ "$ENABLE_IPV6" != "true" && "$ENABLE_IPV6" != "false" ]]; then
        error_exit "ENABLE_IPV6 必须是 true 或 false"
    fi

    if [[ "$DUPLICATE_CN" != "true" && "$DUPLICATE_CN" != "false" ]]; then
        error_exit "DUPLICATE_CN 必须是 true 或 false"
    fi

    if [[ "$PUSH_BLOCK_DNS" != "true" && "$PUSH_BLOCK_DNS" != "false" ]]; then
        error_exit "PUSH_BLOCK_DNS 必须是 true 或 false"
    fi

    if [[ "$CLIENT_TO_CLIENT" != "true" && "$CLIENT_TO_CLIENT" != "false" ]]; then
        error_exit "CLIENT_TO_CLIENT 必须是 true 或 false"
    fi

    log "${GREEN}输入参数验证通过${NC}"
}

# 函数: 检查是否为 root 用户
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error_exit "此脚本必须以 root 用户身份运行。请使用 sudo 或切换到 root 用户。"
    fi
}

# 函数: 检查必要的命令是否可用
check_commands() {
    log "${BLUE}检查必要的命令...${NC}"

    local required_commands=("ip" "curl" "grep" "awk" "sed")
    local missing_commands=()

    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_commands+=("$cmd")
        fi
    done

    if [ ${#missing_commands[@]} -ne 0 ]; then
        log "${YELLOW}警告: 以下命令不可用: ${missing_commands[*]}${NC}"
        log "${YELLOW}尝试安装缺失的命令...${NC}"

        if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
            apt update -y
            apt install -y iproute2 curl grep gawk sed
        elif [[ "$OS" == "centos" ]]; then
            yum install -y iproute curl grep gawk sed
        fi

        # 再次检查
        missing_commands=()
        for cmd in "${required_commands[@]}"; do
            if ! command -v "$cmd" &>/dev/null; then
                missing_commands+=("$cmd")
            fi
        done

        if [ ${#missing_commands[@]} -ne 0 ]; then
            error_exit "无法安装必要的命令: ${missing_commands[*]}"
        fi
    fi

    log "${GREEN}所有必要的命令都可用${NC}"
}

# 函数: 检测操作系统
detect_os() {
    if [ -f /etc/debian_version ]; then
        OS="debian"
        if [ -f /etc/lsb-release ]; then
            OS="ubuntu"
        fi
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
    else
        error_exit "不支持的操作系统。此脚本仅支持 Ubuntu、Debian 和 CentOS/RHEL。"
    fi
    log "${GREEN}检测到操作系统: $OS${NC}"
}

# 函数: 检查 OpenVPN 是否已安装并显示菜单
check_openvpn_installed() {
    log "${BLUE}检查 OpenVPN 是否已安装...${NC}"

    # 检查 OpenVPN 是否已安装
    if command -v openvpn &>/dev/null; then
        log "${YELLOW}检测到 OpenVPN 已安装${NC}"

        # 显示菜单
        echo -e "${BLUE}OpenVPN 已安装在此系统上。请选择操作:${NC}"
        echo "1) 生成新的客户端配置文件"
        echo "2) 更新客户端ta.key"
        echo "3) 诊断连接问题"
        echo "4) 修复当前安装"
        echo "5) 重启 OpenVPN 服务"
        echo "6) 查看服务器信息"
        echo "7) 查看 VPN 实时状态"
        echo "8) 完全卸载 OpenVPN"
        echo "9) 退出"

        # 检查是否存在ta.key更新标记
        if [ -f "/etc/openvpn/ta.key.updated" ]; then
            echo -e "${YELLOW}注意: 检测到ta.key已被更新，建议使用选项2更新客户端配置${NC}"
        fi

        while true; do
            echo -n "请输入选项 [1-9]: "
            read -r option

            case $option in
                1)
                    # 生成新的客户端配置文件
                    generate_new_client
                    exit 0
                    ;;
                2)
                    # 更新客户端ta.key
                    update_client_ta_key
                    # 返回菜单
                    check_openvpn_installed
                    exit 0
                    ;;
                3)
                    # 诊断连接问题
                    diagnose_connection_issues
                    # 返回菜单
                    check_openvpn_installed
                    exit 0
                    ;;
                4)
                    # 修复当前安装
                    repair_installation
                    exit 0
                    ;;
                5)
                    # 重启 OpenVPN 服务
                    detect_os
                    restart_openvpn
                    exit 0
                    ;;
                6)
                    # 查看服务器信息
                    detect_os
                    show_server_info
                    # 返回菜单
                    check_openvpn_installed
                    exit 0
                    ;;
                7)
                    # 查看 VPN 实时状态
                    detect_os
                    show_vpn_status
                    # 返回菜单
                    check_openvpn_installed
                    exit 0
                    ;;
                8)
                    # 完全卸载 OpenVPN
                    uninstall_openvpn
                    exit 0
                    ;;
                9)
                    log "${GREEN}用户选择退出${NC}"
                    exit 0
                    ;;
                *)
                    echo -e "${RED}无效选项，请重新输入${NC}"
                    ;;
            esac
        done
    else
        log "${GREEN}OpenVPN 未安装${NC}"
        # 继续安装流程
    fi
}

# 函数: 更新客户端ta.key
update_client_ta_key() {
    log "${BLUE}开始更新客户端ta.key...${NC}"

    # 检查ta.key是否存在
    if [ ! -f "/etc/openvpn/ta.key" ]; then
        log "${RED}错误: ta.key文件不存在，无法更新客户端配置${NC}"
        return 1
    fi

    # 检查客户端配置目录
    local client_configs_dir="/etc/openvpn/client-configs"
    if [ ! -d "$client_configs_dir" ]; then
        log "${RED}错误: 客户端配置目录不存在${NC}"
        return 1
    fi

    # 获取现有客户端列表
    local clients=()
    local client_certs=()

    # 从证书目录获取客户端列表
    if [ -d "/etc/openvpn/easy-rsa/pki/issued" ]; then
        for cert in /etc/openvpn/easy-rsa/pki/issued/*.crt; do
            if [ -f "$cert" ]; then
                local client_name=$(basename "$cert" .crt)
                if [ "$client_name" != "server" ] && [ "$client_name" != "$SERVER_NAME" ]; then
                    client_certs+=("$client_name")
                fi
            fi
        done
    fi

    if [ ${#client_certs[@]} -eq 0 ]; then
        log "${RED}错误: 未找到任何客户端证书${NC}"
        return 1
    fi

    # 显示客户端列表
    echo -e "${BLUE}找到以下客户端证书:${NC}"
    for i in "${!client_certs[@]}"; do
        echo "$((i+1))) ${client_certs[$i]}"
    done
    echo "$((${#client_certs[@]}+1))) 更新所有客户端"
    echo "$((${#client_certs[@]}+2))) 返回主菜单"

    # 提示用户选择要更新的客户端
    echo -n "请选择要更新的客户端 [1-$((${#client_certs[@]}+2))]: "
    read -r client_choice

    # 验证用户输入
    if ! [[ "$client_choice" =~ ^[0-9]+$ ]] || [ "$client_choice" -lt 1 ] || [ "$client_choice" -gt $((${#client_certs[@]}+2)) ]; then
        log "${RED}错误: 无效的选择${NC}"
        return 1
    fi

    # 如果用户选择返回主菜单
    if [ "$client_choice" -eq $((${#client_certs[@]}+2)) ]; then
        return 0
    fi

    # 使用脚本目录作为默认输出目录
    OUTPUT_DIR="$SCRIPT_DIR"

    # 验证输出目录是否可写
    if [ ! -w "$OUTPUT_DIR" ]; then
        error_exit "输出目录 $OUTPUT_DIR 不可写"
    fi

    # 更新选定的客户端或所有客户端
    if [ "$client_choice" -eq $((${#client_certs[@]}+1)) ]; then
        # 更新所有客户端
        log "${BLUE}更新所有客户端配置...${NC}"
        local updated_count=0

        for client in "${client_certs[@]}"; do
            log "${BLUE}更新客户端 ${client}...${NC}"
            OUTPUT_FILE="${client}.ovpn"

            # 生成新的客户端配置
            if /etc/openvpn/make_client_config.sh "$client" "$OUTPUT_DIR" "$OUTPUT_FILE" false; then
                log "${GREEN}成功更新客户端 ${client}${NC}"
                updated_count=$((updated_count+1))
            else
                log "${RED}更新客户端 ${client} 失败${NC}"
            fi
        done

        log "${GREEN}已成功更新 ${updated_count}/${#client_certs[@]} 个客户端配置${NC}"
    else
        # 更新选定的客户端
        local selected_client="${client_certs[$((client_choice-1))]}"
        log "${BLUE}更新客户端 ${selected_client}...${NC}"

        # 提示用户输入输出文件名
        echo -n "请输入配置文件名称 [${selected_client}.ovpn]: "
        read -r output_file

        # 如果用户未输入，使用默认值
        if [ -z "$output_file" ]; then
            output_file="${selected_client}.ovpn"
        elif [[ "$output_file" != *.ovpn ]]; then
            output_file="${output_file}.ovpn"
        fi

        # 生成新的客户端配置
        if /etc/openvpn/make_client_config.sh "$selected_client" "$OUTPUT_DIR" "$output_file" false; then
            log "${GREEN}成功更新客户端 ${selected_client}${NC}"
            log "${GREEN}配置文件已保存到: ${OUTPUT_DIR}/${output_file}${NC}"
        else
            log "${RED}更新客户端 ${selected_client} 失败${NC}"
            return 1
        fi
    fi

    log "${YELLOW}重要提示: 请将更新后的配置文件分发给相应的客户端，替换旧的配置文件${NC}"
    log "${YELLOW}客户端必须使用新的配置文件才能连接到服务器${NC}"

    # 等待用户按任意键继续
    echo -e "\n按任意键返回主菜单..."
    read -n 1 -s
    return 0
}

# 函数: 生成新的客户端配置文件
generate_new_client() {
    log "${BLUE}开始生成新的客户端配置文件...${NC}"

    # 提示用户输入客户端名称
    echo -n "请输入新客户端名称 [client2]: "
    read -r new_client_name

    # 如果用户未输入，使用默认值
    if [ -z "$new_client_name" ]; then
        new_client_name="client2"
    fi

    # 验证客户端名称
    if ! [[ "$new_client_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log "${RED}错误: 客户端名称只能包含字母、数字、下划线和连字符${NC}"
        exit 1
    fi

    # 设置客户端名称
    CLIENT_NAME="$new_client_name"

    # 使用脚本目录作为默认输出目录
    OUTPUT_DIR="$SCRIPT_DIR"

    # 验证输出目录是否可写
    if [ ! -w "$OUTPUT_DIR" ]; then
        error_exit "输出目录 $OUTPUT_DIR 不可写"
    fi

    # 提示用户输入输出文件名
    echo -n "请输入配置文件名称 [${new_client_name}.ovpn]: "
    read -r output_file

    # 如果用户未输入，使用默认值
    if [ -z "$output_file" ]; then
        output_file="${new_client_name}.ovpn"
    elif [[ "$output_file" != *.ovpn ]]; then
        output_file="${output_file}.ovpn"
    fi

    # 设置输出文件名
    OUTPUT_FILE="$output_file"

    # 询问是否为移动设备生成配置
    echo -n "是否为移动设备生成配置？(避免使用不支持的 fragment 指令) [y/N]: "
    read -r mobile_choice
    if [[ "$mobile_choice" =~ ^[Yy]$ ]]; then
        MOBILE_DEVICE=true
        log "${BLUE}将生成移动设备专用配置 (不包含 fragment 指令)${NC}"
    else
        MOBILE_DEVICE=false
        log "${BLUE}将生成标准桌面端配置${NC}"
    fi

    # 生成客户端证书和配置
    cd /etc/openvpn/easy-rsa/ || error_exit "无法进入 easy-rsa 目录"
    echo "yes" | ./easyrsa build-client-full "$CLIENT_NAME" nopass || error_exit "生成客户端证书失败"

    # 生成客户端配置文件
    /etc/openvpn/make_client_config.sh "$CLIENT_NAME" "$OUTPUT_DIR" "$OUTPUT_FILE" "$MOBILE_DEVICE" || error_exit "生成客户端配置失败"

    # 确定最终的输出文件名
    FINAL_OUTPUT_FILE="$OUTPUT_FILE"
    if [ -z "$FINAL_OUTPUT_FILE" ]; then
        FINAL_OUTPUT_FILE="${CLIENT_NAME}.ovpn"
    fi

    log "${GREEN}客户端证书和配置生成完成${NC}"
    log "${GREEN}客户端配置文件位置: ${OUTPUT_DIR}/${FINAL_OUTPUT_FILE}${NC}"
}

# 函数: 修复当前安装
repair_installation() {
    log "${BLUE}开始修复 OpenVPN 安装...${NC}"

    # 停止 OpenVPN 服务
    log "${BLUE}停止 OpenVPN 服务...${NC}"
    systemctl stop openvpn@server

    # 备份现有配置
    if [ -d /etc/openvpn ]; then
        BACKUP_DIR="/etc/openvpn.bak.$(date +%Y%m%d%H%M%S)"
        log "${BLUE}备份现有配置到 $BACKUP_DIR...${NC}"
        cp -r /etc/openvpn "$BACKUP_DIR"
    fi

    # 检查并修复常见问题

    # 1. 检查并修复权限问题
    log "${BLUE}检查并修复权限问题...${NC}"
    chmod 755 /etc/openvpn
    chmod 644 /etc/openvpn/server.conf
    chmod 600 /etc/openvpn/*.key
    chmod 644 /etc/openvpn/*.crt
    chmod 644 /etc/openvpn/dh.pem

    # 2. 检查并修复网络配置
    log "${BLUE}检查并修复网络配置...${NC}"

    # 确保 IP 转发已启用
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
        run_cmd "sysctl -p" "应用 IP 转发设置" || log "${YELLOW}警告: 无法应用 sysctl 设置${NC}"
    fi

    # 检查 IP 转发是否已启用
    check_ip_forwarding

    # 检查并修复防火墙规则
    log "${BLUE}检查并修复防火墙规则...${NC}"

    # 获取当前配置的端口和协议
    if [ -f "/etc/openvpn/server.conf" ]; then
        CURRENT_PORT=$(grep -E "^port " /etc/openvpn/server.conf | awk '{print $2}')
        CURRENT_PROTOCOL=$(grep -E "^proto " /etc/openvpn/server.conf | awk '{print $2}')

        if [ -n "$CURRENT_PORT" ] && [ -n "$CURRENT_PROTOCOL" ]; then
            # 使用当前配置的端口和协议
            PORT="$CURRENT_PORT"
            PROTOCOL="$CURRENT_PROTOCOL"

            # 检查端口是否已开放
            if ! check_port_open "$PORT" "$PROTOCOL"; then
                log "${YELLOW}端口 $PORT/$PROTOCOL 未开放，正在配置防火墙规则...${NC}"
                configure_network
            fi
        fi
    fi

    # 3. 重新启动服务
    log "${BLUE}重新启动 OpenVPN 服务...${NC}"
    systemctl start openvpn@server
    systemctl enable openvpn@server

    # 检查服务状态
    if systemctl is-active --quiet openvpn@server; then
        log "${GREEN}OpenVPN 服务已成功启动${NC}"
    else
        log "${RED}警告: OpenVPN 服务未能启动，请检查日志${NC}"
    fi

    log "${GREEN}OpenVPN 修复完成${NC}"
}

# 函数: 完全卸载 OpenVPN
uninstall_openvpn() {
    log "${BLUE}开始卸载 OpenVPN...${NC}"

    # 确认卸载
    echo -e "${RED}警告: 这将完全卸载 OpenVPN 并删除所有相关文件和配置。${NC}"
    echo -e "${RED}此操作不可逆。${NC}"
    echo -n "确定要继续吗? [y/N]: "
    read -r confirm

    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log "${GREEN}用户取消卸载${NC}"
        exit 0
    fi

    # 停止 OpenVPN 服务
    log "${BLUE}停止 OpenVPN 服务...${NC}"
    systemctl stop openvpn@server 2>/dev/null
    systemctl disable openvpn@server 2>/dev/null

    # 停止所有 OpenVPN 服务实例
    log "${BLUE}停止所有 OpenVPN 服务实例...${NC}"
    for service in $(systemctl list-units --full --all | grep -F "openvpn" | awk '{print $1}'); do
        systemctl stop "$service" 2>/dev/null
        systemctl disable "$service" 2>/dev/null
        log "${GREEN}已停止并禁用服务: $service${NC}"
    done

    # 删除 OpenVPN 包
    log "${BLUE}删除 OpenVPN 软件包...${NC}"
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        apt purge -y openvpn easy-rsa
        apt autoremove -y
    elif [[ "$OS" == "centos" ]]; then
        yum remove -y openvpn easy-rsa
    fi

    # 删除配置文件和证书
    log "${BLUE}删除配置文件和证书...${NC}"
    rm -rf /etc/openvpn
    rm -rf /usr/share/easy-rsa

    # 删除客户端配置文件
    log "${BLUE}删除客户端配置文件...${NC}"
    # 检查脚本目录中的客户端配置文件
    if [ -d "$SCRIPT_DIR" ]; then
        find "$SCRIPT_DIR" -name "*.ovpn" -delete
        log "${GREEN}已删除脚本目录中的客户端配置文件${NC}"
    fi

    # 删除可能存在的其他客户端配置目录
    rm -rf /etc/openvpn/client-configs
    rm -rf /root/client-configs
    rm -rf /home/*/client-configs

    # 删除日志文件
    log "${BLUE}删除日志文件...${NC}"
    rm -rf /var/log/openvpn
    rm -f /var/log/openvpn*

    # 删除运行时文件
    log "${BLUE}删除运行时文件...${NC}"
    rm -rf /run/openvpn
    rm -f /run/openvpn*
    rm -f /var/run/openvpn*

    # 删除系统服务文件
    log "${BLUE}删除系统服务文件...${NC}"
    rm -f /lib/systemd/system/openvpn*.service
    rm -f /usr/lib/systemd/system/openvpn*.service
    rm -f /etc/systemd/system/openvpn*.service
    systemctl daemon-reload

    # 移除网络接口脚本
    log "${BLUE}移除网络接口脚本...${NC}"
    rm -f /etc/network/if-up.d/iptables

    # 移除 IP 转发设置
    log "${BLUE}移除 IP 转发设置...${NC}"
    if grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        sed -i '/^net.ipv4.ip_forward=1/d' /etc/sysctl.conf
        log "${GREEN}已从 /etc/sysctl.conf 中移除 IP 转发设置${NC}"
        # 应用更改
        sysctl -p
    fi

    # 移除防火墙规则
    log "${BLUE}移除防火墙规则...${NC}"

    # 检测所有网络接口
    log "${BLUE}检测所有网络接口...${NC}"
    ALL_INTERFACES=$(ip -o -4 addr show | awk '{print $2}' | grep -v "lo" | sort | uniq)

    # 获取当前配置的端口和协议（如果可能）
    if [ -f "/etc/openvpn/server.conf.bak" ]; then
        CURRENT_PORT=$(grep -E "^port " /etc/openvpn/server.conf.bak | awk '{print $2}')
        CURRENT_PROTOCOL=$(grep -E "^proto " /etc/openvpn/server.conf.bak | awk '{print $2}')
    else
        # 使用默认值
        CURRENT_PORT="1194"
        CURRENT_PROTOCOL="udp"
    fi

    # 获取可能的 VPN 子网
    VPN_SUBNETS=("10.8.0.0/24" "10.8.0.0/16" "192.168.255.0/24" "172.16.0.0/24")

    # 移除所有接口上的 iptables 规则
    for iface in $ALL_INTERFACES; do
        log "${BLUE}移除接口 $iface 上的 iptables 规则...${NC}"

        # 移除端口规则
        iptables -D INPUT -i $iface -p $CURRENT_PROTOCOL --dport $CURRENT_PORT -j ACCEPT 2>/dev/null

        # 移除 NAT 规则
        for subnet in "${VPN_SUBNETS[@]}"; do
            iptables -t nat -D POSTROUTING -s $subnet -o $iface -j MASQUERADE 2>/dev/null
            iptables -t nat -D POSTROUTING -s $subnet -j SNAT --to-source $(ip -4 addr show $iface | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1) 2>/dev/null
        done

        # 移除转发规则
        iptables -D FORWARD -i tun+ -o $iface -j ACCEPT 2>/dev/null
        iptables -D FORWARD -i $iface -o tun+ -j ACCEPT 2>/dev/null
        iptables -D FORWARD -i tun+ -o $iface -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
        iptables -D FORWARD -i $iface -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    done

    # 移除 tun 接口规则
    iptables -D INPUT -i tun+ -j ACCEPT 2>/dev/null
    iptables -D FORWARD -i tun+ -j ACCEPT 2>/dev/null

    # 保存 iptables 规则
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        if [ -d "/etc/iptables" ]; then
            iptables-save > /etc/iptables/rules.v4
            log "${GREEN}已保存 iptables 规则${NC}"
        fi
    elif [[ "$OS" == "centos" ]]; then
        if command -v service &>/dev/null; then
            service iptables save
            log "${GREEN}已保存 iptables 规则${NC}"
        fi
    fi

    # 移除 UFW 规则（如果存在）
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        log "${BLUE}移除 UFW 规则...${NC}"
        ufw delete allow $CURRENT_PORT/$CURRENT_PROTOCOL 2>/dev/null

        # 移除 UFW 中的 NAT 规则
        if grep -q "POSTROUTING -s" /etc/ufw/before.rules; then
            sed -i '/# NAT 表规则/,/COMMIT/d' /etc/ufw/before.rules
            log "${GREEN}已从 UFW 中移除 NAT 规则${NC}"
        fi

        # 恢复 UFW 默认转发策略
        sed -i 's/DEFAULT_FORWARD_POLICY="ACCEPT"/DEFAULT_FORWARD_POLICY="DROP"/g' /etc/default/ufw

        # 重启 UFW
        ufw disable
        ufw enable
        log "${GREEN}已重启 UFW${NC}"
    fi

    # 移除 firewalld 规则（如果存在）
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        log "${BLUE}移除 firewalld 规则...${NC}"
        firewall-cmd --permanent --remove-port=$CURRENT_PORT/$CURRENT_PROTOCOL 2>/dev/null
        firewall-cmd --permanent --remove-service=openvpn 2>/dev/null

        # 禁用 masquerade
        firewall-cmd --permanent --remove-masquerade 2>/dev/null

        # 重新加载 firewalld
        firewall-cmd --reload
        log "${GREEN}已重新加载 firewalld${NC}"
    fi

    # 清理可能存在的其他文件
    log "${BLUE}清理其他文件...${NC}"
    rm -f /etc/openvpn*.conf
    rm -f /etc/openvpn*.conf.bak
    rm -f /etc/openvpn*.key
    rm -f /etc/openvpn*.crt
    rm -f /etc/openvpn*.pem
    rm -f /etc/openvpn*.log
    rm -f /etc/openvpn*.status
    rm -f /etc/openvpn*.updated

    # 删除 iptables 配置目录
    rm -rf /etc/iptables
    rm -rf /etc/sysconfig/iptables.d

    # 删除备份文件
    find /etc -name "*openvpn*" -type f -delete
    find /var -name "*openvpn*" -type f -delete

    # 检查是否有残留的 tun 设备
    if ip link show | grep -q "tun"; then
        log "${BLUE}移除残留的 tun 设备...${NC}"
        for tun in $(ip link show | grep "tun" | awk -F: '{print $2}' | tr -d ' '); do
            ip link delete "$tun" 2>/dev/null
            log "${GREEN}已移除 tun 设备: $tun${NC}"
        done
    fi

    log "${GREEN}OpenVPN 已成功完全卸载${NC}"
}

# 函数: 安装依赖包
install_dependencies() {
    log "${BLUE}开始安装依赖包...${NC}"

    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        apt update || error_exit "无法更新软件包列表"
        apt upgrade -y || log "${YELLOW}警告: 系统更新失败，继续安装...${NC}"
        apt install -y openvpn easy-rsa net-tools iptables-persistent || error_exit "安装软件包失败"
    elif [[ "$OS" == "centos" ]]; then
        yum update -y || log "${YELLOW}警告: 系统更新失败，继续安装...${NC}"
        yum install -y epel-release || error_exit "安装 EPEL 仓库失败"
        yum install -y openvpn easy-rsa net-tools iptables-services || error_exit "安装软件包失败"
    fi

    log "${GREEN}依赖包安装完成${NC}"
}

# 函数: 设置 PKI 和证书
setup_pki() {
    log "${BLUE}开始设置 PKI 和证书...${NC}"

    # 创建 easy-rsa 目录
    mkdir -p /etc/openvpn/easy-rsa/

    # 复制 easy-rsa 文件
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/ || error_exit "复制 easy-rsa 文件失败"
    elif [[ "$OS" == "centos" ]]; then
        cp -r /usr/share/easy-rsa/3/* /etc/openvpn/easy-rsa/ || error_exit "复制 easy-rsa 文件失败"
    fi

    # 配置 vars 文件
    cd /etc/openvpn/easy-rsa/ || error_exit "无法进入 easy-rsa 目录"

    cat > vars << EOF
set_var EASYRSA_REQ_COUNTRY    "CN"
set_var EASYRSA_REQ_PROVINCE   "Beijing"
set_var EASYRSA_REQ_CITY       "Beijing"
set_var EASYRSA_REQ_ORG        "My Organization"
set_var EASYRSA_REQ_EMAIL      "admin@example.com"
set_var EASYRSA_REQ_OU         "IT Department"
set_var EASYRSA_KEY_SIZE       2048
set_var EASYRSA_ALGO           rsa
set_var EASYRSA_CA_EXPIRE      3650
set_var EASYRSA_CERT_EXPIRE    3650
EOF

    # 初始化 PKI
    ./easyrsa init-pki || error_exit "初始化 PKI 失败"

    # 创建 CA 证书 (使用 expect 自动回答提示)
    echo "yes" | ./easyrsa build-ca nopass || error_exit "创建 CA 证书失败"

    # 生成服务器证书和密钥
    echo "yes" | ./easyrsa build-server-full "$SERVER_NAME" nopass || error_exit "生成服务器证书失败"

    # 生成 Diffie-Hellman 参数
    ./easyrsa gen-dh || error_exit "生成 DH 参数失败"

    # 生成 TLS 认证密钥
    openvpn --genkey --secret /etc/openvpn/ta.key || error_exit "生成 TLS 认证密钥失败"

    # 复制证书和密钥到 OpenVPN 目录
    cp pki/ca.crt /etc/openvpn/ || error_exit "复制 CA 证书失败"
    cp pki/issued/"$SERVER_NAME".crt /etc/openvpn/ || error_exit "复制服务器证书失败"
    cp pki/private/"$SERVER_NAME".key /etc/openvpn/ || error_exit "复制服务器密钥失败"
    cp pki/dh.pem /etc/openvpn/ || error_exit "复制 DH 参数失败"

    log "${GREEN}PKI 和证书设置完成${NC}"
}

# 函数: 检查OpenVPN版本
check_openvpn_version() {
    log "${BLUE}检查 OpenVPN 版本...${NC}"

    # 获取OpenVPN版本
    OPENVPN_VERSION=$(openvpn --version | head -n 1 | awk '{print $2}')
    log "${GREEN}OpenVPN 版本: $OPENVPN_VERSION${NC}"

    # 检查是否支持scramble选项
    SUPPORTS_SCRAMBLE=false
    if openvpn --help | grep -q "scramble"; then
        SUPPORTS_SCRAMBLE=true
        log "${GREEN}OpenVPN 支持 scramble 选项${NC}"
    else
        log "${YELLOW}OpenVPN 不支持 scramble 选项，将不使用此功能${NC}"
    fi

    return 0
}

# 函数: 验证OpenVPN配置
.# 注意: 此函数已增强，使用更可靠的方法检测和添加NAT规则
# 1. 使用iptables -t nat -C命令精确检查NAT规则是否存在
# 2. 添加NAT规则后验证是否成功添加
# 3. 如果MASQUERADE方法失败，尝试使用SNAT作为备选方法
validate_openvpn_config() {
    log "${BLUE}验证 OpenVPN 配置文件...${NC}"

    # 检查配置文件是否存在
    if [ ! -f "/etc/openvpn/server.conf" ]; then
        log "${RED}错误: 服务器配置文件不存在${NC}"
        return 1
    fi

    # 检查ta.key文件是否存在
    if [ ! -f "/etc/openvpn/ta.key" ]; then
        log "${RED}错误: ta.key文件不存在${NC}"
        log "${YELLOW}注意: 如果之前已经生成过客户端配置，重新生成ta.key将导致现有客户端无法连接${NC}"
        log "${YELLOW}自动重新生成ta.key文件...${NC}"
        openvpn --genkey --secret /etc/openvpn/ta.key
        if [ ! -f "/etc/openvpn/ta.key" ]; then
            log "${RED}错误: 无法生成ta.key文件${NC}"
            return 1
        else
            log "${GREEN}成功生成ta.key文件${NC}"
            chmod 600 /etc/openvpn/ta.key
            log "${YELLOW}警告: 现有客户端将无法连接，需要更新客户端配置${NC}"
            log "${YELLOW}请运行脚本并选择'更新客户端ta.key'选项来更新客户端配置${NC}"
            # 设置标志，表示ta.key已更新
            echo "$(date '+%Y-%m-%d %H:%M:%S')" > /etc/openvpn/ta.key.updated
        fi
    fi

    # 检查文件权限
    log "${BLUE}检查文件权限...${NC}"
    if [ -f "/etc/openvpn/server.conf" ]; then
        chmod 644 /etc/openvpn/server.conf
        log "${GREEN}已设置server.conf权限${NC}"
    fi

    if [ -f "/etc/openvpn/ta.key" ]; then
        chmod 600 /etc/openvpn/ta.key
        log "${GREEN}已设置ta.key权限${NC}"
    fi

    if [ -f "/etc/openvpn/ca.crt" ]; then
        chmod 644 /etc/openvpn/ca.crt
        log "${GREEN}已设置ca.crt权限${NC}"
    fi

    if [ -f "/etc/openvpn/dh.pem" ]; then
        chmod 644 /etc/openvpn/dh.pem
        log "${GREEN}已设置dh.pem权限${NC}"
    fi

    # 检查服务器证书和密钥
    local server_name=$(grep -E "^cert " /etc/openvpn/server.conf | awk '{print $2}' | sed 's/.crt//')
    if [ -z "$server_name" ]; then
        server_name="server"
    fi

    if [ -f "/etc/openvpn/${server_name}.crt" ]; then
        chmod 644 "/etc/openvpn/${server_name}.crt"
        log "${GREEN}已设置${server_name}.crt权限${NC}"
    fi

    if [ -f "/etc/openvpn/${server_name}.key" ]; then
        chmod 600 "/etc/openvpn/${server_name}.key"
        log "${GREEN}已设置${server_name}.key权限${NC}"
    fi

    # 检查IP转发是否启用
    log "${BLUE}检查IP转发...${NC}"
    local ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if [ "$ip_forward" != "1" ]; then
        log "${YELLOW}警告: IP转发未启用，正在启用...${NC}"
        echo 1 > /proc/sys/net/ipv4/ip_forward
        sysctl -w net.ipv4.ip_forward=1
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
        sysctl -p
        log "${GREEN}IP转发已启用${NC}"
    else
        log "${GREEN}IP转发已启用${NC}"
    fi

    # 检查防火墙规则
    log "${BLUE}检查防火墙规则...${NC}"
    local port=$(grep -E "^port " /etc/openvpn/server.conf | awk '{print $2}')
    local protocol=$(grep -E "^proto " /etc/openvpn/server.conf | awk '{print $2}')

    if [ -z "$port" ]; then
        port="1194"
    fi

    if [ -z "$protocol" ]; then
        protocol="udp"
    fi

    # 检测主网络接口
    local main_interface=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
    if [ -z "$main_interface" ]; then
        main_interface="eth0"
        log "${YELLOW}警告: 无法检测到主网络接口，使用默认值 eth0${NC}"
    fi

    # 检查iptables规则
    if ! iptables -L INPUT -n | grep -q "$protocol dpt:$port"; then
        log "${YELLOW}警告: iptables中未找到OpenVPN端口规则，正在添加...${NC}"
        iptables -A INPUT -i $main_interface -p $protocol --dport $port -j ACCEPT
        log "${GREEN}已添加iptables端口规则${NC}"
    fi

    # 使用iptables -C命令直接检查规则是否存在
    if ! iptables -C INPUT -i tun+ -j ACCEPT 2>/dev/null; then
        log "${YELLOW}警告: iptables中未找到tun接口规则，正在添加...${NC}"
        iptables -A INPUT -i tun+ -j ACCEPT
        iptables -A FORWARD -i tun+ -j ACCEPT
        iptables -A FORWARD -i tun+ -o $main_interface -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A FORWARD -i $main_interface -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
        log "${GREEN}已添加iptables tun接口规则${NC}"
    fi

    # 检查NAT规则
    # 获取VPN子网
    local vpn_subnet=$(grep -E "^server " /etc/openvpn/server.conf | awk '{print $2}')
    local vpn_netmask=$(grep -E "^server " /etc/openvpn/server.conf | awk '{print $3}')

    if [ -z "$vpn_subnet" ]; then
        vpn_subnet="10.8.0.0"
    fi

    if [ -z "$vpn_netmask" ]; then
        vpn_netmask="255.255.255.0"
    fi

    if ! iptables -t nat -C POSTROUTING -s $vpn_subnet/$vpn_netmask -o $main_interface -j MASQUERADE 2>/dev/null; then
        log "${YELLOW}警告: 未找到NAT规则，正在添加...${NC}"
        iptables -t nat -A POSTROUTING -s $vpn_subnet/$vpn_netmask -o $main_interface -j MASQUERADE

        # 验证NAT规则是否已应用
        if ! iptables -t nat -C POSTROUTING -s $vpn_subnet/$vpn_netmask -o $main_interface -j MASQUERADE 2>/dev/null; then
            log "${RED}错误: 无法应用iptables NAT规则，尝试备选方法${NC}"
            # 备选方法：使用SNAT而不是MASQUERADE
            local server_ip=$(ip -4 addr show $main_interface | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
            if [ -n "$server_ip" ]; then
                iptables -t nat -A POSTROUTING -s $vpn_subnet/$vpn_netmask -j SNAT --to-source $server_ip
                log "${YELLOW}已尝试使用备选NAT方法${NC}"
            else
                log "${RED}错误: 无法获取服务器IP地址，NAT规则添加失败${NC}"
            fi
        else
            log "${GREEN}已添加NAT规则${NC}"
        fi
    else
        log "${GREEN}NAT规则正常${NC}"
    fi

    # 保存iptables规则
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        if [ -d "/etc/iptables" ]; then
            iptables-save > /etc/iptables/rules.v4
            log "${GREEN}已保存iptables规则${NC}"
        fi
    elif [[ "$OS" == "centos" ]]; then
        if command -v service &>/dev/null; then
            service iptables save
            log "${GREEN}已保存iptables规则${NC}"
        fi
    fi

    # 检查UFW规则(如果存在)
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        if ! ufw status | grep -q "$port/$protocol"; then
            log "${YELLOW}警告: UFW中未找到OpenVPN端口规则，正在添加...${NC}"
            ufw allow $port/$protocol
            log "${GREEN}已添加UFW端口规则${NC}"
        fi
    fi

    # 检查firewalld规则(如果存在)
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        if ! firewall-cmd --list-ports | grep -q "$port/$protocol"; then
            log "${YELLOW}警告: firewalld中未找到OpenVPN端口规则，正在添加...${NC}"
            firewall-cmd --permanent --add-port=$port/$protocol
            firewall-cmd --permanent --add-service=openvpn
            firewall-cmd --reload
            log "${GREEN}已添加firewalld端口规则${NC}"
        fi
    fi

    log "${GREEN}OpenVPN 配置文件验证和修复完成${NC}"
    return 0
}

# 函数: 配置 OpenVPN 服务器
configure_server() {
    log "${BLUE}开始配置 OpenVPN 服务器...${NC}"

    # 检查OpenVPN版本
    check_openvpn_version

    # 创建服务器配置文件
    cat > /etc/openvpn/server.conf << EOF
port $PORT
proto $PROTOCOL
dev tun
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
dh dh.pem
topology subnet
server $VPN_SUBNET $VPN_NETMASK
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $DNS1"
push "dhcp-option DNS $DNS2"
keepalive $KEEPALIVE_PING $KEEPALIVE_TIMEOUT
tls-auth ta.key 0
cipher $CIPHER
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC
auth $AUTH
compress $COMPRESS
push "compress $COMPRESS"
allow-compression yes
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb $LOG_LEVEL
max-clients $MAX_CLIENTS
tls-version-min $TLS_VERSION
# 躲避中国运营商封锁的优化
mssfix 1400
fragment 1400
EOF

    # 如果支持scramble选项，则添加
    if [ "$SUPPORTS_SCRAMBLE" = true ]; then
        echo "scramble obfuscate" >> /etc/openvpn/server.conf
    fi

    # 添加条件配置选项
    if [ "$ENABLE_IPV6" = true ]; then
        echo "server-ipv6 fd42:42:42:42::/112" >> /etc/openvpn/server.conf
        echo "push \"route-ipv6 2000::/3\"" >> /etc/openvpn/server.conf
    fi

    if [ "$DUPLICATE_CN" = true ]; then
        echo "duplicate-cn" >> /etc/openvpn/server.conf
    fi

    if [ "$PUSH_BLOCK_DNS" = true ]; then
        echo "push \"block-outside-dns\"" >> /etc/openvpn/server.conf
    fi

    if [ "$CLIENT_TO_CLIENT" = true ]; then
        echo "client-to-client" >> /etc/openvpn/server.conf
    fi

    # 修正 CentOS 的 group 设置
    if [[ "$OS" == "centos" ]]; then
        sed -i 's/group nogroup/group nobody/g' /etc/openvpn/server.conf
    fi

    log "${GREEN}OpenVPN 服务器配置完成${NC}"
}

# 函数: 检查端口是否已开放
check_port_open() {
    local port=$1
    local protocol=$2
    local is_open=false

    log "${BLUE}检查端口 $port/$protocol 是否已开放...${NC}"

    # 检查 iptables 规则
    if iptables -L INPUT -n | grep -q "$protocol dpt:$port"; then
        log "${GREEN}端口 $port/$protocol 已在 iptables 中开放${NC}"
        is_open=true
    fi

    # 检查 UFW 规则 (如果存在)
    if command -v ufw &>/dev/null && ufw status | grep -q "$port/$protocol"; then
        log "${GREEN}端口 $port/$protocol 已在 UFW 中开放${NC}"
        is_open=true
    fi

    # 检查 firewalld 规则 (如果存在)
    if command -v firewall-cmd &>/dev/null && firewall-cmd --list-ports | grep -q "$port/$protocol"; then
        log "${GREEN}端口 $port/$protocol 已在 firewalld 中开放${NC}"
        is_open=true
    fi

    # 返回结果
    if [ "$is_open" = true ]; then
        return 0
    else
        return 1
    fi
}

# 函数: 验证网络配置
verify_network_configuration() {
    log "${BLUE}验证网络配置...${NC}"

    local config_issues=false

    # 验证IP转发是否启用
    local ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if [ "$ip_forward" != "1" ]; then
        log "${RED}错误: IP转发未启用，VPN客户端可能无法访问互联网${NC}"
        log "${YELLOW}尝试再次启用IP转发...${NC}"
        echo 1 > /proc/sys/net/ipv4/ip_forward
        sysctl -w net.ipv4.ip_forward=1

        # 再次检查
        ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
        if [ "$ip_forward" != "1" ]; then
            log "${RED}错误: 无法启用IP转发，请手动检查系统配置${NC}"
            config_issues=true
        else
            log "${GREEN}IP转发已成功启用${NC}"
        fi
    else
        log "${GREEN}IP转发已正确启用${NC}"
    fi

    # 验证NAT规则是否存在
    local nat_rule_exists=false
    if iptables -t nat -C POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -o $NIC -j MASQUERADE 2>/dev/null; then
        nat_rule_exists=true
        log "${GREEN}NAT规则已正确配置${NC}"
    elif iptables -t nat -L POSTROUTING | grep -q "$VPN_SUBNET"; then
        nat_rule_exists=true
        log "${GREEN}找到针对VPN子网的NAT规则${NC}"
    else
        log "${RED}错误: 未找到NAT规则，VPN客户端可能无法访问互联网${NC}"
        log "${YELLOW}尝试再次添加NAT规则...${NC}"
        iptables -t nat -A POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -o $NIC -j MASQUERADE

        # 再次检查
        if iptables -t nat -C POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -o $NIC -j MASQUERADE 2>/dev/null; then
            nat_rule_exists=true
            log "${GREEN}NAT规则已成功添加${NC}"
        else
            log "${RED}错误: 无法添加NAT规则，请手动检查iptables配置${NC}"
            config_issues=true
        fi
    fi

    # 验证FORWARD规则是否存在
    local forward_rule_exists=false
    if iptables -C FORWARD -i tun+ -o $NIC -j ACCEPT 2>/dev/null; then
        forward_rule_exists=true
        log "${GREEN}FORWARD规则已正确配置${NC}"
    else
        log "${RED}错误: 未找到FORWARD规则，VPN客户端可能无法访问互联网${NC}"
        log "${YELLOW}尝试再次添加FORWARD规则...${NC}"
        iptables -A FORWARD -i tun+ -o $NIC -j ACCEPT
        iptables -A FORWARD -i $NIC -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

        # 再次检查
        if iptables -C FORWARD -i tun+ -o $NIC -j ACCEPT 2>/dev/null; then
            forward_rule_exists=true
            log "${GREEN}FORWARD规则已成功添加${NC}"
        else
            log "${RED}错误: 无法添加FORWARD规则，请手动检查iptables配置${NC}"
            config_issues=true
        fi
    fi

    # 验证网络接口是否有互联网连接
    log "${BLUE}验证网络接口 $NIC 是否有互联网连接...${NC}"
    local nic_has_internet=false
    if ping -c 1 -I $NIC 8.8.8.8 >/dev/null 2>&1; then
        log "${GREEN}网络接口 $NIC 可以访问互联网${NC}"
        nic_has_internet=true
    else
        log "${YELLOW}警告: 网络接口 $NIC 无法访问互联网，尝试查找其他可用接口...${NC}"
        config_issues=true

        # 尝试查找其他可用接口
        local found_interface=false
        local internet_iface=""
        for iface in $(ip -o -4 addr show | awk '{print $2}' | grep -v "lo" | sort | uniq); do
            if [ "$iface" != "$NIC" ] && ping -c 1 -I $iface 8.8.8.8 >/dev/null 2>&1; then
                log "${GREEN}找到可访问互联网的备选接口: $iface${NC}"
                found_interface=true
                internet_iface=$iface
                break
            fi
        done

        if [ "$found_interface" = true ]; then
            log "${YELLOW}建议: 为接口 $internet_iface 添加NAT规则${NC}"
            iptables -t nat -A POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -o $internet_iface -j MASQUERADE
            log "${GREEN}已为接口 $internet_iface 添加NAT规则${NC}"

            # 添加FORWARD规则
            iptables -A FORWARD -i tun+ -o $internet_iface -j ACCEPT
            iptables -A FORWARD -i $internet_iface -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
            log "${GREEN}已为接口 $internet_iface 添加FORWARD规则${NC}"

            # 保存规则
            if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
                iptables-save > /etc/iptables/rules.v4 || log "${YELLOW}警告: 无法保存iptables规则${NC}"
            elif [[ "$OS" == "centos" ]]; then
                service iptables save || log "${YELLOW}警告: 无法保存iptables规则${NC}"
            fi

            log "${GREEN}已成功配置备选接口 $internet_iface 用于VPN流量${NC}"
        else
            log "${RED}错误: 未找到可访问互联网的网络接口，请检查服务器网络配置${NC}"
        fi
    fi

    # 检查是否为多网卡环境，并为所有可能的出口接口添加NAT规则
    log "${BLUE}检查是否为多网卡环境...${NC}"
    local interface_count=$(ip -o -4 addr show | awk '{print $2}' | grep -v "lo" | sort | uniq | wc -l)
    if [ "$interface_count" -gt 1 ]; then
        log "${YELLOW}检测到多网卡环境 (${interface_count}个接口)，为所有可能的出口接口添加NAT规则...${NC}"

        for iface in $(ip -o -4 addr show | awk '{print $2}' | grep -v "lo" | sort | uniq); do
            if [ "$iface" != "tun0" ] && [ "$iface" != "tun+" ]; then
                # 检查是否已存在该接口的NAT规则
                if ! iptables -t nat -C POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -o $iface -j MASQUERADE 2>/dev/null; then
                    log "${BLUE}为接口 $iface 添加NAT规则...${NC}"
                    iptables -t nat -A POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -o $iface -j MASQUERADE

                    # 添加FORWARD规则
                    iptables -A FORWARD -i tun+ -o $iface -j ACCEPT
                    iptables -A FORWARD -i $iface -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

                    log "${GREEN}已为接口 $iface 添加NAT和FORWARD规则${NC}"
                else
                    log "${GREEN}接口 $iface 已存在NAT规则${NC}"
                fi
            fi
        done

        # 保存规则
        if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
            iptables-save > /etc/iptables/rules.v4 || log "${YELLOW}警告: 无法保存iptables规则${NC}"
        elif [[ "$OS" == "centos" ]]; then
            service iptables save || log "${YELLOW}警告: 无法保存iptables规则${NC}"
        fi

        log "${GREEN}已为所有网络接口配置NAT规则${NC}"
    else
        log "${GREEN}单网卡环境，无需额外配置${NC}"
    fi

    # 总结验证结果
    if [ "$ip_forward" = "1" ] && [ "$nat_rule_exists" = true ] && [ "$forward_rule_exists" = true ] && [ "$config_issues" = false ]; then
        log "${GREEN}网络配置验证通过，VPN客户端应该能够访问互联网${NC}"
        return 0
    else
        if [ "$config_issues" = true ]; then
            log "${YELLOW}警告: 网络配置验证过程中发现并尝试修复了一些问题${NC}"
            log "${YELLOW}如果VPN客户端仍然无法访问互联网，请尝试以下步骤:${NC}"
            log "${YELLOW}1. 检查服务器是否有多个网络接口，确保正确的接口配置了NAT规则${NC}"
            log "${YELLOW}2. 检查服务器防火墙是否允许VPN流量${NC}"
            log "${YELLOW}3. 检查服务器是否有其他安全策略限制网络流量${NC}"
            log "${YELLOW}4. 尝试重启OpenVPN服务: systemctl restart openvpn@server${NC}"
            log "${YELLOW}5. 如果问题仍然存在，请联系系统管理员寻求帮助${NC}"
        else
            log "${GREEN}网络配置验证通过，但发现了一些潜在问题${NC}"
            log "${YELLOW}建议重启OpenVPN服务以确保所有配置生效: systemctl restart openvpn@server${NC}"
        fi
        return 1
    fi
}

# 函数: 配置网络
configure_network() {
    log "${BLUE}开始配置网络...${NC}"

    # 启用 IP 转发
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
        run_cmd "sysctl -p" "应用 IP 转发设置" || log "${YELLOW}警告: 无法应用 sysctl 设置${NC}"
    else
        log "${GREEN}IP 转发配置已存在${NC}"
    fi

    # 再次检查 IP 转发是否已启用
    check_ip_forwarding

    # 检测主网络接口
    log "${BLUE}检测主网络接口...${NC}"

    # 方法1: 使用默认路由
    NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    if [ -n "$NIC" ]; then
        log "${GREEN}方法1检测到主网络接口: $NIC${NC}"
    else
        log "${YELLOW}方法1未检测到主网络接口${NC}"
    fi

    # 方法2: 检查具有公网IP的接口
    if [ -z "$NIC" ]; then
        for iface in $(ip -o -4 addr show | awk '{print $2}' | grep -v "lo" | sort | uniq); do
            ip=$(ip -4 addr show $iface | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
            if [ -n "$ip" ] && [[ ! "$ip" =~ ^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.) ]]; then
                NIC=$iface
                log "${GREEN}方法2检测到具有公网IP的网络接口: $NIC${NC}"
                break
            fi
        done
    fi

    # 方法3: 检查能够访问互联网的接口
    if [ -z "$NIC" ]; then
        for iface in $(ip -o -4 addr show | awk '{print $2}' | grep -v "lo" | sort | uniq); do
            if ping -c 1 -I $iface 8.8.8.8 >/dev/null 2>&1; then
                NIC=$iface
                log "${GREEN}方法3检测到能够访问互联网的网络接口: $NIC${NC}"
                break
            fi
        done
    fi

    # 方法4: 使用最活跃的非lo接口
    if [ -z "$NIC" ]; then
        NIC=$(ip -o -4 addr show | awk '{print $2}' | grep -v "lo" | head -1)
        if [ -n "$NIC" ]; then
            log "${YELLOW}方法4使用第一个非lo网络接口: $NIC${NC}"
        fi
    fi

    # 如果仍然没有检测到，使用默认值
    if [ -z "$NIC" ]; then
        NIC="eth0"
        log "${RED}警告: 无法检测到任何网络接口，使用默认值 eth0${NC}"
    fi

    # 验证检测到的接口是否存在
    if ! ip link show $NIC >/dev/null 2>&1; then
        log "${RED}错误: 检测到的网络接口 $NIC 不存在${NC}"
        # 尝试找到一个存在的接口
        for iface in eth0 ens3 ens5 ens18 ens160 ens192 enp0s3 enp0s8 enp1s0 enp2s0 enp3s0 enp4s0 enp5s0 em1 em2; do
            if ip link show $iface >/dev/null 2>&1; then
                NIC=$iface
                log "${YELLOW}使用备选网络接口: $NIC${NC}"
                break
            fi
        done
    fi

    log "${GREEN}最终使用的网络接口: $NIC${NC}"

    # 配置NAT转发规则（确保VPN流量可以通过公网网卡出去）
    log "${BLUE}配置NAT转发规则...${NC}"

    # 确保之前的NAT规则被清除，避免重复规则
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" || "$OS" == "centos" ]]; then
        log "${BLUE}清除现有NAT规则...${NC}"
        iptables -t nat -D POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -o $NIC -j MASQUERADE 2>/dev/null || true
        # 也尝试清除可能存在的任何接口的规则
        for iface in $(ip -o -4 addr show | awk '{print $2}' | grep -v "lo" | sort | uniq); do
            iptables -t nat -D POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -o $iface -j MASQUERADE 2>/dev/null || true
        done
    fi

    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        # 使用 iptables 设置NAT规则
        log "${BLUE}使用iptables设置NAT规则...${NC}"
        iptables -t nat -A POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -o $NIC -j MASQUERADE

        # 验证NAT规则是否已应用
        if ! iptables -t nat -C POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -o $NIC -j MASQUERADE 2>/dev/null; then
            log "${RED}错误: 无法应用iptables NAT规则，尝试备选方法${NC}"
            # 备选方法：使用SNAT而不是MASQUERADE
            iptables -t nat -A POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -j SNAT --to-source $(ip -4 addr show $NIC | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)

            # 再次验证
            if ! iptables -t nat -L POSTROUTING | grep -q "$VPN_SUBNET"; then
                log "${RED}错误: 备选NAT方法也失败，VPN客户端可能无法访问互联网${NC}"
            else
                log "${GREEN}备选NAT方法应用成功${NC}"
            fi
        else
            log "${GREEN}iptables NAT规则应用成功${NC}"
        fi

        # 保存NAT规则
        log "${BLUE}保存iptables规则...${NC}"
        mkdir -p /etc/iptables
        if ! iptables-save > /etc/iptables/rules.v4; then
            log "${YELLOW}警告: 无法保存iptables规则到文件，尝试使用其他方法${NC}"
            # 尝试使用其他方法保存规则
            if command -v netfilter-persistent &>/dev/null; then
                netfilter-persistent save || log "${RED}错误: netfilter-persistent保存失败${NC}"
            elif command -v iptables-persistent &>/dev/null; then
                iptables-persistent save || log "${RED}错误: iptables-persistent保存失败${NC}"
            fi
        else
            log "${GREEN}iptables规则保存成功${NC}"
        fi

        # 确保规则在启动时加载
        if [ ! -f /etc/network/if-up.d/iptables ]; then
            log "${BLUE}创建网络接口启动脚本以加载iptables规则...${NC}"
            cat > /etc/network/if-up.d/iptables << EOF
#!/bin/sh
iptables-restore < /etc/iptables/rules.v4
exit 0
EOF
            chmod +x /etc/network/if-up.d/iptables
            log "${GREEN}网络接口启动脚本创建成功${NC}"
        fi

        # 配置 UFW NAT规则 (如果存在)
        if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
            log "${BLUE}配置UFW NAT规则...${NC}"
            # 检查 NAT 规则是否已存在
            if ! grep -q "POSTROUTING -s $VPN_SUBNET/$VPN_NETMASK -o $NIC -j MASQUERADE" /etc/ufw/before.rules; then
                # 编辑 UFW 配置
                cat >> /etc/ufw/before.rules << EOF

# NAT 表规则
*nat
:POSTROUTING ACCEPT [0:0]
# 允许从 VPN 网络流量到互联网
-A POSTROUTING -s $VPN_SUBNET/$VPN_NETMASK -o $NIC -j MASQUERADE
COMMIT
EOF
                # 编辑 UFW 配置启用转发
                sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/g' /etc/default/ufw

                # 重启 UFW
                log "${BLUE}重启UFW...${NC}"
                ufw disable
                ufw enable
                log "${GREEN}UFW重启完成${NC}"
            else
                log "${GREEN}UFW NAT规则已存在${NC}"
            fi
        fi
    elif [[ "$OS" == "centos" ]]; then
        # 使用 firewalld 设置NAT规则 (如果存在)
        if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
            log "${BLUE}使用firewalld设置NAT规则...${NC}"
            firewall-cmd --permanent --add-masquerade
            firewall-cmd --reload

            # 验证masquerade是否已启用
            if ! firewall-cmd --query-masquerade; then
                log "${RED}错误: firewalld masquerade未启用，尝试使用iptables${NC}"
                iptables -t nat -A POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -o $NIC -j MASQUERADE
                service iptables save || log "${YELLOW}警告: 无法保存iptables规则${NC}"
            else
                log "${GREEN}firewalld masquerade已启用${NC}"
            fi
        else
            # 使用 iptables 设置NAT规则
            log "${BLUE}使用iptables设置NAT规则...${NC}"
            iptables -t nat -A POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -o $NIC -j MASQUERADE

            # 验证NAT规则是否已应用
            if ! iptables -t nat -C POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -o $NIC -j MASQUERADE 2>/dev/null; then
                log "${RED}错误: 无法应用iptables NAT规则，尝试备选方法${NC}"
                # 备选方法：使用SNAT而不是MASQUERADE
                iptables -t nat -A POSTROUTING -s "$VPN_SUBNET/$VPN_NETMASK" -j SNAT --to-source $(ip -4 addr show $NIC | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
            else
                log "${GREEN}iptables NAT规则应用成功${NC}"
            fi

            # 保存规则
            log "${BLUE}保存iptables规则...${NC}"
            if ! service iptables save; then
                log "${YELLOW}警告: 无法通过service保存iptables规则，尝试其他方法${NC}"
                # 尝试直接保存
                if [ -d /etc/sysconfig ]; then
                    mkdir -p /etc/sysconfig/iptables.d
                    iptables-save > /etc/sysconfig/iptables
                    log "${GREEN}iptables规则已保存到/etc/sysconfig/iptables${NC}"
                fi
            else
                log "${GREEN}iptables规则保存成功${NC}"
            fi
        fi
    fi

    # 添加额外的NAT规则以确保所有流量都能正确路由
    log "${BLUE}添加额外的NAT和路由规则...${NC}"

    # 确保所有VPN客户端流量都能通过服务器的默认网关
    iptables -A FORWARD -i tun+ -o $NIC -j ACCEPT
    iptables -A FORWARD -i $NIC -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

    # 验证转发规则
    if ! iptables -C FORWARD -i tun+ -o $NIC -j ACCEPT 2>/dev/null; then
        log "${RED}错误: 无法应用FORWARD规则，VPN客户端可能无法访问互联网${NC}"
    else
        log "${GREEN}FORWARD规则应用成功${NC}"
    fi

    # 保存所有规则
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        iptables-save > /etc/iptables/rules.v4 || log "${YELLOW}警告: 无法保存最终iptables规则${NC}"
    elif [[ "$OS" == "centos" ]]; then
        service iptables save || log "${YELLOW}警告: 无法保存最终iptables规则${NC}"
    fi

    log "${GREEN}NAT和路由规则配置完成${NC}"

    # 验证网络配置
    verify_network_configuration

    # 检查端口是否已开放
    if check_port_open "$PORT" "$PROTOCOL"; then
        log "${GREEN}端口 $PORT/$PROTOCOL 已开放，无需再次配置防火墙规则${NC}"
    else
        log "${YELLOW}端口 $PORT/$PROTOCOL 未开放，正在配置防火墙规则...${NC}"

        # 配置防火墙规则
        if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
            # 使用 iptables
            iptables -A INPUT -i $NIC -m state --state NEW -p "$PROTOCOL" --dport "$PORT" -j ACCEPT
            iptables -A INPUT -i tun+ -j ACCEPT
            iptables -A FORWARD -i tun+ -j ACCEPT
            iptables -A FORWARD -i tun+ -o $NIC -m state --state RELATED,ESTABLISHED -j ACCEPT
            iptables -A FORWARD -i $NIC -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

            # 保存规则
            iptables-save > /etc/iptables/rules.v4 || log "${YELLOW}警告: 无法保存 iptables 规则${NC}"

            # 配置 UFW (如果存在)
            if command -v ufw &>/dev/null; then
                # 检查 UFW 状态
                if ufw status | grep -q "Status: active"; then
                    log "${BLUE}配置 UFW 规则...${NC}"
                    ufw allow "$PORT"/"$PROTOCOL"
                    ufw allow OpenSSH
                fi
            fi
        elif [[ "$OS" == "centos" ]]; then
            # 使用 firewalld (如果存在)
            if command -v firewall-cmd &>/dev/null; then
                # 检查 firewalld 状态
                if systemctl is-active --quiet firewalld; then
                    log "${BLUE}配置 firewalld 规则...${NC}"
                    firewall-cmd --permanent --add-port="$PORT"/"$PROTOCOL"
                    firewall-cmd --permanent --add-service=openvpn
                    firewall-cmd --reload
                else
                    log "${YELLOW}firewalld 未运行，尝试启动...${NC}"
                    systemctl start firewalld
                    systemctl enable firewalld

                    # 再次尝试配置
                    firewall-cmd --permanent --add-port="$PORT"/"$PROTOCOL"
                    firewall-cmd --permanent --add-service=openvpn
                    firewall-cmd --reload
                fi
            else
                # 使用 iptables
                log "${BLUE}配置 iptables 规则...${NC}"
                iptables -A INPUT -i $NIC -m state --state NEW -p "$PROTOCOL" --dport "$PORT" -j ACCEPT
                iptables -A INPUT -i tun+ -j ACCEPT
                iptables -A FORWARD -i tun+ -j ACCEPT
                iptables -A FORWARD -i tun+ -o $NIC -m state --state RELATED,ESTABLISHED -j ACCEPT
                iptables -A FORWARD -i $NIC -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

                # 保存规则
                service iptables save || log "${YELLOW}警告: 无法保存 iptables 规则${NC}"
            fi
        fi
    fi

    # 验证端口是否已开放
    if check_port_open "$PORT" "$PROTOCOL"; then
        log "${GREEN}端口 $PORT/$PROTOCOL 已成功开放${NC}"
    else
        log "${YELLOW}警告: 端口 $PORT/$PROTOCOL 可能未正确开放，请手动检查防火墙配置${NC}"
    fi

    log "${GREEN}网络配置完成${NC}"
}

# 函数: 生成客户端证书和配置
generate_client() {
    log "${BLUE}开始生成客户端证书和配置...${NC}"

    # 生成客户端证书和密钥
    cd /etc/openvpn/easy-rsa/ || error_exit "无法进入 easy-rsa 目录"
    echo "yes" | ./easyrsa build-client-full "$CLIENT_NAME" nopass || error_exit "生成客户端证书失败"

    # 创建客户端配置目录
    mkdir -p /etc/openvpn/client-configs/

    # 创建客户端配置文件生成脚本
    cat > /etc/openvpn/make_client_config.sh << 'EOF'
#!/bin/bash

# 参数解析
CLIENT=$1
OUTPUT_DIR=$2
OUTPUT_FILE=$3
MOBILE_DEVICE=$4

if [ -z "$CLIENT" ]; then
    echo "错误: 请提供客户端名称"
    echo "用法: $0 <客户端名称> [输出目录] [输出文件名] [是否为移动设备(true/false)]"
    exit 1
fi

# 如果未指定是否为移动设备，默认为false
if [ -z "$MOBILE_DEVICE" ]; then
    MOBILE_DEVICE=false
fi

# 如果未指定输出目录，使用默认值
if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="/etc/openvpn/client-configs"
fi

# 确保输出目录存在
mkdir -p "$OUTPUT_DIR"

# 基础配置文件路径
BASE_CONFIG="/etc/openvpn/client-configs/base.conf"

# 获取服务器 IP 和配置
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null)
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(hostname -I | awk '{print $1}')
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="YOUR_SERVER_IP"
        echo "警告: 无法自动检测服务器 IP，请手动编辑配置文件"
    fi
fi

# 读取服务器配置
if [ -f "/etc/openvpn/server.conf" ]; then
    SERVER_PORT=$(grep -E "^port " /etc/openvpn/server.conf | awk '{print $2}')
    SERVER_PROTO=$(grep -E "^proto " /etc/openvpn/server.conf | awk '{print $2}')
    SERVER_CIPHER=$(grep -E "^cipher " /etc/openvpn/server.conf | awk '{print $2}')
    SERVER_AUTH=$(grep -E "^auth " /etc/openvpn/server.conf | awk '{print $2}')
    SERVER_COMPRESS=$(grep -E "^compress " /etc/openvpn/server.conf | awk '{print $2}')
    SERVER_LOG_LEVEL=$(grep -E "^verb " /etc/openvpn/server.conf | awk '{print $2}')
    SERVER_TLS_VERSION=$(grep -E "^tls-version-min " /etc/openvpn/server.conf | awk '{print $2}')
    # 检查服务器配置是否使用了scramble选项
    SUPPORTS_SCRAMBLE=false
    if grep -q "^scramble " /etc/openvpn/server.conf; then
        SUPPORTS_SCRAMBLE=true
        echo "检测到服务器配置使用了scramble选项，客户端配置也将使用此选项"
    else
        echo "服务器配置未使用scramble选项，客户端配置也将不使用此选项"
    fi
else
    SERVER_PORT="1194"
    SERVER_PROTO="udp"
    SERVER_CIPHER="AES-256-CBC"
    SERVER_AUTH="SHA256"
    SERVER_COMPRESS="lz4-v2"
    SERVER_LOG_LEVEL="3"
    SERVER_TLS_VERSION="1.2"
    SUPPORTS_SCRAMBLE=false
    echo "警告: 无法读取服务器配置，使用默认值"
fi

    # 创建基础配置文件（如果不存在）
if [ ! -f "$BASE_CONFIG" ]; then
  cat > "$BASE_CONFIG" << BASEEOF
client
dev tun
proto ${SERVER_PROTO}
remote ${SERVER_IP} ${SERVER_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher ${SERVER_CIPHER}
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC
auth ${SERVER_AUTH}
compress ${SERVER_COMPRESS}
allow-compression yes
verb ${SERVER_LOG_LEVEL}
tls-version-min ${SERVER_TLS_VERSION}
# 躲避中国运营商封锁的优化
mssfix 1400
BASEEOF

  # 如果不是移动设备，添加fragment指令
  if [ "$MOBILE_DEVICE" = false ]; then
    echo "fragment 1400" >> "$BASE_CONFIG"
  fi

  # 继续添加其他配置
  cat >> "$BASE_CONFIG" << BASEEOF
# 添加多服务器支持，提高连接成功率
remote-random
resolv-retry infinite
BASEEOF

  # 如果服务器支持scramble选项，则添加到客户端配置
  if [ "$SUPPORTS_SCRAMBLE" = true ]; then
    echo "scramble obfuscate" >> "$BASE_CONFIG"
  fi
fi

# 检查客户端证书是否存在
if [ ! -f "/etc/openvpn/easy-rsa/pki/issued/${CLIENT}.crt" ]; then
    echo "错误: 客户端证书不存在。请先运行: cd /etc/openvpn/easy-rsa/ && ./easyrsa build-client-full ${CLIENT} nopass"
    exit 1
fi

if [ ! -f "/etc/openvpn/easy-rsa/pki/private/${CLIENT}.key" ]; then
    echo "错误: 客户端密钥不存在。请先运行: cd /etc/openvpn/easy-rsa/ && ./easyrsa build-client-full ${CLIENT} nopass"
    exit 1
fi

# 确定输出文件名
if [ -z "$OUTPUT_FILE" ]; then
    OUTPUT_FILE="${CLIENT}.ovpn"
fi

# 生成客户端配置
cat "${BASE_CONFIG}" \
    <(echo -e '<ca>') \
    /etc/openvpn/ca.crt \
    <(echo -e '</ca>\n<cert>') \
    /etc/openvpn/easy-rsa/pki/issued/${CLIENT}.crt \
    <(echo -e '</cert>\n<key>') \
    /etc/openvpn/easy-rsa/pki/private/${CLIENT}.key \
    <(echo -e '</key>\n<tls-auth>') \
    /etc/openvpn/ta.key \
    <(echo -e '</tls-auth>\nkey-direction 1') \
    > "${OUTPUT_DIR}/${OUTPUT_FILE}"

echo "客户端配置文件已创建: ${OUTPUT_DIR}/${OUTPUT_FILE}"
EOF

    chmod +x /etc/openvpn/make_client_config.sh

    # 创建基础客户端配置
    mkdir -p /etc/openvpn/client-configs

    # 获取服务器 IP
    SERVER_IP=$(curl -s ifconfig.me)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi

    # 创建基础配置文件
    cat > /etc/openvpn/client-configs/base.conf << EOF
client
dev tun
proto $PROTOCOL
remote $SERVER_IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher $CIPHER
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC
auth $AUTH
compress $COMPRESS
allow-compression yes
verb 3
# 躲避中国运营商封锁的优化
mssfix 1400
EOF

    # 如果不是移动设备，添加fragment指令
    if [ "$MOBILE_DEVICE" = false ]; then
        echo "fragment 1400" >> /etc/openvpn/client-configs/base.conf
    fi

    # 继续添加其他配置
    cat >> /etc/openvpn/client-configs/base.conf << EOF
# 添加多服务器支持，提高连接成功率
remote-random
resolv-retry infinite
EOF

    # 如果支持scramble选项，则添加到客户端配置
    if [ "$SUPPORTS_SCRAMBLE" = true ]; then
        echo "scramble obfuscate" >> /etc/openvpn/client-configs/base.conf
    fi

    # 生成客户端配置文件
    /etc/openvpn/make_client_config.sh "$CLIENT_NAME" "$OUTPUT_DIR" "$OUTPUT_FILE" "$MOBILE_DEVICE" || error_exit "生成客户端配置失败"

    # 确定最终的输出文件名
    FINAL_OUTPUT_FILE="$OUTPUT_FILE"
    if [ -z "$FINAL_OUTPUT_FILE" ]; then
        FINAL_OUTPUT_FILE="${CLIENT_NAME}.ovpn"
    fi

    log "${GREEN}客户端证书和配置生成完成${NC}"
    log "${GREEN}客户端配置文件位置: ${OUTPUT_DIR}/${FINAL_OUTPUT_FILE}${NC}"
}


# 函数: 启动 OpenVPN 服务
start_openvpn() {
    log "${BLUE}启动 OpenVPN 服务...${NC}"

    # 检查基本配置
    validate_openvpn_config

    # 启动 OpenVPN 服务
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" || "$OS" == "centos" ]]; then
        if ! run_cmd "systemctl start openvpn@server" "启动 OpenVPN 服务"; then
            log "${RED}启动 OpenVPN 服务失败，获取详细错误信息...${NC}"

            # 获取详细的错误信息
            local status_output=$(systemctl status openvpn@server 2>&1)
            local journal_output=$(journalctl -xeu openvpn@server -n 50 --no-pager 2>&1)

            log "${RED}systemctl status 输出:${NC}"
            log "$status_output"

            log "${RED}journalctl 输出:${NC}"
            log "$journal_output"

            error_exit "启动 OpenVPN 服务失败，请查看上述日志获取详细信息"
        fi

        run_cmd "systemctl enable openvpn@server" "设置 OpenVPN 服务开机自启" || log "${YELLOW}警告: 无法设置 OpenVPN 服务开机自启${NC}"
    fi

    # 检查服务状态
    if systemctl is-active --quiet openvpn@server; then
        log "${GREEN}OpenVPN 服务已成功启动${NC}"
    else
        log "${RED}警告: OpenVPN 服务未能正确启动，请检查日志${NC}"
        FAILED_COMMANDS="${FAILED_COMMANDS}• OpenVPN 服务未能正确启动，请检查 journalctl -u openvpn@server 获取详细信息\n"
    fi
}

# 函数: 重启 OpenVPN 服务
restart_openvpn() {
    log "${BLUE}重启 OpenVPN 服务...${NC}"

    # 重启 OpenVPN 服务
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" || "$OS" == "centos" ]]; then
        run_cmd "systemctl restart openvpn@server" "重启 OpenVPN 服务" || error_exit "重启 OpenVPN 服务失败"
    fi

    # 检查服务状态
    if systemctl is-active --quiet openvpn@server; then
        log "${GREEN}OpenVPN 服务已成功重启${NC}"
    else
        log "${YELLOW}警告: OpenVPN 服务可能未正确重启，请检查日志${NC}"
        FAILED_COMMANDS="${FAILED_COMMANDS}• OpenVPN 服务未能正确重启，请检查 journalctl -u openvpn@server 获取详细信息\n"
    fi

    # 检查 IP 转发是否启用
    check_ip_forwarding
}

# 函数: 显示服务器信息
show_server_info() {
    log "${BLUE}显示 OpenVPN 服务器信息...${NC}"

    # 检查 OpenVPN 是否已安装
    if ! command -v openvpn &>/dev/null; then
        log "${RED}错误: OpenVPN 未安装${NC}"
        return 1
    fi

    # 检查服务器配置文件是否存在
    if [ ! -f "/etc/openvpn/server.conf" ]; then
        log "${RED}错误: 服务器配置文件不存在${NC}"
        return 1
    fi

    echo -e "\n${BLUE}=== OpenVPN 服务器信息 ===${NC}\n"

    # 检查服务状态
    echo -e "${BLUE}服务状态:${NC}"
    if systemctl is-active --quiet openvpn@server; then
        echo -e "  状态: ${GREEN}运行中${NC}"

        # 获取服务运行时间
        UPTIME=$(systemctl show openvpn@server --property=ActiveEnterTimestamp | sed 's/ActiveEnterTimestamp=//g')
        if [ -n "$UPTIME" ]; then
            echo -e "  运行时间: $(date -d "$UPTIME" "+%Y-%m-%d %H:%M:%S") 开始"
        fi
    else
        echo -e "  状态: ${RED}未运行${NC}"
    fi

    # 获取服务器 IP
    SERVER_IP=$(curl -s ifconfig.me)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    echo -e "  服务器 IP: $SERVER_IP"

    # 从配置文件读取信息
    echo -e "\n${BLUE}配置信息:${NC}"

    # 读取协议
    PROTOCOL=$(grep -E "^proto " /etc/openvpn/server.conf | awk '{print $2}')
    if [ -n "$PROTOCOL" ]; then
        echo -e "  协议: $PROTOCOL"
    else
        echo -e "  协议: ${YELLOW}未知${NC}"
    fi

    # 读取端口
    PORT=$(grep -E "^port " /etc/openvpn/server.conf | awk '{print $2}')
    if [ -n "$PORT" ]; then
        echo -e "  端口: $PORT"
    else
        echo -e "  端口: ${YELLOW}未知${NC}"
    fi

    # 读取子网
    SERVER_LINE=$(grep -E "^server " /etc/openvpn/server.conf)
    if [ -n "$SERVER_LINE" ]; then
        VPN_SUBNET=$(echo "$SERVER_LINE" | awk '{print $2}')
        VPN_NETMASK=$(echo "$SERVER_LINE" | awk '{print $3}')
        echo -e "  子网: $VPN_SUBNET/$VPN_NETMASK"
    else
        echo -e "  子网: ${YELLOW}未知${NC}"
    fi

    # 读取加密算法
    CIPHER=$(grep -E "^cipher " /etc/openvpn/server.conf | awk '{print $2}')
    if [ -n "$CIPHER" ]; then
        echo -e "  加密算法: $CIPHER"
    else
        echo -e "  加密算法: ${YELLOW}未知${NC}"
    fi

    # 读取认证算法
    AUTH=$(grep -E "^auth " /etc/openvpn/server.conf | awk '{print $2}')
    if [ -n "$AUTH" ]; then
        echo -e "  认证算法: $AUTH"
    else
        echo -e "  认证算法: ${YELLOW}未知${NC}"
    fi

    # 读取最大客户端数
    MAX_CLIENTS=$(grep -E "^max-clients " /etc/openvpn/server.conf | awk '{print $2}')
    if [ -n "$MAX_CLIENTS" ]; then
        echo -e "  最大客户端数: $MAX_CLIENTS"
    else
        echo -e "  最大客户端数: ${YELLOW}未知${NC}"
    fi

    # 检查 IP 转发是否启用
    IP_FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if [ "$IP_FORWARD" = "1" ]; then
        echo -e "  IP 转发: ${GREEN}已启用${NC}"
    else
        echo -e "  IP 转发: ${RED}未启用${NC}"
    fi

    # 检查防火墙状态
    echo -e "\n${BLUE}防火墙状态:${NC}"

    # 检查 iptables
    if iptables -L INPUT -n | grep -q "$PROTOCOL dpt:$PORT"; then
        echo -e "  iptables: ${GREEN}端口 $PORT/$PROTOCOL 已开放${NC}"
    else
        echo -e "  iptables: ${YELLOW}端口 $PORT/$PROTOCOL 可能未开放${NC}"
    fi

    # 检查 UFW (如果存在)
    if command -v ufw &>/dev/null; then
        if ufw status | grep -q "Status: active"; then
            if ufw status | grep -q "$PORT/$PROTOCOL"; then
                echo -e "  UFW: ${GREEN}端口 $PORT/$PROTOCOL 已开放${NC}"
            else
                echo -e "  UFW: ${YELLOW}端口 $PORT/$PROTOCOL 可能未开放${NC}"
            fi
        else
            echo -e "  UFW: ${YELLOW}未启用${NC}"
        fi
    fi

    # 检查 firewalld (如果存在)
    if command -v firewall-cmd &>/dev/null; then
        if systemctl is-active --quiet firewalld; then
            if firewall-cmd --list-ports | grep -q "$PORT/$PROTOCOL"; then
                echo -e "  firewalld: ${GREEN}端口 $PORT/$PROTOCOL 已开放${NC}"
            else
                echo -e "  firewalld: ${YELLOW}端口 $PORT/$PROTOCOL 可能未开放${NC}"
            fi
        else
            echo -e "  firewalld: ${YELLOW}未启用${NC}"
        fi
    fi

    # 显示连接的客户端数量
    STATUS_LOG=""
    if [ -f "/var/log/openvpn/openvpn-status.log" ]; then
        STATUS_LOG="/var/log/openvpn/openvpn-status.log"
    elif [ -f "/etc/openvpn/openvpn-status.log" ]; then
        STATUS_LOG="/etc/openvpn/openvpn-status.log"
    fi

    if [ -n "$STATUS_LOG" ]; then
        # 使用更可靠的方法计算客户端数量
        CLIENT_COUNT=0
        CLIENT_SECTION=false

        while IFS= read -r line; do
            if [[ "$line" == "ROUTING TABLE" ]]; then
                CLIENT_SECTION=false
                continue
            elif [[ "$line" == "Common Name"* ]]; then
                CLIENT_SECTION=true
                continue
            fi

            if [[ "$CLIENT_SECTION" == true && -n "$line" ]]; then
                # 这是一个客户端行
                CLIENT_COUNT=$((CLIENT_COUNT + 1))
            fi
        done < "$STATUS_LOG"

        echo -e "\n${BLUE}连接信息:${NC}"
        echo -e "  当前连接客户端数: $CLIENT_COUNT"
    fi

    echo -e "\n${BLUE}系统信息:${NC}"
    echo -e "  操作系统: $(cat /etc/os-release | grep "PRETTY_NAME" | cut -d= -f2 | tr -d '"')"
    echo -e "  内核版本: $(uname -r)"
    echo -e "  OpenVPN 版本: $(openvpn --version | head -n 1 | awk '{print $2}')"

    echo -e "\n${YELLOW}提示:${NC}"
    echo -e "  1. 如需查看实时 VPN 状态，请选择 \"查看 VPN 实时状态\" 选项"
    echo -e "  2. 如需修改配置，请选择 \"修复当前安装\" 或 \"修改连接协议\" 选项"
    echo -e "  3. 如需重启服务，请选择 \"重启 OpenVPN 服务\" 选项"

    # 等待用户按任意键继续
    echo -e "\n按任意键返回主菜单..."
    read -n 1 -s
}

# 函数: 诊断连接问题
# 注意: 此函数已增强，使用更可靠的方法检测和添加NAT规则
# 1. 使用iptables -t nat -C命令精确检查NAT规则是否存在
# 2. 添加NAT规则后验证是否成功添加
# 3. 如果MASQUERADE方法失败，尝试使用SNAT作为备选方法
# 4. 在重启服务前再次检查并尝试添加NAT规则
# 5. 在诊断输出中同时检查MASQUERADE和SNAT规则
diagnose_connection_issues() {
    log "${BLUE}开始诊断连接问题...${NC}"

    # 检查 OpenVPN 是否已安装
    if ! command -v openvpn &>/dev/null; then
        log "${RED}错误: OpenVPN 未安装${NC}"
        log "${YELLOW}尝试安装 OpenVPN...${NC}"

        # 检测操作系统
        if [ -f /etc/debian_version ]; then
            OS="debian"
            if [ -f /etc/lsb-release ]; then
                OS="ubuntu"
            fi
        elif [ -f /etc/redhat-release ]; then
            OS="centos"
        else
            log "${RED}不支持的操作系统。此脚本仅支持 Ubuntu、Debian 和 CentOS/RHEL。${NC}"
            return 1
        fi

        # 安装OpenVPN
        if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
            apt update
            apt install -y openvpn easy-rsa
        elif [[ "$OS" == "centos" ]]; then
            yum install -y epel-release
            yum install -y openvpn easy-rsa
        fi

        # 检查安装结果
        if ! command -v openvpn &>/dev/null; then
            log "${RED}安装 OpenVPN 失败${NC}"
            return 1
        else
            log "${GREEN}成功安装 OpenVPN${NC}"
        fi
    fi

    # 检查 OpenVPN 是否正在运行
    if ! systemctl is-active --quiet openvpn@server; then
        log "${RED}错误: OpenVPN 服务未运行${NC}"
        log "${YELLOW}尝试启动 OpenVPN 服务...${NC}"
        systemctl start openvpn@server
        sleep 2
        if ! systemctl is-active --quiet openvpn@server; then
            log "${RED}无法启动 OpenVPN 服务${NC}"
            log "${YELLOW}检查服务日志...${NC}"
            journalctl -u openvpn@server -n 20 --no-pager

            # 尝试修复服务配置
            log "${YELLOW}尝试修复服务配置...${NC}"

            # 检查服务单元文件
            if [ ! -f "/lib/systemd/system/openvpn@.service" ] && [ ! -f "/usr/lib/systemd/system/openvpn@.service" ]; then
                log "${YELLOW}创建OpenVPN服务单元文件...${NC}"
                cat > /lib/systemd/system/openvpn@.service << EOF
[Unit]
Description=OpenVPN connection to %i
After=network.target

[Service]
Type=forking
ExecStart=/usr/sbin/openvpn --daemon --writepid /run/openvpn/%i.pid --cd /etc/openvpn/ --config %i.conf
PIDFile=/run/openvpn/%i.pid
WorkingDirectory=/etc/openvpn
ProtectSystem=yes
CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID CAP_SYS_CHROOT CAP_DAC_OVERRIDE
LimitNPROC=10
DeviceAllow=/dev/null rw
DeviceAllow=/dev/net/tun rw

[Install]
WantedBy=multi-user.target
EOF
                mkdir -p /run/openvpn
                systemctl daemon-reload
            fi

            # 再次尝试启动服务
            systemctl start openvpn@server
            sleep 2
            if ! systemctl is-active --quiet openvpn@server; then
                log "${RED}修复后仍无法启动服务，请检查配置文件${NC}"

                # 检查配置文件
                if [ -f "/etc/openvpn/server.conf" ]; then
                    log "${YELLOW}验证配置文件...${NC}"
                    openvpn --config /etc/openvpn/server.conf --test-crypto
                fi

                return 1
            else
                log "${GREEN}修复后成功启动服务${NC}"
            fi
        else
            log "${GREEN}成功启动 OpenVPN 服务${NC}"
        fi
    fi

    # 检查ta.key是否存在
    if [ ! -f "/etc/openvpn/ta.key" ]; then
        log "${RED}错误: ta.key文件不存在${NC}"
        log "${YELLOW}正在生成ta.key文件...${NC}"
        openvpn --genkey --secret /etc/openvpn/ta.key
        if [ ! -f "/etc/openvpn/ta.key" ]; then
            log "${RED}无法生成ta.key文件${NC}"
            return 1
        else
            log "${GREEN}成功生成ta.key文件${NC}"
            chmod 600 /etc/openvpn/ta.key
            # 设置标志，表示ta.key已更新
            echo "$(date '+%Y-%m-%d %H:%M:%S')" > /etc/openvpn/ta.key.updated
            log "${YELLOW}警告: 现有客户端将无法连接，需要更新客户端配置${NC}"
        fi
    fi

    # 检查ta.key是否最近被更新
    if [ -f "/etc/openvpn/ta.key.updated" ]; then
        log "${YELLOW}警告: ta.key文件已被更新${NC}"
        log "${YELLOW}这可能导致现有客户端无法连接${NC}"
        log "${YELLOW}请使用'更新客户端ta.key'选项更新客户端配置${NC}"
    fi

    # 检查文件权限
    log "${BLUE}检查文件权限...${NC}"
    if [ -f "/etc/openvpn/server.conf" ]; then
        chmod 644 /etc/openvpn/server.conf
        log "${GREEN}已设置server.conf权限${NC}"
    fi

    if [ -f "/etc/openvpn/ta.key" ]; then
        chmod 600 /etc/openvpn/ta.key
        log "${GREEN}已设置ta.key权限${NC}"
    fi

    if [ -f "/etc/openvpn/ca.crt" ]; then
        chmod 644 /etc/openvpn/ca.crt
        log "${GREEN}已设置ca.crt权限${NC}"
    fi

    if [ -f "/etc/openvpn/dh.pem" ]; then
        chmod 644 /etc/openvpn/dh.pem
        log "${GREEN}已设置dh.pem权限${NC}"
    fi

    # 检查服务器证书和密钥
    local server_name=$(grep -E "^cert " /etc/openvpn/server.conf | awk '{print $2}' | sed 's/.crt//')
    if [ -z "$server_name" ]; then
        server_name="server"
    fi

    if [ -f "/etc/openvpn/${server_name}.crt" ]; then
        chmod 644 "/etc/openvpn/${server_name}.crt"
        log "${GREEN}已设置${server_name}.crt权限${NC}"
    fi

    if [ -f "/etc/openvpn/${server_name}.key" ]; then
        chmod 600 "/etc/openvpn/${server_name}.key"
        log "${GREEN}已设置${server_name}.key权限${NC}"
    fi

    # 检查防火墙设置
    log "${BLUE}检查防火墙设置...${NC}"
    local port=$(grep -E "^port " /etc/openvpn/server.conf | awk '{print $2}')
    local protocol=$(grep -E "^proto " /etc/openvpn/server.conf | awk '{print $2}')

    if [ -z "$port" ]; then
        port="1194"
    fi

    if [ -z "$protocol" ]; then
        protocol="udp"
    fi

    # 检测主网络接口
    local main_interface=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
    if [ -z "$main_interface" ]; then
        main_interface="eth0"
        log "${YELLOW}警告: 无法检测到主网络接口，使用默认值 eth0${NC}"
    fi

    # 检查iptables
    if ! iptables -L INPUT -n | grep -q "$protocol dpt:$port"; then
        log "${YELLOW}警告: iptables中未找到OpenVPN端口规则，正在添加...${NC}"
        iptables -A INPUT -i $main_interface -p $protocol --dport $port -j ACCEPT
        log "${GREEN}已添加iptables端口规则${NC}"
    else
        log "${GREEN}iptables防火墙规则正常${NC}"
    fi

    # 检查tun接口规则
    if ! iptables -C INPUT -i tun+ -j ACCEPT 2>/dev/null; then
        log "${YELLOW}警告: iptables中未找到tun接口规则，正在添加...${NC}"
        iptables -A INPUT -i tun+ -j ACCEPT
        iptables -A FORWARD -i tun+ -j ACCEPT
        iptables -A FORWARD -i tun+ -o $main_interface -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A FORWARD -i $main_interface -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
        log "${GREEN}已添加iptables tun接口规则${NC}"
    fi

    # 检查UFW
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        if ! ufw status | grep -q "$port/$protocol"; then
            log "${YELLOW}警告: UFW中未找到OpenVPN端口规则，正在添加...${NC}"
            ufw allow $port/$protocol
            log "${GREEN}已添加UFW端口规则${NC}"
        else
            log "${GREEN}UFW防火墙规则正常${NC}"
        fi
    fi

    # 检查firewalld
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        if ! firewall-cmd --list-ports | grep -q "$port/$protocol"; then
            log "${YELLOW}警告: firewalld中未找到OpenVPN端口规则，正在添加...${NC}"
            firewall-cmd --permanent --add-port=$port/$protocol
            firewall-cmd --permanent --add-service=openvpn
            firewall-cmd --reload
            log "${GREEN}已添加firewalld端口规则${NC}"
        else
            log "${GREEN}firewalld防火墙规则正常${NC}"
        fi
    fi

    # 检查IP转发
    log "${BLUE}检查IP转发...${NC}"
    local ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if [ "$ip_forward" != "1" ]; then
        log "${YELLOW}警告: IP转发未启用，正在启用...${NC}"
        echo 1 > /proc/sys/net/ipv4/ip_forward
        sysctl -w net.ipv4.ip_forward=1
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
        sysctl -p
        log "${GREEN}IP转发已启用${NC}"
    else
        log "${GREEN}IP转发已启用${NC}"
    fi

    # 检查NAT规则
    log "${BLUE}检查NAT规则...${NC}"
    if [ -z "$main_interface" ]; then
        log "${YELLOW}警告: 无法检测到主网络接口${NC}"
    else
        # 获取VPN子网
        local vpn_subnet=$(grep -E "^server " /etc/openvpn/server.conf | awk '{print $2}')
        local vpn_netmask=$(grep -E "^server " /etc/openvpn/server.conf | awk '{print $3}')

        if [ -z "$vpn_subnet" ]; then
            vpn_subnet="10.8.0.0"
        fi

        if [ -z "$vpn_netmask" ]; then
            vpn_netmask="255.255.255.0"
        fi

        if ! iptables -t nat -C POSTROUTING -s $vpn_subnet/$vpn_netmask -o $main_interface -j MASQUERADE 2>/dev/null; then
            log "${YELLOW}警告: 未找到NAT规则，正在添加...${NC}"
            iptables -t nat -A POSTROUTING -s $vpn_subnet/$vpn_netmask -o $main_interface -j MASQUERADE

            # 验证NAT规则是否已应用
            if ! iptables -t nat -C POSTROUTING -s $vpn_subnet/$vpn_netmask -o $main_interface -j MASQUERADE 2>/dev/null; then
                log "${RED}错误: 无法应用iptables NAT规则，尝试备选方法${NC}"
                # 备选方法：使用SNAT而不是MASQUERADE
                local server_ip=$(ip -4 addr show $main_interface | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
                if [ -n "$server_ip" ]; then
                    iptables -t nat -A POSTROUTING -s $vpn_subnet/$vpn_netmask -j SNAT --to-source $server_ip
                    log "${YELLOW}已尝试使用备选NAT方法${NC}"
                else
                    log "${RED}错误: 无法获取服务器IP地址，NAT规则添加失败${NC}"
                fi
            else
                log "${GREEN}已添加NAT规则${NC}"
            fi
        else
            log "${GREEN}NAT规则正常${NC}"
        fi

        # 保存iptables规则
        if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
            if [ -d "/etc/iptables" ]; then
                iptables-save > /etc/iptables/rules.v4
                log "${GREEN}已保存iptables规则${NC}"
            fi
        elif [[ "$OS" == "centos" ]]; then
            if command -v service &>/dev/null; then
                service iptables save
                log "${GREEN}已保存iptables规则${NC}"
            fi
        fi
    fi

    # 检查日志文件中的错误
    log "${BLUE}检查OpenVPN日志文件...${NC}"
    local log_found=false
    local log_files=("/var/log/openvpn.log" "/var/log/openvpn/openvpn.log" "/etc/openvpn/openvpn.log")

    for log_file in "${log_files[@]}"; do
        if [ -f "$log_file" ]; then
            log_found=true
            local auth_errors=$(grep -i "auth" "$log_file" | grep -i "fail\|error" | tail -5)
            local tls_errors=$(grep -i "tls" "$log_file" | grep -i "fail\|error" | tail -5)
            local ta_errors=$(grep -i "ta.key" "$log_file" | grep -i "fail\|error" | tail -5)

            if [ -n "$auth_errors" ]; then
                log "${YELLOW}发现认证错误:${NC}"
                echo "$auth_errors"
                log "${YELLOW}这可能表明客户端证书有问题${NC}"
                log "${YELLOW}建议重新生成客户端证书${NC}"
            fi

            if [ -n "$tls_errors" ]; then
                log "${YELLOW}发现TLS错误:${NC}"
                echo "$tls_errors"
                log "${YELLOW}这可能表明TLS设置有问题${NC}"
                log "${YELLOW}正在检查TLS设置...${NC}"

                # 检查TLS版本设置
                local tls_version=$(grep -E "^tls-version-min " /etc/openvpn/server.conf | awk '{print $2}')
                if [ -z "$tls_version" ]; then
                    log "${YELLOW}未找到TLS版本设置，添加默认设置...${NC}"
                    echo "tls-version-min 1.2" >> /etc/openvpn/server.conf
                    log "${GREEN}已添加TLS版本设置${NC}"
                fi
            fi

            if [ -n "$ta_errors" ]; then
                log "${YELLOW}发现ta.key错误:${NC}"
                echo "$ta_errors"
                log "${YELLOW}这可能表明客户端和服务器的ta.key不匹配${NC}"
                log "${YELLOW}正在重新生成ta.key...${NC}"

                # 备份旧的ta.key
                if [ -f "/etc/openvpn/ta.key" ]; then
                    cp /etc/openvpn/ta.key /etc/openvpn/ta.key.bak
                    log "${GREEN}已备份旧的ta.key${NC}"
                fi

                # 生成新的ta.key
                openvpn --genkey --secret /etc/openvpn/ta.key
                chmod 600 /etc/openvpn/ta.key
                echo "$(date '+%Y-%m-%d %H:%M:%S')" > /etc/openvpn/ta.key.updated
                log "${GREEN}已重新生成ta.key${NC}"
                log "${YELLOW}请使用'更新客户端ta.key'选项更新客户端配置${NC}"
            fi

            break
        fi
    done

    if [ "$log_found" = false ]; then
        log "${YELLOW}未找到OpenVPN日志文件，创建日志目录...${NC}"
        mkdir -p /var/log/openvpn
        touch /var/log/openvpn/openvpn.log
        chmod 644 /var/log/openvpn/openvpn.log

        # 确保日志设置在配置文件中
        if [ -f "/etc/openvpn/server.conf" ]; then
            if ! grep -q "^log " /etc/openvpn/server.conf; then
                echo "log /var/log/openvpn/openvpn.log" >> /etc/openvpn/server.conf
                log "${GREEN}已添加日志设置到配置文件${NC}"
            fi
        fi
    fi

    # 重启OpenVPN服务以应用更改
    log "${BLUE}重启OpenVPN服务以应用更改...${NC}"

    # 确保NAT规则已正确应用
    log "${BLUE}确保NAT规则已正确应用...${NC}"
    if [ -n "$main_interface" ] && [ -n "$vpn_subnet" ] && [ -n "$vpn_netmask" ]; then
        if ! iptables -t nat -C POSTROUTING -s $vpn_subnet/$vpn_netmask -o $main_interface -j MASQUERADE 2>/dev/null; then
            log "${YELLOW}再次尝试添加NAT规则...${NC}"
            iptables -t nat -A POSTROUTING -s $vpn_subnet/$vpn_netmask -o $main_interface -j MASQUERADE

            # 验证NAT规则是否已应用
            if ! iptables -t nat -C POSTROUTING -s $vpn_subnet/$vpn_netmask -o $main_interface -j MASQUERADE 2>/dev/null; then
                log "${RED}错误: 无法应用iptables NAT规则，尝试备选方法${NC}"
                # 备选方法：使用SNAT而不是MASQUERADE
                local server_ip=$(ip -4 addr show $main_interface | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
                if [ -n "$server_ip" ]; then
                    iptables -t nat -A POSTROUTING -s $vpn_subnet/$vpn_netmask -j SNAT --to-source $server_ip
                    log "${YELLOW}已尝试使用备选NAT方法${NC}"
                else
                    log "${RED}错误: 无法获取服务器IP地址，NAT规则添加失败${NC}"
                fi
            else
                log "${GREEN}已成功添加NAT规则${NC}"
            fi

            # 保存iptables规则
            if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
                if [ -d "/etc/iptables" ]; then
                    iptables-save > /etc/iptables/rules.v4
                    log "${GREEN}已保存iptables规则${NC}"
                fi
            elif [[ "$OS" == "centos" ]]; then
                if command -v service &>/dev/null; then
                    service iptables save
                    log "${GREEN}已保存iptables规则${NC}"
                fi
            fi
        else
            log "${GREEN}NAT规则已正确应用${NC}"
        fi
    fi

    systemctl restart openvpn@server
    sleep 2
    if systemctl is-active --quiet openvpn@server; then
        log "${GREEN}OpenVPN服务已成功重启${NC}"
    else
        log "${RED}OpenVPN服务重启失败${NC}"
        log "${YELLOW}检查服务日志...${NC}"
        journalctl -u openvpn@server -n 20 --no-pager
    fi

    # 输出诊断结果摘要 - 使用与问题描述中相同的格式
    echo ""
    echo -e "${GREEN}诊断提示${NC}"

    # 检查NAT规则并输出警告
    if [ -z "$main_interface" ]; then
        echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}警告: 无法检测到主网络接口${NC}"
        echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}这可能导致客户端无法访问互联网${NC}"
    elif ! iptables -t nat -C POSTROUTING -s $vpn_subnet/$vpn_netmask -o $main_interface -j MASQUERADE 2>/dev/null; then
        # 检查是否使用了备选SNAT方法
        local server_ip=$(ip -4 addr show $main_interface | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        if [ -n "$server_ip" ] && iptables -t nat -C POSTROUTING -s $vpn_subnet/$vpn_netmask -j SNAT --to-source $server_ip 2>/dev/null; then
            echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}使用备选SNAT方法配置了NAT规则${NC}"
        else
            echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}警告: 未找到NAT规则${NC}"
            echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}这可能导致客户端无法访问互联网${NC}"
        fi
    fi

    # 检查OpenVPN日志文件
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}检查OpenVPN日志文件...${NC}"
    if [ "$log_found" = false ]; then
        echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}未找到OpenVPN日志文件${NC}"
    fi

    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}诊断和修复完成${NC}"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}如果您仍然遇到连接问题，请尝试以下操作:${NC}"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}1. 使用'更新客户端ta.key'选项更新客户端配置${NC}"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}2. 使用'修复当前安装'选项修复安装${NC}"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}3. 重启OpenVPN服务${NC}"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}4. 检查客户端日志以获取更多信息${NC}"

    # 等待用户按任意键继续
    echo -e "\n按任意键返回主菜单..."
    read -n 1 -s
    return 0
}

# 函数: 显示 VPN 实时状态
show_vpn_status() {
    log "${BLUE}显示 OpenVPN 实时状态...${NC}"

    # 检查 OpenVPN 是否已安装
    if ! command -v openvpn &>/dev/null; then
        log "${RED}错误: OpenVPN 未安装${NC}"
        return 1
    fi

    # 检查 OpenVPN 是否正在运行
    if ! systemctl is-active --quiet openvpn@server; then
        log "${RED}错误: OpenVPN 服务未运行${NC}"
        return 1
    fi

    # 检查状态日志文件
    STATUS_LOG=""
    if [ -f "/var/log/openvpn/openvpn-status.log" ]; then
        STATUS_LOG="/var/log/openvpn/openvpn-status.log"
    elif [ -f "/etc/openvpn/openvpn-status.log" ]; then
        STATUS_LOG="/etc/openvpn/openvpn-status.log"
    else
        log "${RED}错误: 找不到 OpenVPN 状态日志文件${NC}"
        return 1
    fi

    # 清屏并显示标题
    clear
    echo -e "${BLUE}=== OpenVPN 实时状态监控 ===${NC}"
    echo -e "${YELLOW}按 Ctrl+C 退出监控${NC}\n"

    # 使用 watch 命令实时显示状态
    # 创建临时脚本
    TEMP_SCRIPT=$(mktemp)
    cat > "$TEMP_SCRIPT" << 'EOF'
#!/bin/bash
# 定义颜色
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# 获取状态日志文件路径
if [ -f "/var/log/openvpn/openvpn-status.log" ]; then
    STATUS_LOG="/var/log/openvpn/openvpn-status.log"
elif [ -f "/etc/openvpn/openvpn-status.log" ]; then
    STATUS_LOG="/etc/openvpn/openvpn-status.log"
else
    echo -e "${RED}错误: 找不到 OpenVPN 状态日志文件${NC}"
    exit 1
fi

# 显示更新时间
echo -e "${BLUE}状态更新时间:${NC} $(date '+%Y-%m-%d %H:%M:%S')"

# 显示服务状态
if systemctl is-active --quiet openvpn@server; then
    echo -e "${BLUE}服务状态:${NC} ${GREEN}运行中${NC}"
else
    echo -e "${BLUE}服务状态:${NC} ${RED}未运行${NC}"
    exit 0
fi

# 显示连接的客户端
echo -e "\n${BLUE}已连接的客户端:${NC}"
echo -e "------------------------------------------------------------------------------------------------------------"
echo -e "| ${YELLOW}客户端名称            | 远程 IP             | 虚拟 IP        | 已连接时间      | 接收字节    | 发送字节    ${NC}|"
echo -e "------------------------------------------------------------------------------------------------------------"

# 解析状态日志文件
CLIENT_SECTION=false
ROUTING_SECTION=false
CLIENT_COUNT=0

# 创建数组来存储客户端信息
declare -a CLIENT_NAMES
declare -a REMOTE_IPS
declare -a REMOTE_PORTS
declare -a VIRTUAL_IPS
declare -a BYTES_RECEIVEDS
declare -a BYTES_SENTS
declare -a CONNECTED_SINCES

# 第一遍：收集所有客户端信息
while IFS= read -r line; do
    if [[ "$line" == "ROUTING TABLE" ]]; then
        CLIENT_SECTION=false
        continue
    elif [[ "$line" == "Updated,"* ]]; then
        # 这是日志文件的更新时间行，跳过
        continue
    elif [[ "$line" == "Common Name"* ]]; then
        # 这是客户端列表的标题行，开始客户端部分
        CLIENT_SECTION=true
        continue
    fi

    if [[ "$CLIENT_SECTION" == true && -n "$line" ]]; then
        # 解析客户端行
        CLIENT_NAME=$(echo "$line" | awk '{print $1}')
        REMOTE_IP=$(echo "$line" | awk '{print $2}' | cut -d: -f1)
        REMOTE_PORT=$(echo "$line" | awk '{print $2}' | cut -d: -f2)
        BYTES_RECEIVED=$(echo "$line" | awk '{print $3}')
        BYTES_SENT=$(echo "$line" | awk '{print $4}')
        CONNECTED_SINCE=$(echo "$line" | awk '{print $5, $6, $7, $8}')

        # 格式化字节数
        if [[ "$BYTES_RECEIVED" -ge 1073741824 ]]; then
            BYTES_RECEIVED=$(echo "scale=2; $BYTES_RECEIVED/1073741824" | bc)" GB"
        elif [[ "$BYTES_RECEIVED" -ge 1048576 ]]; then
            BYTES_RECEIVED=$(echo "scale=2; $BYTES_RECEIVED/1048576" | bc)" MB"
        elif [[ "$BYTES_RECEIVED" -ge 1024 ]]; then
            BYTES_RECEIVED=$(echo "scale=2; $BYTES_RECEIVED/1024" | bc)" KB"
        else
            BYTES_RECEIVED="$BYTES_RECEIVED B"
        fi

        if [[ "$BYTES_SENT" -ge 1073741824 ]]; then
            BYTES_SENT=$(echo "scale=2; $BYTES_SENT/1073741824" | bc)" GB"
        elif [[ "$BYTES_SENT" -ge 1048576 ]]; then
            BYTES_SENT=$(echo "scale=2; $BYTES_SENT/1048576" | bc)" MB"
        elif [[ "$BYTES_SENT" -ge 1024 ]]; then
            BYTES_SENT=$(echo "scale=2; $BYTES_SENT/1024" | bc)" KB"
        else
            BYTES_SENT="$BYTES_SENT B"
        fi

        # 存储客户端信息到数组
        CLIENT_NAMES+=("$CLIENT_NAME")
        REMOTE_IPS+=("$REMOTE_IP")
        REMOTE_PORTS+=("$REMOTE_PORT")
        VIRTUAL_IPS+=("")  # 初始化为空，稍后从路由表中获取
        BYTES_RECEIVEDS+=("$BYTES_RECEIVED")
        BYTES_SENTS+=("$BYTES_SENT")
        CONNECTED_SINCES+=("$CONNECTED_SINCE")

        CLIENT_COUNT=$((CLIENT_COUNT + 1))
    fi
done < "$STATUS_LOG"

# 第二遍：从路由表中获取虚拟 IP
ROUTING_SECTION=false
while IFS= read -r line; do
    if [[ "$line" == "ROUTING TABLE" ]]; then
        ROUTING_SECTION=true
        continue
    elif [[ "$line" == "GLOBAL STATS" ]]; then
        ROUTING_SECTION=false
        continue
    fi

    if [[ "$ROUTING_SECTION" == true && -n "$line" && "$line" != "Virtual Address"* ]]; then
        # 解析路由表行，查找虚拟 IP
        R_VIRTUAL_IP=$(echo "$line" | awk '{print $1}')
        R_CLIENT_NAME=$(echo "$line" | awk '{print $2}')

        # 更新对应客户端的虚拟 IP
        for i in "${!CLIENT_NAMES[@]}"; do
            if [[ "${CLIENT_NAMES[$i]}" == "$R_CLIENT_NAME" ]]; then
                VIRTUAL_IPS[$i]="$R_VIRTUAL_IP"
                break
            fi
        done
    fi
done < "$STATUS_LOG"

# 显示所有客户端信息
for i in "${!CLIENT_NAMES[@]}"; do
    # 如果没有找到虚拟 IP，使用占位符
    if [[ -z "${VIRTUAL_IPS[$i]}" ]]; then
        VIRTUAL_IPS[$i]="N/A"
    fi

    printf "| %-22s | %-20s | %-14s | %-16s | %-12s | %-12s |\n" \
        "${CLIENT_NAMES[$i]}" "${REMOTE_IPS[$i]}:${REMOTE_PORTS[$i]}" "${VIRTUAL_IPS[$i]}" "${CONNECTED_SINCES[$i]}" "${BYTES_RECEIVEDS[$i]}" "${BYTES_SENTS[$i]}"
done

echo -e "------------------------------------------------------------------------------------------------------------"

# 如果没有客户端连接，显示提示
if [[ "$CLIENT_COUNT" -eq 0 ]]; then
    echo -e "${YELLOW}当前没有客户端连接${NC}"
fi

# 显示系统负载
echo -e "\n${BLUE}系统负载:${NC}"
uptime

# 显示网络接口统计
echo -e "\n${BLUE}网络接口统计:${NC}"
INTERFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
if [[ -n "$INTERFACE" ]]; then
    echo -e "接口: $INTERFACE"
    ifconfig "$INTERFACE" | grep -E "RX|TX"
fi

# 显示 OpenVPN 进程信息
echo -e "\n${BLUE}OpenVPN 进程:${NC}"
ps aux | grep "[o]penvpn"
EOF

    # 使脚本可执行
    chmod +x "$TEMP_SCRIPT"

    # 使用 watch 命令每 2 秒更新一次
    watch -c -n 2 "$TEMP_SCRIPT"

    # 清理临时脚本
    rm -f "$TEMP_SCRIPT"
}

# 函数: 交互式配置向导
interactive_wizard() {
    echo -e "${BLUE}OpenVPN 交互式配置向导${NC}"
    echo -e "${BLUE}==============================${NC}"
    echo "此向导将帮助您配置 OpenVPN 服务器。"
    echo "对于每个选项，您可以按 Enter 键接受默认值，或输入新值。"
    echo ""

    # 基本选项
    echo -e "${BLUE}基本选项:${NC}"

    # 选择协议
    echo -e "${BLUE}请选择 OpenVPN 传输协议:${NC}"
    echo "1) UDP (推荐，性能更好，使用端口 1194)"
    echo "2) TCP (更可靠，适合某些网络环境，使用端口 443)"
    while true; do
        echo -n "请输入选项 [1-2] (默认: 1): "
        read -r proto_option

        if [ -z "$proto_option" ]; then
            proto_option="1"
        fi

        case $proto_option in
            1)
                PROTOCOL="udp"
                PORT=1194
                log "${GREEN}已选择 UDP 协议，端口设置为 1194${NC}"
                break
                ;;
            2)
                PROTOCOL="tcp"
                PORT=443
                log "${GREEN}已选择 TCP 协议，端口设置为 443${NC}"
                break
                ;;
            *)
                echo -e "${RED}无效选项，请重新输入${NC}"
                ;;
        esac
    done

    # 设置端口（可选，允许用户覆盖默认端口）
    echo -e "${BLUE}当前端口设置为: $PORT${NC}"
    echo -n "是否要修改端口? [y/N]: "
    read -r change_port
    if [[ "$change_port" == "y" || "$change_port" == "Y" ]]; then
        echo -n "请输入 OpenVPN 端口 (1-65535): "
        read -r port_input
        if [ -n "$port_input" ]; then
            if [[ "$port_input" =~ ^[0-9]+$ ]] && [ "$port_input" -ge 1 ] && [ "$port_input" -le 65535 ]; then
                PORT="$port_input"
                log "${GREEN}端口已修改为: $PORT${NC}"
            else
                echo -e "${YELLOW}无效端口，保持默认值: $PORT${NC}"
            fi
        fi
    fi

    # 设置客户端名称
    echo -n "请输入客户端名称 (默认: $CLIENT_NAME): "
    read -r client_input
    if [ -n "$client_input" ]; then
        if [[ "$client_input" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            CLIENT_NAME="$client_input"
        else
            echo -e "${YELLOW}无效客户端名称，使用默认值: $CLIENT_NAME${NC}"
        fi
    fi

    # 设置 DNS 服务器
    echo -n "请输入 DNS 服务器 (格式: DNS1,DNS2) (默认: $DNS1,$DNS2): "
    read -r dns_input
    if [ -n "$dns_input" ]; then
        IFS=',' read -r dns1 dns2 <<< "$dns_input"
        if [[ "$dns1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            DNS1="$dns1"
        fi
        if [[ "$dns2" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            DNS2="$dns2"
        fi
    fi

    # 高级选项
    echo ""
    echo -n "是否配置高级选项? [y/N]: "
    read -r advanced_option

    if [[ "$advanced_option" == "y" || "$advanced_option" == "Y" ]]; then
        echo -e "${BLUE}高级选项:${NC}"

        # TLS 版本
        echo -e "${BLUE}请选择 TLS 版本:${NC}"
        echo "1) 1.2 (兼容性更好，适用于大多数客户端)"
        echo "2) 1.3 (安全性更高，但可能不兼容某些旧客户端)"
        while true; do
            echo -n "请输入选项 [1-2] (默认: 1): "
            read -r tls_option

            if [ -z "$tls_option" ]; then
                tls_option="1"
            fi

            case $tls_option in
                1)
                    TLS_VERSION="1.2"
                    log "${GREEN}已选择 TLS 1.2${NC}"
                    break
                    ;;
                2)
                    TLS_VERSION="1.3"
                    log "${GREEN}已选择 TLS 1.3${NC}"
                    break
                    ;;
                *)
                    echo -e "${RED}无效选项，请重新输入${NC}"
                    ;;
            esac
        done

        # 保持连接参数
        echo -n "请输入保持连接参数 (格式: PING,TIMEOUT) (默认: $KEEPALIVE_PING,$KEEPALIVE_TIMEOUT): "
        read -r keepalive_input
        if [ -n "$keepalive_input" ]; then
            IFS=',' read -r ping timeout <<< "$keepalive_input"
            if [[ "$ping" =~ ^[0-9]+$ ]] && [[ "$timeout" =~ ^[0-9]+$ ]]; then
                KEEPALIVE_PING="$ping"
                KEEPALIVE_TIMEOUT="$timeout"
            else
                echo -e "${YELLOW}无效格式，使用默认值: $KEEPALIVE_PING,$KEEPALIVE_TIMEOUT${NC}"
            fi
        fi

        # 日志级别
        echo -n "请输入日志级别 (0-9) (默认: $LOG_LEVEL): "
        read -r log_level_input
        if [ -n "$log_level_input" ]; then
            if [[ "$log_level_input" =~ ^[0-9]$ ]]; then
                LOG_LEVEL="$log_level_input"
            else
                echo -e "${YELLOW}无效日志级别，使用默认值: $LOG_LEVEL${NC}"
            fi
        fi

        # 最大客户端连接数
        echo -n "请输入最大客户端连接数 (默认: $MAX_CLIENTS): "
        read -r max_clients_input
        if [ -n "$max_clients_input" ]; then
            if [[ "$max_clients_input" =~ ^[0-9]+$ ]] && [ "$max_clients_input" -gt 0 ]; then
                MAX_CLIENTS="$max_clients_input"
            else
                echo -e "${YELLOW}无效值，使用默认值: $MAX_CLIENTS${NC}"
            fi
        fi

        # 布尔选项
        echo -n "是否启用 IPv6 支持? [y/N]: "
        read -r ipv6_option
        if [[ "$ipv6_option" == "y" || "$ipv6_option" == "Y" ]]; then
            ENABLE_IPV6=true
        fi

        echo -n "是否允许重复的 Common Name (多个客户端使用同一个证书)? [y/N]: "
        read -r duplicate_cn_option
        if [[ "$duplicate_cn_option" == "y" || "$duplicate_cn_option" == "Y" ]]; then
            DUPLICATE_CN=true
        fi

        echo -n "是否阻止 DNS 泄漏? [y/N]: "
        read -r block_dns_option
        if [[ "$block_dns_option" == "y" || "$block_dns_option" == "Y" ]]; then
            PUSH_BLOCK_DNS=true
        fi

        echo -n "是否允许客户端之间通信? [y/N]: "
        read -r client_to_client_option
        if [[ "$client_to_client_option" == "y" || "$client_to_client_option" == "Y" ]]; then
            CLIENT_TO_CLIENT=true
        fi
    fi

    # 输出目录和文件名
    echo ""
    echo -e "${BLUE}输出选项:${NC}"

    echo -n "请输入客户端配置文件输出目录 (默认: $OUTPUT_DIR): "
    read -r output_dir_input
    if [ -n "$output_dir_input" ]; then
        OUTPUT_DIR="$output_dir_input"
        # 验证输出目录
        if [ ! -d "$OUTPUT_DIR" ]; then
            echo -e "${YELLOW}警告: 输出目录不存在，将尝试创建${NC}"
            mkdir -p "$OUTPUT_DIR" || error_exit "无法创建输出目录: $OUTPUT_DIR"
        fi
        if [ ! -w "$OUTPUT_DIR" ]; then
            echo -e "${YELLOW}警告: 输出目录不可写，使用默认值: $SCRIPT_DIR${NC}"
            OUTPUT_DIR="$SCRIPT_DIR"
        fi
    fi

    echo -n "请输入客户端配置文件名称 (默认: ${CLIENT_NAME}.ovpn): "
    read -r output_file_input
    if [ -n "$output_file_input" ]; then
        OUTPUT_FILE="$output_file_input"
        if [[ "$OUTPUT_FILE" != *.ovpn ]]; then
            OUTPUT_FILE="${OUTPUT_FILE}.ovpn"
        fi
    else
        OUTPUT_FILE="${CLIENT_NAME}.ovpn"
    fi

    echo ""
    echo -e "${GREEN}配置完成！${NC}"
    echo "按 Enter 键继续安装..."
    read -r
}

# 函数: 设置协议（默认使用UDP）
select_protocol() {
    # 强制使用UDP协议，移除TCP选项
    PROTOCOL="udp"

    # 如果端口未通过命令行参数设置，则使用随机端口以避免封锁
    if [ "$PORT" = "1194" ] && [ "$PROTOCOL_SET_BY_ARG" = false ]; then
        # 生成一个随机端口号（10000-65000范围内）
        PORT=$((RANDOM % 55000 + 10000))
        log "${GREEN}为避免运营商封锁，使用随机端口: $PORT${NC}"
    else
        log "${GREEN}使用指定端口: $PORT${NC}"
    fi

    log "${GREEN}使用 UDP 协议${NC}"
}

# 函数: 交互式选择输出文件名
select_output_file() {
    if [ "$OUTPUT_FILE_SET_BY_ARG" = false ]; then
        echo -e "${BLUE}请输入客户端配置文件名称:${NC}"
        echo "默认文件名为: ${CLIENT_NAME}.ovpn"
        echo -n "请输入文件名 (直接按 Enter 使用默认值): "
        read -r output_file_input

        if [ -n "$output_file_input" ]; then
            OUTPUT_FILE="$output_file_input"
            if [[ "$OUTPUT_FILE" != *.ovpn ]]; then
                log "${YELLOW}警告: 输出文件名 $OUTPUT_FILE 没有 .ovpn 扩展名，将自动添加${NC}"
                OUTPUT_FILE="${OUTPUT_FILE}.ovpn"
            fi
            log "${GREEN}已设置输出文件名: $OUTPUT_FILE${NC}"
        else
            OUTPUT_FILE="${CLIENT_NAME}.ovpn"
            log "${GREEN}使用默认输出文件名: $OUTPUT_FILE${NC}"
        fi
    else
        log "${GREEN}使用命令行指定的输出文件名: $OUTPUT_FILE${NC}"
    fi
}

# 函数: 选择设备类型（移动设备或桌面端）
select_device_type() {
    # 如果未通过命令行参数设置移动设备选项
    if [ "$MOBILE_DEVICE" = false ]; then
        echo -n "是否为移动设备生成配置？(避免使用不支持的 fragment 指令) [y/N]: "
        read -r mobile_choice
        if [[ "$mobile_choice" =~ ^[Yy]$ ]]; then
            MOBILE_DEVICE=true
            log "${BLUE}将生成移动设备专用配置 (不包含 fragment 指令)${NC}"
        else
            log "${BLUE}将生成标准桌面端配置${NC}"
        fi
    else
        log "${BLUE}通过命令行参数指定生成移动设备专用配置${NC}"
    fi
}

# 函数: 显示安装完成信息
show_completion() {
    log "${GREEN}OpenVPN 安装和配置已完成！${NC}"
    log "${BLUE}服务器信息:${NC}"
    log "  协议: $PROTOCOL"
    log "  端口: $PORT"
    log "  子网: $VPN_SUBNET/$VPN_NETMASK"

    # 获取服务器 IP
    SERVER_IP=$(curl -s ifconfig.me)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    log "  服务器 IP: $SERVER_IP"

    log "${BLUE}客户端信息:${NC}"
    # 确定最终的输出文件名
    FINAL_OUTPUT_FILE="$OUTPUT_FILE"
    if [ -z "$FINAL_OUTPUT_FILE" ]; then
        FINAL_OUTPUT_FILE="${CLIENT_NAME}.ovpn"
    fi
    log "  客户端配置文件: ${OUTPUT_DIR}/${FINAL_OUTPUT_FILE}"
    log "  请使用安全的方式将此文件传输到客户端设备"

    log "${YELLOW}重要提示:${NC}"
    log "  1. 防火墙已自动配置允许 $PORT/$PROTOCOL 端口的流量"
    log "  2. 如需创建更多客户端，请重新执行当前脚本并选择选项 \"1) 生成新的客户端配置文件\""
    log "  3. 安装日志保存在: $LOG_FILE"

    # 显示失败命令日志（如果有）
    if [ -n "$FAILED_COMMANDS" ]; then
        log "${RED}警告: 以下命令执行失败或出现问题:${NC}"
        echo -e "$FAILED_COMMANDS" | while read -r line; do
            if [ -n "$line" ]; then
                log "  $line"
            fi
        done
        log "${YELLOW}请检查上述问题，可能需要手动修复${NC}"
    fi
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -t|--protocol)
            # 强制使用UDP协议，忽略用户输入
            PROTOCOL="udp"
            log "${YELLOW}注意: 为避免中国运营商封锁，脚本已被修改为仅支持UDP协议${NC}"
            PROTOCOL_SET_BY_ARG=true
            shift 2
            ;;
        -c|--client)
            CLIENT_NAME="$2"
            shift 2
            ;;
        -d|--dns)
            IFS=',' read -r DNS1 DNS2 <<< "$2"
            shift 2
            ;;
        -s|--subnet)
            VPN_SUBNET="$2"
            shift 2
            ;;
        -m|--netmask)
            VPN_NETMASK="$2"
            shift 2
            ;;
        -e|--cipher)
            CIPHER="$2"
            shift 2
            ;;
        -a|--auth)
            AUTH="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -f|--output-file)
            OUTPUT_FILE="$2"
            OUTPUT_FILE_SET_BY_ARG=true
            shift 2
            ;;
        --tls-version)
            TLS_VERSION="$2"
            if [[ "$TLS_VERSION" != "1.2" && "$TLS_VERSION" != "1.3" ]]; then
                error_exit "TLS 版本必须是 1.2 或 1.3"
            fi
            shift 2
            ;;
        --keepalive)
            IFS=',' read -r KEEPALIVE_PING KEEPALIVE_TIMEOUT <<< "$2"
            if ! [[ "$KEEPALIVE_PING" =~ ^[0-9]+$ ]] || ! [[ "$KEEPALIVE_TIMEOUT" =~ ^[0-9]+$ ]]; then
                error_exit "保持连接参数必须是数字，格式为: PING,TIMEOUT"
            fi
            shift 2
            ;;
        --log-level)
            LOG_LEVEL="$2"
            if ! [[ "$LOG_LEVEL" =~ ^[0-9]$ ]] || [ "$LOG_LEVEL" -lt 0 ] || [ "$LOG_LEVEL" -gt 9 ]; then
                error_exit "日志级别必须是 0-9 之间的数字"
            fi
            shift 2
            ;;
        --enable-ipv6)
            ENABLE_IPV6=true
            shift
            ;;
        --max-clients)
            MAX_CLIENTS="$2"
            if ! [[ "$MAX_CLIENTS" =~ ^[0-9]+$ ]] || [ "$MAX_CLIENTS" -lt 1 ]; then
                error_exit "最大客户端连接数必须是大于 0 的数字"
            fi
            shift 2
            ;;
        --duplicate-cn)
            DUPLICATE_CN=true
            shift
            ;;
        --push-block-dns)
            PUSH_BLOCK_DNS=true
            shift
            ;;
        --client-to-client)
            CLIENT_TO_CLIENT=true
            shift
            ;;
        --mobile-device)
            MOBILE_DEVICE=true
            shift
            ;;
        *)
            error_exit "未知选项: $1"
            ;;
    esac
done

# 主函数
main() {
    # 显示欢迎信息
    echo -e "${BLUE}OpenVPN 自动安装脚本${NC}"
    echo -e "${BLUE}==============================${NC}"

    # 检查是否为 root 用户
    check_root

    # 创建日志文件
    touch "$LOG_FILE" || error_exit "无法创建日志文件"

    # 验证输入参数
    validate_inputs

    # 检测操作系统
    detect_os

    # 检查 IP 转发是否启用
    check_ip_forwarding

    # 检查必要的命令
    check_commands

    # 检查 OpenVPN 是否已安装
    check_openvpn_installed

    # 创建临时目录
    TEMP_DIR=$(mktemp -d)
    log "${BLUE}创建临时目录: $TEMP_DIR${NC}"

    # 安装依赖包
    install_dependencies

    # 选择传输协议
    select_protocol

    # 选择输出文件名
    select_output_file

    # 设置 PKI 和证书
    setup_pki

    # 配置 OpenVPN 服务器
    configure_server

    # 配置网络
    configure_network

    # 选择设备类型（移动设备或桌面端）
    select_device_type

    # 生成客户端证书和配置
    generate_client

    # 启动 OpenVPN 服务
    start_openvpn

    # 显示安装完成信息
    show_completion
}

# 执行主函数
main
