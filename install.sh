#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

# 日志文件
LOG_FILE="/var/log/openvpn-install.log"

# 函数: 记录日志
function log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# 添加脚本执行目录变量
SCRIPT_DIR=$(pwd)
log "${BLUE}脚本执行目录: $SCRIPT_DIR${NC}"

# 临时文件和目录
TEMP_DIR=""

# 函数: 执行命令并记录结果
function run_cmd() {
    local cmd="$1"
    local desc="$2"

    # 执行命令
    eval "$cmd"
    local status=$?

    # 如果命令失败，记录到日志
    if [ $status -ne 0 ]; then
        log "${RED}命令失败: ${desc}${NC}"
        return 1
    fi

    return 0
}

# 函数: 错误处理
function error_exit() {
    log "${RED}错误: $1${NC}"
    exit 1
}

# 函数: 清理临时文件和中断的安装
function cleanup() {
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

# 函数: 显示进度
function show_progress() {
    echo -ne "[$1] $2\r"
}

# 函数: 配置文件备份
function backup_config() {
    if [ -f "$1" ]; then
        cp "$1" "$1.bak.$(date +%Y%m%d%H%M%S)"
        log "${GREEN}已备份配置文件: $1${NC}"
    fi
}

# 函数: 增强安全性
function secure_permissions() {
    chmod 600 /etc/openvpn/easy-rsa/pki/private/*
    chmod 644 /etc/openvpn/easy-rsa/pki/issued/*
    log "${GREEN}已设置安全权限${NC}"
}

function isRoot() {
	# 检查是否为root用户
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	# 检查TUN模块是否可用
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	# 检查操作系统类型和版本
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 9 ]]; then
				echo "⚠️ 您的Debian版本不受支持。"
				echo ""
				echo "但是，如果您使用的是Debian >= 9或不稳定/测试版，您可以继续，但风险自负。"
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "是否继续？[y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
				echo "⚠️ 您的Ubuntu版本不受支持。"
				echo ""
				echo "但是，如果您使用的是Ubuntu >= 16.04或测试版，您可以继续，但风险自负。"
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "是否继续？[y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/system-release ]]; then
		source /etc/os-release
		if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
			OS="centos"
			if [[ ${VERSION_ID%.*} -lt 7 ]]; then
				echo "⚠️ 您的CentOS版本不受支持。"
				echo ""
				echo "此脚本仅支持CentOS 7和CentOS 8。"
				echo ""
				exit 1
			fi
		fi
		if [[ $ID == "ol" ]]; then
			OS="oracle"
			if [[ ! $VERSION_ID =~ (8) ]]; then
				echo "您的Oracle Linux版本不受支持。"
				echo ""
				echo "此脚本仅支持Oracle Linux 8。"
				exit 1
			fi
		fi
		if [[ $ID == "amzn" ]]; then
			if [[ $VERSION_ID == "2" ]]; then
				OS="amzn"
			elif [[ "$(echo "$PRETTY_NAME" | cut -c 1-18)" == "Amazon Linux 2023." ]] && [[ "$(echo "$PRETTY_NAME" | cut -c 19)" -ge 6 ]]; then
				OS="amzn2023"
			else
				echo "⚠️ 您的Amazon Linux版本不受支持。"
				echo ""
				echo "此脚本仅支持Amazon Linux 2或Amazon Linux 2023.6+"
				echo ""
				exit 1
			fi
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "看起来您没有在Debian、Ubuntu、Fedora、CentOS、Amazon Linux 2、Oracle Linux 8或Arch Linux系统上运行此安装程序。"
		exit 1
	fi
}

function initialCheck() {
	# 初始检查：root权限、TUN可用性和操作系统
	log "${BLUE}执行初始检查...${NC}"

	if ! isRoot; then
		error_exit "抱歉，您需要以root用户身份运行此脚本。"
	fi

	if ! tunAvailable; then
		error_exit "TUN模块不可用。"
	fi

	checkOS
	log "${GREEN}初始检查通过${NC}"
}

function installUnbound() {
	# 安装Unbound DNS解析器
	log "${BLUE}开始安装Unbound DNS解析器...${NC}"

	# 如果Unbound未安装，则安装它
	if [[ ! -e /etc/unbound/unbound.conf ]]; then
		log "Unbound未安装，开始安装..."

		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd "apt-get install -y unbound" "安装Unbound"

			# 备份原始配置
			backup_config "/etc/unbound/unbound.conf"

			# 配置
			log "配置Unbound..."
			echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >>/etc/unbound/unbound.conf

		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			run_cmd "yum install -y unbound" "安装Unbound"

			# 备份原始配置
			backup_config "/etc/unbound/unbound.conf"

			# 配置
			log "配置Unbound..."
			run_cmd "sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf" "配置Unbound接口"
			run_cmd "sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf" "配置Unbound访问控制"
			run_cmd "sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf" "配置Unbound隐藏身份"
			run_cmd "sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf" "配置Unbound隐藏版本"
			run_cmd "sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf" "配置Unbound使用大写ID"

		elif [[ $OS == "fedora" ]]; then
			run_cmd "dnf install -y unbound" "安装Unbound"

			# 备份原始配置
			backup_config "/etc/unbound/unbound.conf"

			# 配置
			log "配置Unbound..."
			run_cmd "sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf" "配置Unbound接口"
			run_cmd "sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf" "配置Unbound访问控制"
			run_cmd "sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf" "配置Unbound隐藏身份"
			run_cmd "sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf" "配置Unbound隐藏版本"
			run_cmd "sed -i 's|# use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf" "配置Unbound使用大写ID"

		elif [[ $OS == "arch" ]]; then
			run_cmd "pacman -Syu --noconfirm unbound" "安装Unbound"

			# 获取根服务器列表
			log "获取根服务器列表..."
			run_cmd "curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache" "下载根服务器列表"

			if [[ ! -f /etc/unbound/unbound.conf.old ]]; then
				backup_config "/etc/unbound/unbound.conf"
				mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old
			fi

			log "创建Unbound配置文件..."
			echo 'server:
	use-syslog: yes
	do-daemonize: no
	username: "unbound"
	directory: "/etc/unbound"
	trust-anchor-file: trusted-key.key
	root-hints: root.hints
	interface: 10.8.0.1
	access-control: 10.8.0.1/24 allow
	port: 53
	num-threads: 2
	use-caps-for-id: yes
	harden-glue: yes
	hide-identity: yes
	hide-version: yes
	qname-minimisation: yes
	prefetch: yes' >/etc/unbound/unbound.conf
		fi

		# IPv6 DNS for all OS
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			log "添加IPv6支持..."
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/unbound.conf
		fi

		if [[ ! $OS =~ (fedora|centos|amzn|oracle) ]]; then
			# DNS Rebinding fix
			log "添加DNS Rebinding保护..."
			echo "private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96" >>/etc/unbound/unbound.conf
		fi
	else # Unbound is already installed
		log "Unbound已安装，添加OpenVPN配置..."
		backup_config "/etc/unbound/unbound.conf"
		echo 'include: /etc/unbound/openvpn.conf' >>/etc/unbound/unbound.conf

		# Add Unbound 'server' for the OpenVPN subnet
		log "为OpenVPN子网创建Unbound服务器配置..."
		echo 'server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96' >/etc/unbound/openvpn.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			log "添加IPv6支持到OpenVPN配置..."
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/openvpn.conf
		fi
	fi

	log "启用并重启Unbound服务..."
	run_cmd "systemctl enable unbound" "启用Unbound服务"
	run_cmd "systemctl restart unbound" "重启Unbound服务"

	log "${GREEN}Unbound DNS解析器安装完成${NC}"
}

function resolvePublicIP() {
	# 解析公共IP地址
	# IP版本标志，默认使用IPv4
	CURL_IP_VERSION_FLAG="-4"
	DIG_IP_VERSION_FLAG="-4"

	# 在NAT后面，我们默认使用可公开访问的IPv4/IPv6
	if [[ $IPV6_SUPPORT == "y" ]]; then
		CURL_IP_VERSION_FLAG=""
		DIG_IP_VERSION_FLAG="-6"
	fi

	# 如果还没有公共IP，我们将尝试使用：https://api.seeip.org
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://api.seeip.org 2>/dev/null)
	fi

	# 如果还没有公共IP，我们将尝试使用：https://ifconfig.me
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://ifconfig.me 2>/dev/null)
	fi

	# 如果还没有公共IP，我们将尝试使用：https://api.ipify.org
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://api.ipify.org 2>/dev/null)
	fi

	# 如果还没有公共IP，我们将尝试使用：ns1.google.com
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(dig $DIG_IP_VERSION_FLAG TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
	fi

	if [[ -z $PUBLIC_IP ]]; then
		echo >&2 echo "无法解析公共IP地址"
		exit 1
	fi

	echo "$PUBLIC_IP"
}

function installQuestions() {
	# 安装前的问题配置
	echo "欢迎使用OpenVPN安装程序！"
	echo "Git仓库地址：https://github.com/rockyshi1993/OpenVpn"
	echo ""

	echo "在开始安装之前，我需要问您几个问题。"
	echo "如果您对默认选项满意，可以直接按回车键。"
	echo ""
	echo "我需要知道您希望OpenVPN监听的网络接口的IPv4地址。"
	echo "除非您的服务器位于NAT后面，否则应该是您的公共IPv4地址。"

	# 检测公共IPv4地址并为用户预填充
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	if [[ -z $IP ]]; then
		# 检测公共IPv6地址
		IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "IP地址: " -e -i "$IP" IP
	fi
	# 如果$IP是私有IP地址，则服务器必须位于NAT后面
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "看起来此服务器位于NAT后面。它的公共IPv4地址或主机名是什么？"
		echo "我们需要它让客户端连接到服务器。"

		if [[ -z $ENDPOINT ]]; then
			DEFAULT_ENDPOINT=$(resolvePublicIP)
		fi

		until [[ $ENDPOINT != "" ]]; do
			read -rp "公共IPv4地址或主机名: " -e -i "$DEFAULT_ENDPOINT" ENDPOINT
		done
	fi

	echo ""
	echo "正在检查IPv6连接..."
	echo ""
	# "ping6"和"ping -6"的可用性取决于发行版
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
	fi
	if eval "$PING6"; then
		echo "您的主机似乎有IPv6连接。"
		SUGGESTION="y"
	else
		echo "您的主机似乎没有IPv6连接。"
		SUGGESTION="n"
	fi
	echo ""
	# 询问用户是否要启用IPv6，无论其可用性如何
	until [[ $IPV6_SUPPORT =~ (y|n) ]]; do
		read -rp "您想启用IPv6支持(NAT)吗？[y/n]: " -e -i $SUGGESTION IPV6_SUPPORT
	done
	echo ""
	echo "您希望OpenVPN监听哪个端口？"
	echo "   1) 默认: 1194"
	echo "   2) 自定义"
	echo "   3) 随机 [49152-65535]"
	until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "端口选择 [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
	1)
		PORT="1194"
		;;
	2)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "自定义端口 [1-65535]: " -e -i 1194 PORT
		done
		;;
	3)
		# 在私有端口范围内生成随机数
		PORT=$(shuf -i49152-65535 -n1)
		echo "随机端口: $PORT"
		;;
	esac
	echo ""
	echo "您希望OpenVPN使用什么协议？"
	echo "UDP更快。除非UDP不可用，否则您不应该使用TCP。"
	echo "   1) UDP"
	echo "   2) TCP"
	until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "协议 [1-2]: " -e -i 1 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
	1)
		PROTOCOL="udp"
		;;
	2)
		PROTOCOL="tcp"
		;;
	esac
	echo ""
	echo "您希望VPN使用哪些DNS解析器？"
	echo "   1) 当前系统解析器 (来自 /etc/resolv.conf)"
	echo "   2) 自托管DNS解析器 (Unbound)"
	echo "   3) Cloudflare (任播: 全球)"
	echo "   4) Quad9 (任播: 全球)"
	echo "   5) Quad9 无审查 (任播: 全球)"
	echo "   6) FDN (法国)"
	echo "   7) DNS.WATCH (德国)"
	echo "   8) OpenDNS (任播: 全球)"
	echo "   9) Google (任播: 全球)"
	echo "   10) Yandex Basic (俄罗斯)"
	echo "   11) AdGuard DNS (任播: 全球)"
	echo "   12) NextDNS (任播: 全球)"
	echo "   13) 自定义"
	until [[ $DNS =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 13 ]; do
		read -rp "DNS [1-12]: " -e -i 11 DNS
		if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
			echo ""
			echo "Unbound已经安装。"
			echo "您可以允许脚本配置它，以便从OpenVPN客户端使用它"
			echo "我们将简单地为OpenVPN子网添加第二个服务器到/etc/unbound/unbound.conf。"
			echo "不会对当前配置进行更改。"
			echo ""

			until [[ $CONTINUE =~ (y|n) ]]; do
				read -rp "应用配置更改到Unbound？[y/n]: " -e CONTINUE
			done
			if [[ $CONTINUE == "n" ]]; then
				# 中断循环并清理
				unset DNS
				unset CONTINUE
			fi
		elif [[ $DNS == "13" ]]; then
			until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "主要DNS: " -e DNS1
			done
			until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "次要DNS (可选): " -e DNS2
				if [[ $DNS2 == "" ]]; then
					break
				fi
			done
		fi
	done
	echo ""
	echo "您想使用压缩吗？由于VORACLE攻击会利用它，因此不推荐使用。"
	until [[ $COMPRESSION_ENABLED =~ (y|n) ]]; do
		read -rp"启用压缩？[y/n]: " -e -i n COMPRESSION_ENABLED
	done
	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "选择您想使用的压缩算法：(它们按效率排序)"
		echo "   1) LZ4-v2"
		echo "   2) LZ4"
		echo "   3) LZ0"
		until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
			read -rp"压缩算法 [1-3]: " -e -i 1 COMPRESSION_CHOICE
		done
		case $COMPRESSION_CHOICE in
		1)
			COMPRESSION_ALG="lz4-v2"
			;;
		2)
			COMPRESSION_ALG="lz4"
			;;
		3)
			COMPRESSION_ALG="lzo"
			;;
		esac
	fi
	echo ""
	echo "您想自定义加密设置吗？"
	echo "除非您知道自己在做什么，否则应该坚持使用脚本提供的默认参数。"
	echo "请注意，无论您选择什么，脚本中提供的所有选项都是安全的（与OpenVPN的默认值不同）。"
	echo "访问 https://github.com/rockyshi1993/OpenVpn 了解更多信息。"
	echo ""
	until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
		read -rp "自定义加密设置？[y/n]: " -e -i n CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "n" ]]; then
		# 使用默认、安全且快速的参数
		CIPHER="AES-128-GCM"
		CERT_TYPE="1" # ECDSA
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		DH_TYPE="1" # ECDH
		DH_CURVE="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="1" # tls-crypt
	else
		echo ""
		echo "选择您想用于数据通道的加密算法："
		echo "   1) AES-128-GCM (推荐)"
		echo "   2) AES-192-GCM"
		echo "   3) AES-256-GCM"
		echo "   4) AES-128-CBC"
		echo "   5) AES-192-CBC"
		echo "   6) AES-256-CBC"
		until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
			read -rp "加密算法 [1-6]: " -e -i 1 CIPHER_CHOICE
		done
		case $CIPHER_CHOICE in
		1)
			CIPHER="AES-128-GCM"
			;;
		2)
			CIPHER="AES-192-GCM"
			;;
		3)
			CIPHER="AES-256-GCM"
			;;
		4)
			CIPHER="AES-128-CBC"
			;;
		5)
			CIPHER="AES-192-CBC"
			;;
		6)
			CIPHER="AES-256-CBC"
			;;
		esac
		echo ""
		echo "选择您想使用的证书类型："
		echo "   1) ECDSA (推荐)"
		echo "   2) RSA"
		until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
			read -rp"证书密钥类型 [1-2]: " -e -i 1 CERT_TYPE
		done
		case $CERT_TYPE in
		1)
			echo ""
			echo "选择您想用于证书密钥的曲线："
			echo "   1) prime256v1 (推荐)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp"曲线 [1-3]: " -e -i 1 CERT_CURVE_CHOICE
			done
			case $CERT_CURVE_CHOICE in
			1)
				CERT_CURVE="prime256v1"
				;;
			2)
				CERT_CURVE="secp384r1"
				;;
			3)
				CERT_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "选择您想用于证书RSA密钥的大小："
			echo "   1) 2048位 (推荐)"
			echo "   2) 3072位"
			echo "   3) 4096位"
			until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "RSA密钥大小 [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
			done
			case $RSA_KEY_SIZE_CHOICE in
			1)
				RSA_KEY_SIZE="2048"
				;;
			2)
				RSA_KEY_SIZE="3072"
				;;
			3)
				RSA_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		echo "选择您想用于控制通道的加密算法："
		case $CERT_TYPE in
		1)
			echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256 (推荐)"
			echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"控制通道加密算法 [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		2)
			echo "   1) ECDHE-RSA-AES-128-GCM-SHA256 (推荐)"
			echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"控制通道加密算法 [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		esac
		echo ""
		echo "选择您想使用的Diffie-Hellman密钥类型："
		echo "   1) ECDH (推荐)"
		echo "   2) DH"
		until [[ $DH_TYPE =~ [1-2] ]]; do
			read -rp"DH密钥类型 [1-2]: " -e -i 1 DH_TYPE
		done
		case $DH_TYPE in
		1)
			echo ""
			echo "选择您想用于ECDH密钥的曲线："
			echo "   1) prime256v1 (推荐)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
				read -rp"曲线 [1-3]: " -e -i 1 DH_CURVE_CHOICE
			done
			case $DH_CURVE_CHOICE in
			1)
				DH_CURVE="prime256v1"
				;;
			2)
				DH_CURVE="secp384r1"
				;;
			3)
				DH_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "选择您想使用的Diffie-Hellman密钥大小："
			echo "   1) 2048位 (推荐)"
			echo "   2) 3072位"
			echo "   3) 4096位"
			until [[ $DH_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "DH密钥大小 [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
			done
			case $DH_KEY_SIZE_CHOICE in
			1)
				DH_KEY_SIZE="2048"
				;;
			2)
				DH_KEY_SIZE="3072"
				;;
			3)
				DH_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		# "auth"选项对AEAD密码的行为不同
		if [[ $CIPHER =~ CBC$ ]]; then
			echo "摘要算法对数据通道数据包和来自控制通道的tls-auth数据包进行身份验证。"
		elif [[ $CIPHER =~ GCM$ ]]; then
			echo "摘要算法对来自控制通道的tls-auth数据包进行身份验证。"
		fi
		echo "您想为HMAC使用哪种摘要算法？"
		echo "   1) SHA-256 (推荐)"
		echo "   2) SHA-384"
		echo "   3) SHA-512"
		until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "摘要算法 [1-3]: " -e -i 1 HMAC_ALG_CHOICE
		done
		case $HMAC_ALG_CHOICE in
		1)
			HMAC_ALG="SHA256"
			;;
		2)
			HMAC_ALG="SHA384"
			;;
		3)
			HMAC_ALG="SHA512"
			;;
		esac
		echo ""
		echo "您可以使用tls-auth和tls-crypt为控制通道添加额外的安全层"
		echo "tls-auth对数据包进行身份验证，而tls-crypt对数据包进行身份验证和加密。"
		echo "   1) tls-crypt (推荐)"
		echo "   2) tls-auth"
		until [[ $TLS_SIG =~ [1-2] ]]; do
			read -rp "控制通道额外安全机制 [1-2]: " -e -i 1 TLS_SIG
		done
	fi
	echo ""
	echo "好的，我需要的信息已经收集完毕。我们现在准备设置您的OpenVPN服务器。"
	echo "您将能够在安装结束时生成客户端配置。"
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "按任意键继续..."
	fi
}

function installOpenVPN() {
	# 安装OpenVPN
	if [[ $AUTO_INSTALL == "y" ]]; then
		# 设置默认选项，这样就不会询问任何问题
		APPROVE_INSTALL=${APPROVE_INSTALL:-y}
		APPROVE_IP=${APPROVE_IP:-y}
		IPV6_SUPPORT=${IPV6_SUPPORT:-n}
		PORT_CHOICE=${PORT_CHOICE:-1}
		PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
		DNS=${DNS:-1}
		COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
		CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
		CLIENT=${CLIENT:-client}
		PASS=${PASS:-1}
		CONTINUE=${CONTINUE:-y}

		if [[ -z $ENDPOINT ]]; then
			ENDPOINT=$(resolvePublicIP)
		fi
	fi

	# 首先运行设置问题，如果是自动安装则设置其他变量
	installQuestions

	# 从默认路由获取"公共"接口
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ -z $NIC ]] && [[ $IPV6_SUPPORT == 'y' ]]; then
		NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
	fi

	# $NIC不能为空，用于脚本rm-openvpn-rules.sh
	if [[ -z $NIC ]]; then
		echo
		echo "无法检测到公共接口。"
		echo "这需要设置MASQUERADE。"
		until [[ $CONTINUE =~ (y|n) ]]; do
			read -rp "继续？[y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then
			exit 1
		fi
	fi

	# 如果OpenVPN尚未安装，则安装它。这个脚本在多次运行时或多或少是幂等的，
	# 但只会在第一次从上游安装OpenVPN。
	if [[ ! -e /etc/openvpn/server.conf ]]; then
		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get update
			apt-get -y install ca-certificates gnupg
			# 我们添加OpenVPN仓库以获取最新版本。
			if [[ $VERSION_ID == "16.04" ]]; then
				echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
				wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
				apt-get update
			fi
			# Ubuntu > 16.04和Debian > 8已经有OpenVPN >= 2.4，不需要第三方仓库。
			apt-get install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'centos' ]]; then
			yum install -y epel-release
			yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'
		elif [[ $OS == 'oracle' ]]; then
			yum install -y oracle-epel-release-el8
			yum-config-manager --enable ol8_developer_EPEL
			yum install -y openvpn iptables openssl wget ca-certificates curl tar policycoreutils-python-utils
		elif [[ $OS == 'amzn' ]]; then
			amazon-linux-extras install -y epel
			yum install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'amzn2023' ]]; then
			dnf install -y openvpn iptables openssl wget ca-certificates
		elif [[ $OS == 'fedora' ]]; then
			dnf install -y openvpn iptables openssl wget ca-certificates curl policycoreutils-python-utils
		elif [[ $OS == 'arch' ]]; then
			# Install required dependencies and upgrade the system
			pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl
		fi
		# 在一些openvpn包中默认提供了旧版本的easy-rsa
		if [[ -d /etc/openvpn/easy-rsa/ ]]; then
			rm -rf /etc/openvpn/easy-rsa/
		fi
	fi

	# 查找机器是否使用nogroup或nobody作为无权限组
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi

	# 如果尚未安装，从源代码安装最新版本的easy-rsa。
	if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
		local version="3.1.2"
		wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
		mkdir -p /etc/openvpn/easy-rsa
		tar xzf ~/easy-rsa.tgz --strip-components=1 --no-same-owner --directory /etc/openvpn/easy-rsa
		rm -f ~/easy-rsa.tgz

		cd /etc/openvpn/easy-rsa/ || return
		case $CERT_TYPE in
		1)
			echo "set_var EASYRSA_ALGO ec" >vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
			;;
		2)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
			;;
		esac

		# 为CN和服务器名称生成一个16字符的随机字母数字标识符
		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED

		# 创建PKI，设置CA，DH参数和服务器证书
		./easyrsa init-pki
		EASYRSA_CA_EXPIRE=3650 ./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass

		if [[ $DH_TYPE == "2" ]]; then
			# ECDH密钥是即时生成的，所以我们不需要预先生成它们
			openssl dhparam -out dh.pem $DH_KEY_SIZE
		fi

		EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-server-full "$SERVER_NAME" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

		case $TLS_SIG in
		1)
			# Generate tls-crypt key
			openvpn --genkey --secret /etc/openvpn/tls-crypt.key
			;;
		2)
			# Generate tls-auth key
			openvpn --genkey --secret /etc/openvpn/tls-auth.key
			;;
		esac
	else
		# 如果easy-rsa已经安装，获取生成的SERVER_NAME
		# 用于客户端配置
		cd /etc/openvpn/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
	fi

	# 移动所有生成的文件
	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	if [[ $DH_TYPE == "2" ]]; then
		cp dh.pem /etc/openvpn
	fi

	# 使证书吊销列表对非root用户可读
	chmod 644 /etc/openvpn/crl.pem

	# 生成server.conf配置文件
	echo "port $PORT" >/etc/openvpn/server.conf
	if [[ $IPV6_SUPPORT == 'n' ]]; then
		echo "proto $PROTOCOL" >>/etc/openvpn/server.conf
	elif [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "proto ${PROTOCOL}6" >>/etc/openvpn/server.conf
	fi

	echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf

	# DNS解析器
	case $DNS in
	1) # 当前系统解析器
		# 定位正确的resolv.conf
		# 对于运行systemd-resolved的系统是必需的
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# 从resolv.conf获取解析器并将其用于OpenVPN
		sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
			# 如果是IPv4地址或者IPv6已启用，则复制DNS设置（此时IPv4/IPv6无关紧要）
			if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
			fi
		done
		;;
	2) # Self-hosted DNS resolver (Unbound)
		echo 'push "dhcp-option DNS 10.8.0.1"' >>/etc/openvpn/server.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'push "dhcp-option DNS fd42:42:42:42::1"' >>/etc/openvpn/server.conf
		fi
		;;
	3) # Cloudflare
		echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server.conf
		;;
	4) # Quad9
		echo 'push "dhcp-option DNS 9.9.9.9"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.112"' >>/etc/openvpn/server.conf
		;;
	5) # Quad9 uncensored
		echo 'push "dhcp-option DNS 9.9.9.10"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.10"' >>/etc/openvpn/server.conf
		;;
	6) # FDN
		echo 'push "dhcp-option DNS 80.67.169.40"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 80.67.169.12"' >>/etc/openvpn/server.conf
		;;
	7) # DNS.WATCH
		echo 'push "dhcp-option DNS 84.200.69.80"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 84.200.70.40"' >>/etc/openvpn/server.conf
		;;
	8) # OpenDNS
		echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server.conf
		;;
	9) # Google
		echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server.conf
		;;
	10) # Yandex Basic
		echo 'push "dhcp-option DNS 77.88.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 77.88.8.1"' >>/etc/openvpn/server.conf
		;;
	11) # AdGuard DNS
		echo 'push "dhcp-option DNS 94.140.14.14"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 94.140.15.15"' >>/etc/openvpn/server.conf
		;;
	12) # NextDNS
		echo 'push "dhcp-option DNS 45.90.28.167"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 45.90.30.167"' >>/etc/openvpn/server.conf
		;;
	13) # Custom DNS
		echo "push \"dhcp-option DNS $DNS1\"" >>/etc/openvpn/server.conf
		if [[ $DNS2 != "" ]]; then
			echo "push \"dhcp-option DNS $DNS2\"" >>/etc/openvpn/server.conf
		fi
		;;
	esac
	echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf

	# IPv6 network settings if needed
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"' >>/etc/openvpn/server.conf
	fi

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/server.conf
	fi

	if [[ $DH_TYPE == "1" ]]; then
		echo "dh none" >>/etc/openvpn/server.conf
		echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf
	elif [[ $DH_TYPE == "2" ]]; then
		echo "dh dh.pem" >>/etc/openvpn/server.conf
	fi

	case $TLS_SIG in
	1)
		echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf
		;;
	2)
		echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server.conf
		;;
	esac

	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3" >>/etc/openvpn/server.conf

	# Create client-config-dir dir
	mkdir -p /etc/openvpn/ccd
	# Create log dir
	mkdir -p /var/log/openvpn

	# Enable routing
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf
	fi
	# Apply sysctl rules
	sysctl --system

	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
			fi
		fi
	fi

	# Finally, restart and enable OpenVPN
	if [[ $OS == 'arch' || $OS == 'fedora' || $OS == 'centos' || $OS == 'oracle' || $OS == 'amzn2023' ]]; then
		# Don't modify package-provided service
		cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service

		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service

		systemctl daemon-reload
		systemctl enable openvpn-server@server
		systemctl restart openvpn-server@server
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		# On Ubuntu 16.04, we use the package from the OpenVPN repo
		# This package uses a sysvinit service
		systemctl enable openvpn
		systemctl start openvpn
	else
		# Don't modify package-provided service
		cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service

		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service

		systemctl daemon-reload
		systemctl enable openvpn@server
		systemctl restart openvpn@server
	fi

	if [[ $DNS == 2 ]]; then
		installUnbound
	fi

	# Add iptables rules in two scripts
	mkdir -p /etc/iptables

	# Script to add rules
	echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh

	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "ip6tables -t nat -I POSTROUTING 1 -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
	fi

	# Script to remove rules
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh

	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh
	fi

	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh

	# Handle the rules via a systemd script
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn

	# If the server is behind a NAT, use the correct IP address for the clients to connect to
	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi

	# client-template.txt is created so we have a template to add further users later
	echo "client" >/etc/openvpn/client-template.txt
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >>/etc/openvpn/client-template.txt
		echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
	elif [[ $PROTOCOL == 'tcp' ]]; then
		echo "proto tcp-client" >>/etc/openvpn/client-template.txt
	fi
	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3" >>/etc/openvpn/client-template.txt

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/client-template.txt
	fi

	# Generate the custom client.ovpn
	newClient "install" "$SCRIPT_DIR"
  echo "如果您想添加更多客户端，只需再次运行此脚本即可！"
  echo "客户端配置文件已保存在: $SCRIPT_DIR/install.ovpn"

}

function newClient() {
	# 参数：$1 - 调用来源，"install"表示首次安装，"menu"表示从管理菜单调用
	local from_install=${1:-menu}
	log "${BLUE}开始创建新客户端...${NC}"

	# 保存原始工作目录，用于后续保存配置文件
	ORIGINAL_DIR=$SCRIPT_DIR
	log "原始工作目录: $ORIGINAL_DIR"

	echo ""
	echo "请告诉我客户端的名称。"
	echo "名称必须由字母数字字符组成。也可以包含下划线或破折号。"

	until [[ $CLIENT =~ ^[a-zA-Z0-9_-]+$ ]]; do
		read -rp "客户端名称: " -e CLIENT
	done
	log "用户选择的客户端名称: $CLIENT"

	echo ""
	echo "您想用密码保护配置文件吗？"
	echo "（例如，用密码加密私钥）"
	echo "   1) 添加无密码的客户端"
	echo "   2) 为客户端使用密码"

	until [[ $PASS =~ ^[1-2]$ ]]; do
		read -rp "选择一个选项 [1-2]: " -e -i 1 PASS
	done
	log "用户选择的密码选项: $PASS"

	CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")
	if [[ $CLIENTEXISTS == '1' ]]; then
		log "${RED}客户端 $CLIENT 已存在${NC}"
		echo ""
		echo "指定的客户端CN已在easy-rsa中找到，请选择另一个名称。"
		exit 1
	else
		log "开始生成客户端证书..."
		cd /etc/openvpn/easy-rsa/ || error_exit "无法进入easy-rsa目录"

		case $PASS in
		1)
			log "生成无密码的客户端证书..."
			run_cmd "EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full \"$CLIENT\" nopass" "生成客户端证书"
			;;
		2)
			log "生成带密码的客户端证书..."
			echo "⚠️ 您将在下面被要求输入客户端密码 ⚠️"
			run_cmd "EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full \"$CLIENT\"" "生成客户端证书"
			;;
		esac

		log "${GREEN}客户端 $CLIENT 证书已生成${NC}"
		echo "客户端 $CLIENT 已添加。"
	fi

	# 设置安全权限
	log "设置证书和密钥的安全权限..."
	secure_permissions

	# 使用原始工作目录保存配置文件
	log "使用原始工作目录保存配置文件..."
	homeDir="$ORIGINAL_DIR"
	log "配置文件将保存在: $homeDir"

	# 确定我们使用tls-auth还是tls-crypt
	log "检查TLS安全机制类型..."
	if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
		TLS_SIG="1"
		log "使用tls-crypt"
	elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
		TLS_SIG="2"
		log "使用tls-auth"
	fi

	# 生成自定义client.ovpn
	log "生成客户端配置文件..."
	cp /etc/openvpn/client-template.txt "$homeDir/$CLIENT.ovpn"

	log "添加证书和密钥到配置文件..."
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END CERTIFICATE/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
		echo "</key>"

		case $TLS_SIG in
		1)
			echo "<tls-crypt>"
			cat /etc/openvpn/tls-crypt.key
			echo "</tls-crypt>"
			;;
		2)
			echo "key-direction 1"
			echo "<tls-auth>"
			cat /etc/openvpn/tls-auth.key
			echo "</tls-auth>"
			;;
		esac
	} >>"$homeDir/$CLIENT.ovpn"

	# 设置配置文件权限
	log "设置配置文件权限..."
	chmod 600 "$homeDir/$CLIENT.ovpn"

	if [ "${SUDO_USER}" ] && [ "${SUDO_USER}" != "root" ]; then
		chown "${SUDO_USER}":"${SUDO_USER}" "$homeDir/$CLIENT.ovpn"
	fi

	log "${GREEN}客户端配置文件已成功创建${NC}"
	echo ""
	echo "配置文件已写入 $homeDir/$CLIENT.ovpn。"
	echo "您可以在当前执行脚本的目录中找到此文件。"
	echo "下载.ovpn文件并将其导入到您的OpenVPN客户端。"

  return 0

}

function revokeClient() {
	log "${BLUE}开始撤销客户端证书...${NC}"

	# 保存原始工作目录，用于后续查找和删除配置文件
	ORIGINAL_DIR="$(pwd)"
	log "原始工作目录: $ORIGINAL_DIR"

	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		log "${YELLOW}没有找到现有客户端${NC}"
		echo ""
		echo "您没有现有的客户端！"
		exit 1
	fi

	log "找到 $NUMBEROFCLIENTS 个现有客户端"
	echo ""
	echo "选择您想要撤销的现有客户端证书"
	tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '

	until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
		if [[ $CLIENTNUMBER == '1' ]]; then
			read -rp "选择一个客户端 [1]: " CLIENTNUMBER
		else
			read -rp "选择一个客户端 [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
		fi
	done

	CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
	log "用户选择撤销客户端: $CLIENT"

	cd /etc/openvpn/easy-rsa/ || error_exit "无法进入easy-rsa目录"

	log "撤销客户端证书..."
	run_cmd "./easyrsa --batch revoke \"$CLIENT\"" "撤销客户端证书"

	log "生成新的证书吊销列表(CRL)..."
	run_cmd "EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl" "生成CRL"

	log "更新OpenVPN的CRL文件..."
	if [ -f /etc/openvpn/crl.pem ]; then
		backup_config "/etc/openvpn/crl.pem"
	fi

	run_cmd "rm -f /etc/openvpn/crl.pem" "删除旧的CRL文件"
	run_cmd "cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem" "复制新的CRL文件"
	run_cmd "chmod 644 /etc/openvpn/crl.pem" "设置CRL文件权限"

	log "删除客户端配置文件..."
	# 使用原始工作目录查找和删除配置文件
	if [ -f "$ORIGINAL_DIR/$CLIENT.ovpn" ]; then
		run_cmd "rm -f \"$ORIGINAL_DIR/$CLIENT.ovpn\"" "删除原始目录中的客户端配置"
		log "已从 $ORIGINAL_DIR 删除客户端配置文件"
	fi

	# 为了兼容性，也检查旧位置
	run_cmd "find /home/ -maxdepth 2 -name \"$CLIENT.ovpn\" -delete" "删除用户目录中的客户端配置"
	run_cmd "rm -f \"/root/$CLIENT.ovpn\"" "删除root目录中的客户端配置"

	log "从IP池中删除客户端..."
	if [ -f /etc/openvpn/ipp.txt ]; then
		backup_config "/etc/openvpn/ipp.txt"
		run_cmd "sed -i \"/^$CLIENT,.*/d\" /etc/openvpn/ipp.txt" "从IP池中删除客户端"
	fi

	log "备份index.txt文件..."
	run_cmd "cp /etc/openvpn/easy-rsa/pki/index.txt{,.bk}" "备份index.txt"

	log "${GREEN}客户端证书撤销完成${NC}"
	echo ""
	echo "客户端 $CLIENT 的证书已撤销。"

	exit 0
}

function removeUnbound() {
	log "${BLUE}开始移除Unbound...${NC}"

	# 移除OpenVPN相关配置
	log "移除OpenVPN相关的Unbound配置..."
	if [ -f /etc/unbound/unbound.conf ]; then
		backup_config "/etc/unbound/unbound.conf"
		run_cmd "sed -i '/include: \/etc\/unbound\/openvpn.conf/d' /etc/unbound/unbound.conf" "从unbound.conf中移除OpenVPN配置"
	fi

	if [ -f /etc/unbound/openvpn.conf ]; then
		run_cmd "rm /etc/unbound/openvpn.conf" "删除OpenVPN的Unbound配置文件"
	fi

	until [[ $REMOVE_UNBOUND =~ (y|n) ]]; do
		echo ""
		echo "如果您在安装OpenVPN之前已经在使用Unbound，我已移除了与OpenVPN相关的配置。"
		read -rp "您想要完全移除Unbound吗？[y/n]: " -e REMOVE_UNBOUND
	done
	log "用户选择是否完全移除Unbound: $REMOVE_UNBOUND"

	if [[ $REMOVE_UNBOUND == 'y' ]]; then
		# 停止Unbound
		log "停止Unbound服务..."
		run_cmd "systemctl stop unbound" "停止Unbound服务"

		log "卸载Unbound软件包..."
		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd "apt-get remove --purge -y unbound" "卸载Unbound"
		elif [[ $OS == 'arch' ]]; then
			run_cmd "pacman --noconfirm -R unbound" "卸载Unbound"
		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			run_cmd "yum remove -y unbound" "卸载Unbound"
		elif [[ $OS == 'fedora' ]]; then
			run_cmd "dnf remove -y unbound" "卸载Unbound"
		fi

		log "删除Unbound配置目录..."
		run_cmd "rm -rf /etc/unbound/" "删除Unbound配置目录"

		log "${GREEN}Unbound已完全移除${NC}"
		echo ""
		echo "Unbound已移除！"
	else
		log "重启Unbound服务..."
		run_cmd "systemctl restart unbound" "重启Unbound服务"

		log "${GREEN}Unbound配置已更新，服务已重启${NC}"
		echo ""
		echo "Unbound未被移除。"
	fi
}

function removeOpenVPN() {
	log "${BLUE}开始移除OpenVPN...${NC}"

	# 保存原始工作目录，用于后续查找和删除配置文件
	ORIGINAL_DIR="$(pwd)"
	log "原始工作目录: $ORIGINAL_DIR"

	echo ""
	read -rp "您确定要移除OpenVPN吗？[y/n]: " -e -i n REMOVE
	log "用户选择是否移除OpenVPN: $REMOVE"

	if [[ $REMOVE == 'y' ]]; then
		# 从配置中获取OpenVPN端口
		if [ -f /etc/openvpn/server.conf ]; then
			PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
			PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
			log "检测到OpenVPN配置: 端口=$PORT, 协议=$PROTOCOL"
		else
			log "${YELLOW}未找到OpenVPN配置文件${NC}"
		fi

		# 停止OpenVPN
		log "停止OpenVPN服务..."
		if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
			run_cmd "systemctl disable openvpn-server@server" "禁用OpenVPN服务"
			run_cmd "systemctl stop openvpn-server@server" "停止OpenVPN服务"
			# 移除自定义服务
			if [ -f /etc/systemd/system/openvpn-server@.service ]; then
				log "移除自定义服务文件..."
				run_cmd "rm /etc/systemd/system/openvpn-server@.service" "删除自定义服务文件"
			fi
		elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
			run_cmd "systemctl disable openvpn" "禁用OpenVPN服务"
			run_cmd "systemctl stop openvpn" "停止OpenVPN服务"
		else
			run_cmd "systemctl disable openvpn@server" "禁用OpenVPN服务"
			run_cmd "systemctl stop openvpn@server" "停止OpenVPN服务"
			# 移除自定义服务
			if [ -f /etc/systemd/system/openvpn\@.service ]; then
				log "移除自定义服务文件..."
				run_cmd "rm /etc/systemd/system/openvpn\@.service" "删除自定义服务文件"
			fi
		fi

		# 移除与脚本相关的iptables规则
		log "移除iptables规则..."
		run_cmd "systemctl stop iptables-openvpn" "停止iptables-openvpn服务"

		# 清理
		log "清理iptables相关文件..."
		run_cmd "systemctl disable iptables-openvpn" "禁用iptables-openvpn服务"

		if [ -f /etc/systemd/system/iptables-openvpn.service ]; then
			run_cmd "rm /etc/systemd/system/iptables-openvpn.service" "删除iptables-openvpn服务文件"
		fi

		run_cmd "systemctl daemon-reload" "重新加载systemd配置"

		if [ -f /etc/iptables/add-openvpn-rules.sh ]; then
			run_cmd "rm /etc/iptables/add-openvpn-rules.sh" "删除iptables添加规则脚本"
		fi

		if [ -f /etc/iptables/rm-openvpn-rules.sh ]; then
			run_cmd "rm /etc/iptables/rm-openvpn-rules.sh" "删除iptables移除规则脚本"
		fi

		# SELinux安全策略
		log "检查SELinux安全策略..."
		if hash sestatus 2>/dev/null; then
			if sestatus | grep "Current mode" | grep -qs "enforcing"; then
				log "SELinux处于enforcing模式"
				if [[ $PORT != '1194' ]]; then
					log "移除自定义端口的SELinux策略..."
					run_cmd "semanage port -d -t openvpn_port_t -p \"$PROTOCOL\" \"$PORT\"" "删除SELinux端口策略"
				fi
			fi
		fi

		# 卸载OpenVPN软件包
		log "卸载OpenVPN软件包..."
		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd "apt-get remove --purge -y openvpn" "卸载OpenVPN"
			if [[ -e /etc/apt/sources.list.d/openvpn.list ]]; then
				log "移除OpenVPN仓库..."
				run_cmd "rm /etc/apt/sources.list.d/openvpn.list" "删除OpenVPN仓库"
				run_cmd "apt-get update" "更新软件包列表"
			fi
		elif [[ $OS == 'arch' ]]; then
			run_cmd "pacman --noconfirm -R openvpn" "卸载OpenVPN"
		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			run_cmd "yum remove -y openvpn" "卸载OpenVPN"
		elif [[ $OS == 'fedora' ]]; then
			run_cmd "dnf remove -y openvpn" "卸载OpenVPN"
		fi

		# 清理配置文件和目录
		log "清理OpenVPN配置文件和目录..."

		# 清理配置文件（使用原始工作目录）
		run_cmd "find \"$ORIGINAL_DIR\" -maxdepth 1 -name \"*.ovpn\" -delete" "删除原始目录中的客户端配置"
		log "已删除原始目录中的所有客户端配置文件"

		# 为了兼容性，也清理旧位置
		run_cmd "find /home/ -maxdepth 2 -name \"*.ovpn\" -delete" "删除用户目录中的客户端配置"
		run_cmd "find /root/ -maxdepth 1 -name \"*.ovpn\" -delete" "删除root目录中的客户端配置"

		if [ -d /etc/openvpn ]; then
			run_cmd "rm -rf /etc/openvpn" "删除OpenVPN配置目录"
		fi

		if [ -d /usr/share/doc/openvpn ]; then
			run_cmd "rm -rf /usr/share/doc/openvpn*" "删除OpenVPN文档"
		fi

		if [ -f /etc/sysctl.d/99-openvpn.conf ]; then
			run_cmd "rm -f /etc/sysctl.d/99-openvpn.conf" "删除OpenVPN sysctl配置"
		fi

		if [ -d /var/log/openvpn ]; then
			run_cmd "rm -rf /var/log/openvpn" "删除OpenVPN日志目录"
		fi

		# Unbound
		if [[ -e /etc/unbound/openvpn.conf ]]; then
			log "检测到Unbound配置，开始移除..."
			removeUnbound
		fi

		log "${GREEN}OpenVPN已成功移除${NC}"
		echo ""
		echo "OpenVPN已移除！"
	else
		log "${YELLOW}用户取消了移除操作${NC}"
		echo ""
		echo "移除已取消！"
	fi

	exit 0
}

# 函数: 列出所有客户端
function listClients() {
	log "${BLUE}开始列出所有客户端...${NC}"

	# 检查证书索引文件是否存在
	if [ ! -f /etc/openvpn/easy-rsa/pki/index.txt ]; then
		log "${RED}错误: 找不到证书索引文件${NC}"
		echo "无法找到证书索引文件。OpenVPN可能未正确安装。"
		return 1
	fi

	# 统计有效和已撤销的证书数量
	VALID_CLIENTS=$(grep -c "^V" /etc/openvpn/easy-rsa/pki/index.txt)
	REVOKED_CLIENTS=$(grep -c "^R" /etc/openvpn/easy-rsa/pki/index.txt)
	TOTAL_CLIENTS=$((VALID_CLIENTS + REVOKED_CLIENTS))

	if [ "$TOTAL_CLIENTS" -eq 0 ]; then
		log "${YELLOW}未找到客户端证书${NC}"
		echo ""
		echo "未找到任何客户端证书。"
		return 0
	fi

	log "找到 $VALID_CLIENTS 个有效客户端和 $REVOKED_CLIENTS 个已撤销客户端"

	echo ""
	echo "客户端证书列表:"
	echo "------------------------------------"
	echo "状态 | 客户端名称 | 过期日期"
	echo "------------------------------------"

	# 处理有效证书
	if [ "$VALID_CLIENTS" -gt 0 ]; then
		grep "^V" /etc/openvpn/easy-rsa/pki/index.txt | while read -r line; do
			# 提取客户端名称 (CN)
			CLIENT=$(echo "$line" | grep -oP "CN=\K[^/]+")
			# 提取过期日期
			EXPIRY_DATE=$(echo "$line" | cut -d '=' -f 2 | cut -d 'Z' -f 1 | awk -F'T' '{print $1}')
			echo -e "${GREEN}有效${NC} | $CLIENT | $EXPIRY_DATE"
		done
	fi

	# 处理已撤销证书
	if [ "$REVOKED_CLIENTS" -gt 0 ]; then
		grep "^R" /etc/openvpn/easy-rsa/pki/index.txt | while read -r line; do
			# 提取客户端名称 (CN)
			CLIENT=$(echo "$line" | grep -oP "CN=\K[^/]+")
			# 提取撤销日期
			REVOKE_DATE=$(echo "$line" | awk '{print $3}')
			echo -e "${RED}已撤销${NC} | $CLIENT | 撤销于 $REVOKE_DATE"
		done
	fi

	echo "------------------------------------"
	echo "总计: $TOTAL_CLIENTS 个客户端 ($VALID_CLIENTS 个有效, $REVOKED_CLIENTS 个已撤销)"

	exit 0
}

# 函数: 检查OpenVPN状态
function checkStatus() {
	log "${BLUE}开始检查OpenVPN状态...${NC}"

	# 检查OpenVPN服务状态
	log "检查OpenVPN服务状态..."
	if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
		SERVICE_STATUS=$(systemctl is-active openvpn-server@server)
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		SERVICE_STATUS=$(systemctl is-active openvpn)
	else
		SERVICE_STATUS=$(systemctl is-active openvpn@server)
	fi

	echo ""
	echo "OpenVPN服务状态:"
	echo "------------------------------------"

	if [ "$SERVICE_STATUS" == "active" ]; then
		echo -e "服务状态: ${GREEN}运行中${NC}"

		# 获取服务运行时间
		if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
			UPTIME=$(systemctl show openvpn-server@server --property=ActiveEnterTimestamp | cut -d'=' -f2)
		elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
			UPTIME=$(systemctl show openvpn --property=ActiveEnterTimestamp | cut -d'=' -f2)
		else
			UPTIME=$(systemctl show openvpn@server --property=ActiveEnterTimestamp | cut -d'=' -f2)
		fi

		echo "运行时间: $UPTIME"

		# 检查状态日志文件
		if [ -f /var/log/openvpn/status.log ]; then
			log "解析状态日志文件..."

			# 显示连接的客户端
			echo ""
			echo "当前连接的客户端:"
			echo "------------------------------------"
			echo "用户名 | IP地址 | 已接收 | 已发送 | 连接时间"
			echo "------------------------------------"

			# 解析状态日志文件中的客户端部分
			CLIENT_COUNT=0
			while read -r line; do
				if [[ "$line" == CLIENT_LIST* ]]; then
					CLIENT_COUNT=$((CLIENT_COUNT + 1))
					# 格式: CLIENT_LIST,用户名,IP地址,接收字节,发送字节,连接时间
					CLIENT_NAME=$(echo "$line" | cut -d',' -f2)
					CLIENT_IP=$(echo "$line" | cut -d',' -f3)
					BYTES_RECEIVED=$(echo "$line" | cut -d',' -f4)
					BYTES_SENT=$(echo "$line" | cut -d',' -f5)
					CONNECTED_SINCE=$(echo "$line" | cut -d',' -f6)

					# 转换字节为可读格式
					if [ "$BYTES_RECEIVED" -gt 1073741824 ]; then # 1 GB
						BYTES_RECEIVED=$(awk "BEGIN {printf \"%.2f GB\", $BYTES_RECEIVED/1073741824}")
					elif [ "$BYTES_RECEIVED" -gt 1048576 ]; then # 1 MB
						BYTES_RECEIVED=$(awk "BEGIN {printf \"%.2f MB\", $BYTES_RECEIVED/1048576}")
					elif [ "$BYTES_RECEIVED" -gt 1024 ]; then # 1 KB
						BYTES_RECEIVED=$(awk "BEGIN {printf \"%.2f KB\", $BYTES_RECEIVED/1024}")
					else
						BYTES_RECEIVED="${BYTES_RECEIVED} B"
					fi

					if [ "$BYTES_SENT" -gt 1073741824 ]; then # 1 GB
						BYTES_SENT=$(awk "BEGIN {printf \"%.2f GB\", $BYTES_SENT/1073741824}")
					elif [ "$BYTES_SENT" -gt 1048576 ]; then # 1 MB
						BYTES_SENT=$(awk "BEGIN {printf \"%.2f MB\", $BYTES_SENT/1048576}")
					elif [ "$BYTES_SENT" -gt 1024 ]; then # 1 KB
						BYTES_SENT=$(awk "BEGIN {printf \"%.2f KB\", $BYTES_SENT/1024}")
					else
						BYTES_SENT="${BYTES_SENT} B"
					fi

					echo "$CLIENT_NAME | $CLIENT_IP | $BYTES_RECEIVED | $BYTES_SENT | $CONNECTED_SINCE"
				fi
			done < /var/log/openvpn/status.log

			if [ "$CLIENT_COUNT" -eq 0 ]; then
				echo "当前没有客户端连接"
			fi

			# 显示路由表
			echo ""
			echo "虚拟IP路由表:"
			echo "------------------------------------"
			echo "用户名 | 虚拟IP | 最后更新时间"
			echo "------------------------------------"

			ROUTE_COUNT=0
			while read -r line; do
				if [[ "$line" == ROUTING_TABLE* ]]; then
					ROUTE_COUNT=$((ROUTE_COUNT + 1))
					# 格式: ROUTING_TABLE,用户名,虚拟IP,最后更新时间
					ROUTE_NAME=$(echo "$line" | cut -d',' -f2)
					ROUTE_IP=$(echo "$line" | cut -d',' -f3)
					ROUTE_LAST_REF=$(echo "$line" | cut -d',' -f4)

					echo "$ROUTE_NAME | $ROUTE_IP | $ROUTE_LAST_REF"
				fi
			done < /var/log/openvpn/status.log

			if [ "$ROUTE_COUNT" -eq 0 ]; then
				echo "路由表为空"
			fi
		else
			log "${YELLOW}警告: 找不到状态日志文件${NC}"
			echo "无法找到状态日志文件 (/var/log/openvpn/status.log)"
			echo "无法显示连接的客户端信息"
		fi
	else
		echo -e "服务状态: ${RED}未运行${NC}"
		log "${YELLOW}OpenVPN服务未运行${NC}"
	fi

	echo ""
	echo "OpenVPN配置信息:"
	echo "------------------------------------"

	# 显示服务器配置信息
	if [ -f /etc/openvpn/server.conf ]; then
		PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
		PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
		CIPHER=$(grep '^cipher ' /etc/openvpn/server.conf | cut -d " " -f 2)

		echo "端口: $PORT"
		echo "协议: $PROTOCOL"
		echo "加密算法: $CIPHER"

		# 显示DNS设置
		echo ""
		echo "DNS设置:"
		grep 'push "dhcp-option DNS' /etc/openvpn/server.conf | while read -r line; do
			DNS=$(echo "$line" | grep -oP 'DNS \K[0-9.]+')
			echo "- $DNS"
		done
	else
		log "${RED}错误: 找不到服务器配置文件${NC}"
		echo "无法找到服务器配置文件 (/etc/openvpn/server.conf)"
	fi

	exit 0
}

# 函数: 调整DNS设置
function updateDNSSettings() {
	log "${BLUE}开始调整DNS设置...${NC}"

	# 检查服务器配置文件是否存在
	if [ ! -f /etc/openvpn/server.conf ]; then
		log "${RED}错误: 找不到服务器配置文件${NC}"
		echo "无法找到服务器配置文件。OpenVPN可能未正确安装。"
		return 1
	fi

	# 备份当前配置
	log "备份当前配置文件..."
	backup_config "/etc/openvpn/server.conf"

	# 读取当前DNS设置
	log "读取当前DNS设置..."
	CURRENT_DNS=$(grep 'push "dhcp-option DNS' /etc/openvpn/server.conf | cut -d " " -f 4 | tr '\n' ' ')

	echo ""
	echo "当前DNS设置:"
	if [ -z "$CURRENT_DNS" ]; then
		echo "未找到DNS设置"
	else
		grep 'push "dhcp-option DNS' /etc/openvpn/server.conf | while read -r line; do
			DNS=$(echo "$line" | grep -oP 'DNS \K[0-9.]+')
			echo "- $DNS"
		done
	fi

	# 显示DNS选项菜单
	echo ""
	echo "请选择新的DNS设置:"
	echo "   1) 当前系统解析器 (来自 /etc/resolv.conf)"
	echo "   2) 自托管DNS解析器 (Unbound)"
	echo "   3) Cloudflare (1.1.1.1, 1.0.0.1)"
	echo "   4) Quad9 (9.9.9.9, 149.112.112.112)"
	echo "   5) Quad9 无审查 (9.9.9.10, 149.112.112.10)"
	echo "   6) FDN (80.67.169.40, 80.67.169.12)"
	echo "   7) DNS.WATCH (84.200.69.80, 84.200.70.40)"
	echo "   8) OpenDNS (208.67.222.222, 208.67.220.220)"
	echo "   9) Google (8.8.8.8, 8.8.4.4)"
	echo "   10) Yandex Basic (77.88.8.8, 77.88.8.1)"
	echo "   11) AdGuard DNS (94.140.14.14, 94.140.15.15)"
	echo "   12) NextDNS (45.90.28.167, 45.90.30.167)"
	echo "   13) 自定义DNS"
	echo "   14) 返回主菜单"

	until [[ $DNS_CHOICE =~ ^[1-9]|1[0-4]$ ]]; do
		read -rp "选择一个选项 [1-14]: " DNS_CHOICE
	done

	log "用户选择的DNS选项: $DNS_CHOICE"

	# 如果用户选择返回主菜单
	if [ "$DNS_CHOICE" -eq 14 ]; then
		log "用户选择返回主菜单"
		manageMenu
		return 0
	fi

	# 移除当前DNS设置
	log "移除当前DNS设置..."
	sed -i '/push "dhcp-option DNS/d' /etc/openvpn/server.conf

	# 根据用户选择添加新的DNS设置
	case $DNS_CHOICE in
	1) # 当前系统解析器
		log "用户选择使用当前系统解析器"

		# 定位正确的resolv.conf
		# 对于运行systemd-resolved的系统是必需的
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi

		# 从resolv.conf获取解析器并将其用于OpenVPN
		log "从 $RESOLVCONF 读取DNS服务器..."
		sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
			# 如果是IPv4地址或者IPv6已启用，则复制DNS设置
			if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
				log "添加DNS服务器: $line"
			fi
		done

		echo ""
		echo -e "${GREEN}已设置为使用系统DNS解析器${NC}"
		;;

	2) # 自托管DNS解析器 (Unbound)
		log "用户选择使用自托管DNS解析器 (Unbound)"

		# 检查Unbound是否已安装
		if ! command -v unbound &>/dev/null; then
			log "Unbound未安装，询问用户是否安装..."
			echo ""
			echo "Unbound DNS解析器未安装。"
			echo "您想现在安装它吗？"
			until [[ $INSTALL_UNBOUND =~ (y|n) ]]; do
				read -rp "安装Unbound？[y/n]: " -e INSTALL_UNBOUND
			done

			if [[ $INSTALL_UNBOUND == "y" ]]; then
				log "用户选择安装Unbound"
				installUnbound
			else
				log "用户选择不安装Unbound，使用Cloudflare DNS作为备选"
				echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
				echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
				log "添加Cloudflare DNS服务器: 1.0.0.1, 1.1.1.1"

				echo ""
				echo -e "${YELLOW}Unbound未安装，已设置为使用Cloudflare DNS${NC}"
				break
			fi
		fi

		# 配置OpenVPN使用Unbound
		echo 'push "dhcp-option DNS 10.8.0.1"' >> /etc/openvpn/server.conf
		log "添加DNS服务器: 10.8.0.1 (Unbound)"

		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'push "dhcp-option DNS fd42:42:42:42::1"' >> /etc/openvpn/server.conf
			log "添加IPv6 DNS服务器: fd42:42:42:42::1 (Unbound)"
		fi

		echo ""
		echo -e "${GREEN}已设置为使用自托管DNS解析器 (Unbound)${NC}"
		;;

	3) # Cloudflare
		log "用户选择使用Cloudflare DNS"
		echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
		log "添加DNS服务器: 1.0.0.1, 1.1.1.1"

		echo ""
		echo -e "${GREEN}已设置为使用Cloudflare DNS${NC}"
		;;

	4) # Quad9
		log "用户选择使用Quad9 DNS"
		echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server.conf
		log "添加DNS服务器: 9.9.9.9, 149.112.112.112"

		echo ""
		echo -e "${GREEN}已设置为使用Quad9 DNS${NC}"
		;;

	5) # Quad9 无审查
		log "用户选择使用Quad9无审查 DNS"
		echo 'push "dhcp-option DNS 9.9.9.10"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.10"' >> /etc/openvpn/server.conf
		log "添加DNS服务器: 9.9.9.10, 149.112.112.10"

		echo ""
		echo -e "${GREEN}已设置为使用Quad9无审查 DNS${NC}"
		;;

	6) # FDN
		log "用户选择使用FDN DNS"
		echo 'push "dhcp-option DNS 80.67.169.40"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 80.67.169.12"' >> /etc/openvpn/server.conf
		log "添加DNS服务器: 80.67.169.40, 80.67.169.12"

		echo ""
		echo -e "${GREEN}已设置为使用FDN DNS${NC}"
		;;

	7) # DNS.WATCH
		log "用户选择使用DNS.WATCH"
		echo 'push "dhcp-option DNS 84.200.69.80"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 84.200.70.40"' >> /etc/openvpn/server.conf
		log "添加DNS服务器: 84.200.69.80, 84.200.70.40"

		echo ""
		echo -e "${GREEN}已设置为使用DNS.WATCH${NC}"
		;;

	8) # OpenDNS
		log "用户选择使用OpenDNS"
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		log "添加DNS服务器: 208.67.222.222, 208.67.220.220"

		echo ""
		echo -e "${GREEN}已设置为使用OpenDNS${NC}"
		;;

	9) # Google
		log "用户选择使用Google DNS"
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		log "添加DNS服务器: 8.8.8.8, 8.8.4.4"

		echo ""
		echo -e "${GREEN}已设置为使用Google DNS${NC}"
		;;

	10) # Yandex Basic
		log "用户选择使用Yandex Basic DNS"
		echo 'push "dhcp-option DNS 77.88.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 77.88.8.1"' >> /etc/openvpn/server.conf
		log "添加DNS服务器: 77.88.8.8, 77.88.8.1"

		echo ""
		echo -e "${GREEN}已设置为使用Yandex Basic DNS${NC}"
		;;

	11) # AdGuard DNS
		log "用户选择使用AdGuard DNS"
		echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server.conf
		log "添加DNS服务器: 94.140.14.14, 94.140.15.15"

		echo ""
		echo -e "${GREEN}已设置为使用AdGuard DNS${NC}"
		;;

	12) # NextDNS
		log "用户选择使用NextDNS"
		echo 'push "dhcp-option DNS 45.90.28.167"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 45.90.30.167"' >> /etc/openvpn/server.conf
		log "添加DNS服务器: 45.90.28.167, 45.90.30.167"

		echo ""
		echo -e "${GREEN}已设置为使用NextDNS${NC}"
		;;

	13) # 自定义DNS
		log "用户选择使用自定义DNS"
		echo ""
		echo "请输入主要DNS服务器IP地址:"
		until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
			read -rp "主要DNS: " -e DNS1
		done

		echo 'push "dhcp-option DNS '"$DNS1"'"' >> /etc/openvpn/server.conf
		log "添加主要DNS服务器: $DNS1"

		echo ""
		echo "请输入次要DNS服务器IP地址 (可选):"
		echo "如果不需要次要DNS，请直接按回车键。"
		until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]] || [[ $DNS2 == "" ]]; do
			read -rp "次要DNS (可选): " -e DNS2
		done

		if [[ $DNS2 != "" ]]; then
			echo 'push "dhcp-option DNS '"$DNS2"'"' >> /etc/openvpn/server.conf
			log "添加次要DNS服务器: $DNS2"
		fi

		echo ""
		echo -e "${GREEN}已设置为使用自定义DNS${NC}"
		;;
	esac

	# 重启OpenVPN服务以应用更改
	echo ""
	echo "重启OpenVPN服务以应用更改..."

	if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
		run_cmd "systemctl restart openvpn-server@server" "重启OpenVPN服务"
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		run_cmd "systemctl restart openvpn" "重启OpenVPN服务"
	else
		run_cmd "systemctl restart openvpn@server" "重启OpenVPN服务"
	fi

	echo -e "${GREEN}DNS设置已更新并重启服务${NC}"

	exit 0
}

# 函数: 设置带宽限制
function setBandwidthLimit() {
	log "${BLUE}开始设置带宽限制...${NC}"

	# 检查客户端配置目录是否存在
	if [ ! -d /etc/openvpn/ccd ]; then
		log "创建客户端配置目录..."
		mkdir -p /etc/openvpn/ccd
	fi

	# 检查服务器配置是否包含client-config-dir指令
	if ! grep -q "^client-config-dir" /etc/openvpn/server.conf; then
		log "添加client-config-dir指令到服务器配置..."
		echo "client-config-dir /etc/openvpn/ccd" >> /etc/openvpn/server.conf
	fi

	# 获取有效客户端列表
	log "获取有效客户端列表..."
	if [ ! -f /etc/openvpn/easy-rsa/pki/index.txt ]; then
		log "${RED}错误: 找不到证书索引文件${NC}"
		echo "无法找到证书索引文件。OpenVPN可能未正确安装。"
		return 1
	fi

	# 提取有效客户端
	VALID_CLIENTS=$(grep "^V" /etc/openvpn/easy-rsa/pki/index.txt | grep -oP "CN=\K[^/]+")

	if [ -z "$VALID_CLIENTS" ]; then
		log "${YELLOW}未找到有效客户端${NC}"
		echo ""
		echo "未找到有效客户端。请先创建客户端。"
		return 0
	fi

	# 显示客户端选择菜单
	echo ""
	echo "为哪个客户端设置带宽限制？"
	echo "   0) 所有客户端"

	# 显示客户端列表
	CLIENT_COUNT=0
	while read -r CLIENT; do
		CLIENT_COUNT=$((CLIENT_COUNT + 1))
		echo "   $CLIENT_COUNT) $CLIENT"
	done <<< "$VALID_CLIENTS"

	echo "   $((CLIENT_COUNT + 1))) 返回主菜单"

	# 获取用户选择
	until [[ $CLIENT_CHOICE =~ ^[0-9]+$ ]] && [ "$CLIENT_CHOICE" -ge 0 ] && [ "$CLIENT_CHOICE" -le $((CLIENT_COUNT + 1)) ]; do
		read -rp "选择一个选项 [0-$((CLIENT_COUNT + 1))]: " CLIENT_CHOICE
	done

	# 如果用户选择返回主菜单
	if [ "$CLIENT_CHOICE" -eq $((CLIENT_COUNT + 1)) ]; then
		log "用户选择返回主菜单"
		manageMenu
		return 0
	fi

	# 确定选择的客户端
	if [ "$CLIENT_CHOICE" -eq 0 ]; then
		SELECTED_CLIENT="all"
		log "用户选择为所有客户端设置带宽限制"
	else
		SELECTED_CLIENT=$(echo "$VALID_CLIENTS" | sed -n "${CLIENT_CHOICE}p")
		log "用户选择为客户端 $SELECTED_CLIENT 设置带宽限制"
	fi

	# 显示当前带宽限制（如果存在）
	if [ "$SELECTED_CLIENT" != "all" ]; then
		if [ -f "/etc/openvpn/ccd/$SELECTED_CLIENT" ]; then
			CURRENT_LIMIT=$(grep "^rate-limit" "/etc/openvpn/ccd/$SELECTED_CLIENT")
			if [ -n "$CURRENT_LIMIT" ]; then
				echo ""
				echo "当前带宽限制: $CURRENT_LIMIT"
			fi
		fi
	else
		echo ""
		echo "注意: 您将为所有客户端设置相同的带宽限制。"
		echo "这将覆盖任何现有的客户端特定限制。"
	fi

	# 询问带宽限制类型
	echo ""
	echo "您想设置什么类型的带宽限制？"
	echo "   1) 上传和下载限制"
	echo "   2) 仅上传限制"
	echo "   3) 仅下载限制"
	echo "   4) 移除带宽限制"
	echo "   5) 返回主菜单"

	until [[ $LIMIT_TYPE =~ ^[1-5]$ ]]; do
		read -rp "选择一个选项 [1-5]: " LIMIT_TYPE
	done

	log "用户选择的带宽限制类型: $LIMIT_TYPE"

	case $LIMIT_TYPE in
	1) # 上传和下载限制
		log "用户选择设置上传和下载限制"
		echo ""
		echo "请输入上传速度限制（以KB/s为单位）:"
		until [[ $UPLOAD_LIMIT =~ ^[0-9]+$ ]] && [ "$UPLOAD_LIMIT" -gt 0 ]; do
			read -rp "上传限制 (KB/s): " UPLOAD_LIMIT
		done

		echo ""
		echo "请输入下载速度限制（以KB/s为单位）:"
		until [[ $DOWNLOAD_LIMIT =~ ^[0-9]+$ ]] && [ "$DOWNLOAD_LIMIT" -gt 0 ]; do
			read -rp "下载限制 (KB/s): " DOWNLOAD_LIMIT
		done

		# 应用限制
		if [ "$SELECTED_CLIENT" == "all" ]; then
			log "为所有客户端设置带宽限制: 上传=$UPLOAD_LIMIT KB/s, 下载=$DOWNLOAD_LIMIT KB/s"
			while read -r CLIENT; do
				echo "rate-limit $UPLOAD_LIMIT $DOWNLOAD_LIMIT" > "/etc/openvpn/ccd/$CLIENT"
				log "已为客户端 $CLIENT 设置带宽限制"
			done <<< "$VALID_CLIENTS"
		else
			log "为客户端 $SELECTED_CLIENT 设置带宽限制: 上传=$UPLOAD_LIMIT KB/s, 下载=$DOWNLOAD_LIMIT KB/s"
			echo "rate-limit $UPLOAD_LIMIT $DOWNLOAD_LIMIT" > "/etc/openvpn/ccd/$SELECTED_CLIENT"
		fi

		echo ""
		echo -e "${GREEN}带宽限制已成功设置${NC}"
		;;

	2) # 仅上传限制
		log "用户选择仅设置上传限制"
		echo ""
		echo "请输入上传速度限制（以KB/s为单位）:"
		until [[ $UPLOAD_LIMIT =~ ^[0-9]+$ ]] && [ "$UPLOAD_LIMIT" -gt 0 ]; do
			read -rp "上传限制 (KB/s): " UPLOAD_LIMIT
		done

		# 应用限制
		if [ "$SELECTED_CLIENT" == "all" ]; then
			log "为所有客户端设置上传限制: $UPLOAD_LIMIT KB/s"
			while read -r CLIENT; do
				echo "rate-limit $UPLOAD_LIMIT" > "/etc/openvpn/ccd/$CLIENT"
				log "已为客户端 $CLIENT 设置上传限制"
			done <<< "$VALID_CLIENTS"
		else
			log "为客户端 $SELECTED_CLIENT 设置上传限制: $UPLOAD_LIMIT KB/s"
			echo "rate-limit $UPLOAD_LIMIT" > "/etc/openvpn/ccd/$SELECTED_CLIENT"
		fi

		echo ""
		echo -e "${GREEN}上传限制已成功设置${NC}"
		;;

	3) # 仅下载限制
		log "用户选择仅设置下载限制"
		echo ""
		echo "请输入下载速度限制（以KB/s为单位）:"
		until [[ $DOWNLOAD_LIMIT =~ ^[0-9]+$ ]] && [ "$DOWNLOAD_LIMIT" -gt 0 ]; do
			read -rp "下载限制 (KB/s): " DOWNLOAD_LIMIT
		done

		# 应用限制
		if [ "$SELECTED_CLIENT" == "all" ]; then
			log "为所有客户端设置下载限制: $DOWNLOAD_LIMIT KB/s"
			while read -r CLIENT; do
				echo "rate-limit 0 $DOWNLOAD_LIMIT" > "/etc/openvpn/ccd/$CLIENT"
				log "已为客户端 $CLIENT 设置下载限制"
			done <<< "$VALID_CLIENTS"
		else
			log "为客户端 $SELECTED_CLIENT 设置下载限制: $DOWNLOAD_LIMIT KB/s"
			echo "rate-limit 0 $DOWNLOAD_LIMIT" > "/etc/openvpn/ccd/$SELECTED_CLIENT"
		fi

		echo ""
		echo -e "${GREEN}下载限制已成功设置${NC}"
		;;

	4) # 移除带宽限制
		log "用户选择移除带宽限制"

		if [ "$SELECTED_CLIENT" == "all" ]; then
			log "移除所有客户端的带宽限制"
			while read -r CLIENT; do
				if [ -f "/etc/openvpn/ccd/$CLIENT" ]; then
					# 如果文件只包含rate-limit行，则删除整个文件
					if [ "$(grep -v "^rate-limit" "/etc/openvpn/ccd/$CLIENT" | wc -l)" -eq 0 ]; then
						rm -f "/etc/openvpn/ccd/$CLIENT"
						log "已删除客户端 $CLIENT 的配置文件"
					else
						# 否则只删除rate-limit行
						sed -i '/^rate-limit/d' "/etc/openvpn/ccd/$CLIENT"
						log "已从客户端 $CLIENT 的配置文件中移除带宽限制"
					fi
				fi
			done <<< "$VALID_CLIENTS"
		else
			log "移除客户端 $SELECTED_CLIENT 的带宽限制"
			if [ -f "/etc/openvpn/ccd/$SELECTED_CLIENT" ]; then
				# 如果文件只包含rate-limit行，则删除整个文件
				if [ "$(grep -v "^rate-limit" "/etc/openvpn/ccd/$SELECTED_CLIENT" | wc -l)" -eq 0 ]; then
					rm -f "/etc/openvpn/ccd/$SELECTED_CLIENT"
					log "已删除客户端 $SELECTED_CLIENT 的配置文件"
				else
					# 否则只删除rate-limit行
					sed -i '/^rate-limit/d' "/etc/openvpn/ccd/$SELECTED_CLIENT"
					log "已从客户端 $SELECTED_CLIENT 的配置文件中移除带宽限制"
				fi
			fi
		fi

		echo ""
		echo -e "${GREEN}带宽限制已成功移除${NC}"
		;;

	5) # 返回主菜单
		log "用户选择返回主菜单"
		manageMenu
		return 0
		;;
	esac

	# 重启OpenVPN服务以应用更改
	echo ""
	echo "重启OpenVPN服务以应用更改..."

	if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
		run_cmd "systemctl restart openvpn-server@server" "重启OpenVPN服务"
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		run_cmd "systemctl restart openvpn" "重启OpenVPN服务"
	else
		run_cmd "systemctl restart openvpn@server" "重启OpenVPN服务"
	fi

	echo -e "${GREEN}带宽限制已应用并重启服务${NC}"

	exit 0
}

# 函数: 更新OpenVPN配置
function updateOpenVPNConfig() {
	log "${BLUE}开始更新OpenVPN配置...${NC}"

	# 检查服务器配置文件是否存在
	if [ ! -f /etc/openvpn/server.conf ]; then
		log "${RED}错误: 找不到服务器配置文件${NC}"
		echo "无法找到服务器配置文件。OpenVPN可能未正确安装。"
		return 1
	fi

	# 备份当前配置
	log "备份当前配置文件..."
	backup_config "/etc/openvpn/server.conf"

	# 读取当前配置
	log "读取当前配置..."
	CURRENT_PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
	CURRENT_PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
	CURRENT_CIPHER=$(grep '^cipher ' /etc/openvpn/server.conf | cut -d " " -f 2)

	echo ""
	echo "当前OpenVPN配置:"
	echo "端口: $CURRENT_PORT"
	echo "协议: $CURRENT_PROTOCOL"
	echo "加密算法: $CURRENT_CIPHER"
	echo ""

	# 显示更新选项菜单
	echo "您想更新哪个配置项？"
	echo "   1) 端口"
	echo "   2) 协议"
	echo "   3) 加密算法"
	echo "   4) 返回主菜单"

	until [[ $CONFIG_OPTION =~ ^[1-4]$ ]]; do
		read -rp "选择一个选项 [1-4]: " CONFIG_OPTION
	done

	log "用户选择的配置选项: $CONFIG_OPTION"

	case $CONFIG_OPTION in
	1) # 更新端口
		log "用户选择更新端口"
		echo ""
		echo "当前端口: $CURRENT_PORT"
		echo ""
		echo "请选择新的端口:"
		echo "   1) 默认: 1194"
		echo "   2) 自定义"
		echo "   3) 随机 [49152-65535]"

		until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "端口选择 [1-3]: " -e -i 1 PORT_CHOICE
		done

		case $PORT_CHOICE in
		1)
			NEW_PORT="1194"
			;;
		2)
			until [[ $NEW_PORT =~ ^[0-9]+$ ]] && [ "$NEW_PORT" -ge 1 ] && [ "$NEW_PORT" -le 65535 ]; do
				read -rp "自定义端口 [1-65535]: " -e -i 1194 NEW_PORT
			done
			;;
		3)
			# 在私有端口范围内生成随机数
			NEW_PORT=$(shuf -i49152-65535 -n1)
			echo "随机端口: $NEW_PORT"
			;;
		esac

		# 如果端口已更改，更新配置
		if [ "$CURRENT_PORT" != "$NEW_PORT" ]; then
			log "更新端口从 $CURRENT_PORT 到 $NEW_PORT"

			# 更新服务器配置
			sed -i "s/^port .*/port $NEW_PORT/" /etc/openvpn/server.conf

			# 如果使用SELinux，需要更新SELinux策略
			if hash sestatus 2>/dev/null; then
				if sestatus | grep "Current mode" | grep -qs "enforcing"; then
					log "更新SELinux策略..."

					# 删除旧端口策略
					if [ "$CURRENT_PORT" != "1194" ]; then
						run_cmd "semanage port -d -t openvpn_port_t -p $CURRENT_PROTOCOL $CURRENT_PORT" "删除旧端口SELinux策略"
					fi

					# 添加新端口策略
					if [ "$NEW_PORT" != "1194" ]; then
						run_cmd "semanage port -a -t openvpn_port_t -p $CURRENT_PROTOCOL $NEW_PORT" "添加新端口SELinux策略"
					fi
				fi
			fi

			# 更新防火墙规则
			log "更新防火墙规则..."

			# 更新添加规则脚本
			if [ -f /etc/iptables/add-openvpn-rules.sh ]; then
				sed -i "s/--dport $CURRENT_PORT/--dport $NEW_PORT/" /etc/iptables/add-openvpn-rules.sh
			fi

			# 更新删除规则脚本
			if [ -f /etc/iptables/rm-openvpn-rules.sh ]; then
				sed -i "s/--dport $CURRENT_PORT/--dport $NEW_PORT/" /etc/iptables/rm-openvpn-rules.sh
			fi

			# 应用新的防火墙规则
			run_cmd "systemctl restart iptables-openvpn" "重启防火墙规则"

			echo ""
			echo -e "${GREEN}端口已成功更新为 $NEW_PORT${NC}"

			# 更新客户端配置模板
			log "更新客户端配置模板..."
			if [ -f /etc/openvpn/client-template.txt ]; then
				sed -i "s/^remote .* $CURRENT_PORT/remote $IP $NEW_PORT/" /etc/openvpn/client-template.txt
			fi

			# 提示用户需要更新现有客户端配置
			echo ""
			echo "注意: 您需要更新所有现有客户端的配置文件，将端口从 $CURRENT_PORT 更改为 $NEW_PORT。"
			echo "或者，您可以为现有客户端生成新的配置文件。"
		else
			echo ""
			echo "端口未更改。"
		fi
		;;

	2) # 更新协议
		log "用户选择更新协议"
		echo ""
		echo "当前协议: $CURRENT_PROTOCOL"
		echo ""
		echo "请选择新的协议:"
		echo "   1) UDP (推荐)"
		echo "   2) TCP"

		until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
			read -rp "协议 [1-2]: " -e -i 1 PROTOCOL_CHOICE
		done

		case $PROTOCOL_CHOICE in
		1)
			NEW_PROTOCOL="udp"
			;;
		2)
			NEW_PROTOCOL="tcp"
			;;
		esac

		# 如果协议已更改，更新配置
		if [ "$CURRENT_PROTOCOL" != "$NEW_PROTOCOL" ]; then
			log "更新协议从 $CURRENT_PROTOCOL 到 $NEW_PROTOCOL"

			# 更新服务器配置
			sed -i "s/^proto .*/proto $NEW_PROTOCOL/" /etc/openvpn/server.conf

			# 如果使用SELinux，需要更新SELinux策略
			if hash sestatus 2>/dev/null; then
				if sestatus | grep "Current mode" | grep -qs "enforcing"; then
					log "更新SELinux策略..."

					# 删除旧协议策略
					if [ "$CURRENT_PORT" != "1194" ]; then
						run_cmd "semanage port -d -t openvpn_port_t -p $CURRENT_PROTOCOL $CURRENT_PORT" "删除旧协议SELinux策略"
					fi

					# 添加新协议策略
					if [ "$CURRENT_PORT" != "1194" ]; then
						run_cmd "semanage port -a -t openvpn_port_t -p $NEW_PROTOCOL $CURRENT_PORT" "添加新协议SELinux策略"
					fi
				fi
			fi

			# 更新防火墙规则
			log "更新防火墙规则..."

			# 更新添加规则脚本
			if [ -f /etc/iptables/add-openvpn-rules.sh ]; then
				sed -i "s/-p $CURRENT_PROTOCOL/-p $NEW_PROTOCOL/" /etc/iptables/add-openvpn-rules.sh
			fi

			# 更新删除规则脚本
			if [ -f /etc/iptables/rm-openvpn-rules.sh ]; then
				sed -i "s/-p $CURRENT_PROTOCOL/-p $NEW_PROTOCOL/" /etc/iptables/rm-openvpn-rules.sh
			fi

			# 应用新的防火墙规则
			run_cmd "systemctl restart iptables-openvpn" "重启防火墙规则"

			# 更新客户端配置模板
			log "更新客户端配置模板..."
			if [ -f /etc/openvpn/client-template.txt ]; then
				# 删除旧的协议行和explicit-exit-notify行
				sed -i "/^proto .*/d" /etc/openvpn/client-template.txt
				sed -i "/^explicit-exit-notify/d" /etc/openvpn/client-template.txt

				# 在第二行添加新的协议行
				if [ "$NEW_PROTOCOL" == "udp" ]; then
					sed -i "2i proto udp\nexplicit-exit-notify" /etc/openvpn/client-template.txt
				else
					sed -i "2i proto tcp-client" /etc/openvpn/client-template.txt
				fi
			fi

			echo ""
			echo -e "${GREEN}协议已成功更新为 $NEW_PROTOCOL${NC}"

			# 提示用户需要更新现有客户端配置
			echo ""
			echo "注意: 您需要更新所有现有客户端的配置文件，将协议从 $CURRENT_PROTOCOL 更改为 $NEW_PROTOCOL。"
			echo "或者，您可以为现有客户端生成新的配置文件。"
		else
			echo ""
			echo "协议未更改。"
		fi
		;;

	3) # 更新加密算法
		log "用户选择更新加密算法"
		echo ""
		echo "当前加密算法: $CURRENT_CIPHER"
		echo ""
		echo "请选择新的加密算法:"
		echo "   1) AES-128-GCM (推荐)"
		echo "   2) AES-192-GCM"
		echo "   3) AES-256-GCM"
		echo "   4) AES-128-CBC"
		echo "   5) AES-192-CBC"
		echo "   6) AES-256-CBC"

		until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
			read -rp "加密算法 [1-6]: " -e -i 1 CIPHER_CHOICE
		done

		case $CIPHER_CHOICE in
		1)
			NEW_CIPHER="AES-128-GCM"
			;;
		2)
			NEW_CIPHER="AES-192-GCM"
			;;
		3)
			NEW_CIPHER="AES-256-GCM"
			;;
		4)
			NEW_CIPHER="AES-128-CBC"
			;;
		5)
			NEW_CIPHER="AES-192-CBC"
			;;
		6)
			NEW_CIPHER="AES-256-CBC"
			;;
		esac

		# 如果加密算法已更改，更新配置
		if [ "$CURRENT_CIPHER" != "$NEW_CIPHER" ]; then
			log "更新加密算法从 $CURRENT_CIPHER 到 $NEW_CIPHER"

			# 更新服务器配置
			sed -i "s/^cipher .*/cipher $NEW_CIPHER/" /etc/openvpn/server.conf
			sed -i "s/^ncp-ciphers .*/ncp-ciphers $NEW_CIPHER/" /etc/openvpn/server.conf

			# 更新客户端配置模板
			log "更新客户端配置模板..."
			if [ -f /etc/openvpn/client-template.txt ]; then
				sed -i "s/^cipher .*/cipher $NEW_CIPHER/" /etc/openvpn/client-template.txt
			fi

			echo ""
			echo -e "${GREEN}加密算法已成功更新为 $NEW_CIPHER${NC}"

			# 提示用户需要更新现有客户端配置
			echo ""
			echo "注意: 您需要更新所有现有客户端的配置文件，将加密算法从 $CURRENT_CIPHER 更改为 $NEW_CIPHER。"
			echo "或者，您可以为现有客户端生成新的配置文件。"
		else
			echo ""
			echo "加密算法未更改。"
		fi
		;;

	4) # 返回主菜单
		log "用户选择返回主菜单"
		manageMenu
		return 0
		;;
	esac

	# 重启OpenVPN服务以应用更改
	echo ""
	echo "重启OpenVPN服务以应用更改..."

	if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
		run_cmd "systemctl restart openvpn-server@server" "重启OpenVPN服务"
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		run_cmd "systemctl restart openvpn" "重启OpenVPN服务"
	else
		run_cmd "systemctl restart openvpn@server" "重启OpenVPN服务"
	fi

	echo -e "${GREEN}OpenVPN配置已更新并重启服务${NC}"

	exit 0
}

function manageMenu() {
	log "${BLUE}显示管理菜单...${NC}"

	echo "欢迎使用OpenVPN安装程序！"
	echo "Git仓库地址：https://github.com/rockyshi1993/OpenVpn"
	echo ""
	echo "看起来OpenVPN已经安装。"
	echo ""
	echo "您想做什么？"
	echo "   1) 添加新用户"
	echo "   2) 撤销现有用户"
	echo "   3) 查看当前用户列表"
	echo "   4) 更新OpenVPN配置"
	echo "   5) 检查OpenVPN状态"
	echo "   6) 设置带宽限制"
	echo "   7) 调整DNS设置"
	echo "   8) 移除OpenVPN"
	echo "   9) 退出"
	until [[ $MENU_OPTION =~ ^[1-9]$ ]]; do
		read -rp "选择一个选项 [1-9]: " MENU_OPTION
	done

	log "用户选择的菜单选项: $MENU_OPTION"

	case $MENU_OPTION in
	1)
		log "用户选择添加新用户"
		newClient
		;;
	2)
		log "用户选择撤销现有用户"
		revokeClient
		;;
	3)
		log "用户选择查看当前用户列表"
		listClients
		;;
	4)
		log "用户选择更新OpenVPN配置"
		updateOpenVPNConfig
		;;
	5)
		log "用户选择检查OpenVPN状态"
		checkStatus
		;;
	6)
		log "用户选择设置带宽限制"
		setBandwidthLimit
		;;
	7)
		log "用户选择调整DNS设置"
		updateDNSSettings
		;;
	8)
		log "用户选择移除OpenVPN"
		removeOpenVPN
		;;
	9)
		log "用户选择退出"
		log "${GREEN}脚本执行完毕${NC}"
		exit 0
		;;
	esac
}

# 创建日志目录
if [ ! -d /var/log/openvpn ]; then
    mkdir -p /var/log/openvpn
fi

# 记录脚本开始执行
log "${BLUE}OpenVPN安装脚本开始执行${NC}"
log "脚本版本: 1.0"
log "执行时间: $(date)"
log "系统信息: $(uname -a)"

# 检查root权限、TUN模块和操作系统
initialCheck

# 检查OpenVPN是否已安装
if [[ -e /etc/openvpn/server.conf && $AUTO_INSTALL != "y" ]]; then
    log "检测到OpenVPN已安装，显示管理菜单"
    manageMenu
else
    log "OpenVPN未安装或指定了自动安装，开始安装过程"
    installOpenVPN
fi


# 记录脚本结束
log "${GREEN}OpenVPN安装脚本执行完毕${NC}"
