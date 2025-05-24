# OpenVPN 安装脚本

这是一个用于自动安装和配置 OpenVPN 服务器的脚本，基于 [angristan/openvpn-install](https://github.com/angristan/openvpn-install) 项目。该脚本支持多种 Linux 发行版，包括 Debian、Ubuntu、CentOS、Fedora、Oracle Linux、Amazon Linux 和 Arch Linux。

## 功能特点

- 自动检测操作系统类型和版本
- 自动安装 OpenVPN 和所需依赖
- 自动配置 PKI（公钥基础设施）和证书
- 支持 IPv6
- 支持自定义端口和协议（UDP/TCP）
- 多种 DNS 解析器选项
- 可选的数据压缩
- 可自定义加密设置
- 支持 ECDSA 和 RSA 证书
- 支持 ECDH 和 DH 密钥交换
- 自动配置防火墙规则
- 简单的客户端管理（添加、撤销）
- 完整的卸载功能

## 系统要求

- 支持的操作系统：
  - Debian 9+
  - Ubuntu 16.04+
  - CentOS 7+
  - Fedora
  - Oracle Linux 8
  - Amazon Linux 2
  - Amazon Linux 2023.6+
  - Arch Linux
- root 权限
- TUN 模块可用

## 使用方法

### 安装 OpenVPN

1. 下载脚本：

```bash
wget https://github.com/rockyshi1993/OpenVpn/blob/master/install.sh -O install.sh
chmod +x install.sh
```

2. 运行脚本：

```bash
./install.sh
```

3. 按照提示进行配置：
   - 选择 IP 地址
   - 是否启用 IPv6
   - 选择端口
   - 选择协议（UDP/TCP）
   - 选择 DNS 解析器
   - 是否启用压缩
   - 是否自定义加密设置

4. 安装完成后，客户端配置文件将保存在用户主目录中。

### 管理 OpenVPN

如果 OpenVPN 已经安装，再次运行脚本将显示管理菜单：

```bash
./install.sh
```

管理菜单提供以下选项：
1. 添加新用户
2. 撤销现有用户
3. 卸载 OpenVPN
4. 退出

## 配置选项详解

### IP 地址

脚本会自动检测服务器的公共 IP 地址。如果服务器位于 NAT 后面，您需要提供公共 IP 地址或主机名。

### IPv6 支持

您可以选择是否启用 IPv6 支持。脚本会自动检测服务器是否有 IPv6 连接，并给出建议。

### 端口

您可以选择以下端口选项：
- 默认端口 (1194)
- 自定义端口
- 随机端口 (49152-65535)

### 协议

您可以选择以下协议：
- UDP（推荐，速度更快）
- TCP（仅在 UDP 不可用时使用）

### DNS 解析器

脚本提供多种 DNS 解析器选项：
1. 当前系统解析器（来自 /etc/resolv.conf）
2. 自托管 DNS 解析器 (Unbound)
3. Cloudflare (1.1.1.1, 1.0.0.1)
4. Quad9 (9.9.9.9, 149.112.112.112)
5. Quad9 无审查 (9.9.9.10, 149.112.112.10)
6. FDN (80.67.169.40, 80.67.169.12)
7. DNS.WATCH (84.200.69.80, 84.200.70.40)
8. OpenDNS (208.67.222.222, 208.67.220.220)
9. Google (8.8.8.8, 8.8.4.4)
10. Yandex Basic (77.88.8.8, 77.88.8.1)
11. AdGuard DNS (94.140.14.14, 94.140.15.15)
12. NextDNS (45.90.28.167, 45.90.30.167)
13. 自定义 DNS

### 压缩

您可以选择是否启用压缩。由于 VORACLE 攻击利用压缩，因此不推荐使用。如果启用，可以选择以下压缩算法：
- LZ4-v2（推荐）
- LZ4
- LZO

### 加密设置

您可以使用默认的安全参数，或自定义以下加密设置：

#### 数据通道加密算法
- AES-128-GCM（推荐）
- AES-192-GCM
- AES-256-GCM
- AES-128-CBC
- AES-192-CBC
- AES-256-CBC

#### 证书类型
- ECDSA（推荐）
  - 曲线选项：prime256v1（推荐）、secp384r1、secp521r1
- RSA
  - 密钥大小选项：2048 位（推荐）、3072 位、4096 位

#### 控制通道加密算法
- ECDSA 证书：ECDHE-ECDSA-AES-128-GCM-SHA256（推荐）或 ECDHE-ECDSA-AES-256-GCM-SHA384
- RSA 证书：ECDHE-RSA-AES-128-GCM-SHA256（推荐）或 ECDHE-RSA-AES-256-GCM-SHA384

#### Diffie-Hellman 密钥类型
- ECDH（推荐）
  - 曲线选项：prime256v1（推荐）、secp384r1、secp521r1
- DH
  - 密钥大小选项：2048 位（推荐）、3072 位、4096 位

#### HMAC 摘要算法
- SHA-256（推荐）
- SHA-384
- SHA-512

#### 控制通道额外安全机制
- tls-crypt（推荐）：对数据包进行身份验证和加密
- tls-auth：仅对数据包进行身份验证

## 客户端配置

安装完成后，客户端配置文件（.ovpn）将保存在用户主目录中。您需要将此文件导入到 OpenVPN 客户端中。

### 支持的客户端

- **Windows**: [OpenVPN GUI](https://openvpn.net/community-downloads/)
- **macOS**: [Tunnelblick](https://tunnelblick.net/) 或 [OpenVPN Connect](https://openvpn.net/client-connect-vpn-for-mac-os/)
- **Linux**: 命令行客户端或 NetworkManager
- **Android**: [OpenVPN Connect](https://play.google.com/store/apps/details?id=net.openvpn.openvpn)
- **iOS**: [OpenVPN Connect](https://apps.apple.com/us/app/openvpn-connect/id590379981)

## 添加新客户端

要为新客户端创建配置文件，只需再次运行脚本并选择"添加新用户"选项：

```bash
./install.sh
```

然后输入客户端名称，并选择是否为客户端添加密码保护。

## 撤销客户端证书

要撤销客户端证书，运行脚本并选择"撤销现有用户"选项：

```bash
./install.sh
```

然后选择要撤销的客户端证书。

## 卸载 OpenVPN

要卸载 OpenVPN，运行脚本并选择"卸载 OpenVPN"选项：

```bash
./install.sh
```

这将完全删除 OpenVPN 及其所有配置文件、证书和密钥。

## 故障排除

### 常见问题

1. **TUN 模块不可用**：确保您的系统支持 TUN/TAP 设备。在某些 VPS 提供商中，您可能需要在控制面板中启用 TUN/TAP。

2. **端口被占用**：如果您选择的端口已被其他服务占用，请选择其他端口。

3. **防火墙问题**：确保您的防火墙允许 OpenVPN 端口。脚本会自动添加必要的防火墙规则，但某些系统可能需要额外配置。

4. **客户端连接问题**：
   - 检查客户端配置文件是否正确
   - 确保服务器端口已开放
   - 检查服务器防火墙设置
   - 验证服务器 IP 地址是否正确

5. **DNS 解析问题**：如果客户端可以连接但无法解析域名，请尝试使用不同的 DNS 解析器选项。

### 日志文件

检查 OpenVPN 日志文件以获取更多信息：

```bash
cat /var/log/openvpn/status.log   # 状态日志
journalctl -u openvpn@server      # 系统日志（systemd）
```

## 安全建议

- 定期更新系统和 OpenVPN
- 使用强密码保护客户端证书
- 定期撤销不再使用的客户端证书
- 考虑使用更强的加密设置（如 AES-256-GCM）
- 避免使用压缩（由于 VORACLE 攻击）
- 使用 tls-crypt 而不是 tls-auth 以提供更好的安全性

## 致谢

此脚本基于 [angristan/openvpn-install](https://github.com/angristan/openvpn-install) 项目。