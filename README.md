# OpenVPN 自动安装脚本

这个脚本可以自动化安装和配置 OpenVPN 服务器，支持 Ubuntu/Debian 和 CentOS/RHEL 系统。

## 功能特点

- 自动检测操作系统类型
- 自动安装所需的依赖包
- 自动检测和安装缺失的命令
- 自动配置 PKI 和证书
- 自动配置 OpenVPN 服务器
- 自动检测主网络接口
- 自动配置网络和防火墙规则
- 自动生成客户端配置文件
- 支持自定义配置选项
- 详细的日志记录和错误处理
- 交互式选择 UDP/TCP 传输协议
- 检测已安装状态并提供三个选项（生成新配置、修复安装、完全卸载）
- 支持高级配置选项：
  - TLS 版本选择 (1.2, 1.3)
  - 保持连接参数自定义
  - 日志级别设置
  - IPv6 支持
  - 最大客户端连接数设置
  - 重复 Common Name 支持
  - DNS 泄漏防护
  - 客户端之间通信选项
- 增强的安全性选项
- 改进的用户交互体验
- 更全面的错误处理和验证

## 使用方法

1. 下载脚本：

```bash
wget https://example.com/install.sh -O install.sh
chmod +x install.sh
```

2. 以 root 用户身份运行脚本：

```bash
sudo ./install.sh
```

3. 根据脚本提示进行操作：
   - 如果 OpenVPN 已安装，将显示菜单选项（生成新配置、修复安装、完全卸载）
   - 如果 OpenVPN 未安装，将提示您选择传输协议（UDP 或 TCP）

4. 使用自定义选项运行脚本：

```bash
sudo ./install.sh --port 443 --protocol tcp --client myvpn
sudo ./install.sh --client myvpn --output-dir /home/user/configs --output-file myvpn-config.ovpn
sudo ./install.sh --tls-version 1.3 --keepalive 10,60 --enable-ipv6 --client-to-client
sudo ./install.sh --max-clients 50 --log-level 4 --push-block-dns --duplicate-cn
```

注意：
- 如果通过命令行指定了协议（使用 `--protocol` 选项），则不会显示协议选择提示。
- 高级选项可以与基本选项组合使用，例如：
  ```bash
  sudo ./install.sh --port 443 --protocol tcp --client myvpn --tls-version 1.3 --enable-ipv6
  ```

## 可用选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `-h, --help` | 显示帮助信息 | - |
| `-p, --port PORT` | 设置 OpenVPN 端口 | 1194 |
| `-t, --protocol PROTOCOL` | 设置协议 (udp\|tcp) | udp |
| `-c, --client NAME` | 设置客户端名称 | client1 |
| `-d, --dns DNS1,DNS2` | 设置 DNS 服务器 | 8.8.8.8,8.8.4.4 |
| `-s, --subnet SUBNET` | 设置 VPN 子网 | 10.8.0.0 |
| `-m, --netmask NETMASK` | 设置 VPN 子网掩码 | 255.255.255.0 |
| `-e, --cipher CIPHER` | 设置加密算法 | AES-256-CBC |
| `-a, --auth AUTH` | 设置认证算法 | SHA256 |
| `-o, --output-dir DIR` | 设置客户端配置文件输出目录 | 脚本所在目录 |
| `-f, --output-file FILE` | 设置客户端配置文件名称 | <客户端名称>.ovpn |
| `--tls-version VERSION` | 设置 TLS 版本 (1.2, 1.3) | 1.2 |
| `--keepalive PING,TIMEOUT` | 设置保持连接参数 | 10,120 |
| `--log-level LEVEL` | 设置日志级别 (0-9) | 3 |
| `--enable-ipv6` | 启用 IPv6 支持 | 禁用 |
| `--max-clients NUMBER` | 设置最大客户端连接数 | 100 |
| `--duplicate-cn` | 允许重复的 Common Name | 禁用 |
| `--push-block-dns` | 阻止 DNS 泄漏 | 禁用 |
| `--client-to-client` | 允许客户端之间通信 | 禁用 |

## 安装过程

脚本执行以下步骤：

1. 检查是否为 root 用户
2. 检测操作系统类型
3. 检查必要的命令并安装缺失的命令
4. 检查 OpenVPN 是否已安装
   - 如果已安装，显示菜单（生成新配置、修复安装、完全卸载）
   - 如果未安装，继续安装流程
5. 安装依赖包
6. 选择传输协议（如果未通过命令行指定）
7. 设置 PKI 和证书
8. 配置 OpenVPN 服务器
9. 配置网络和防火墙规则（自动检测主网络接口）
10. 生成客户端证书和配置
11. 启动 OpenVPN 服务
12. 显示安装完成信息

## 高级配置选项

脚本提供了多种高级配置选项，以满足不同的需求和场景：

### TLS 版本

使用 `--tls-version` 选项可以设置 TLS 版本：
- `1.2`：兼容性更好，适用于大多数客户端
- `1.3`：安全性更高，但可能不兼容某些旧客户端

```bash
sudo ./install.sh --tls-version 1.3
```

### 保持连接参数

使用 `--keepalive` 选项可以设置保持连接参数，格式为 `PING,TIMEOUT`：
- `PING`：发送 ping 消息的间隔（秒）
- `TIMEOUT`：未收到 ping 响应后的超时时间（秒）

```bash
sudo ./install.sh --keepalive 10,60
```

### 日志级别

使用 `--log-level` 选项可以设置日志级别（0-9）：
- `0`：静默模式，不输出任何日志
- `3`：默认级别，输出基本日志
- `4-9`：详细日志，用于调试

```bash
sudo ./install.sh --log-level 4
```

### IPv6 支持

使用 `--enable-ipv6` 选项可以启用 IPv6 支持：

```bash
sudo ./install.sh --enable-ipv6
```

### 最大客户端连接数

使用 `--max-clients` 选项可以设置最大客户端连接数：

```bash
sudo ./install.sh --max-clients 50
```

### 重复 Common Name

使用 `--duplicate-cn` 选项可以允许多个客户端使用同一个证书：

```bash
sudo ./install.sh --duplicate-cn
```

### DNS 泄漏防护

使用 `--push-block-dns` 选项可以阻止 DNS 泄漏：

```bash
sudo ./install.sh --push-block-dns
```

### 客户端之间通信

使用 `--client-to-client` 选项可以允许客户端之间直接通信：

```bash
sudo ./install.sh --client-to-client
```

## 客户端配置

安装完成后，客户端配置文件将默认保存在脚本执行的当前目录中。您需要将这些文件安全地传输到客户端设备。

客户端配置文件会自动从服务器配置中读取实际设置，包括协议、端口、加密算法、认证算法和压缩设置，确保客户端和服务器配置一致。

您可以在安装时使用 `-o` 或 `--output-dir` 选项指定客户端配置文件的输出目录，使用 `-f` 或 `--output-file` 选项指定客户端配置文件的名称。例如：

```bash
sudo ./install.sh --client myvpn --output-dir /home/user/configs --output-file myvpn-config.ovpn
```

要为其他客户端生成配置文件，只需重新执行当前脚本即可：

```bash
sudo ./install.sh
```

然后选择选项 "1) 生成新的客户端配置文件"，按照提示输入客户端名称和配置文件名称即可。配置文件默认保存在脚本所在目录。

您也可以直接使用以下命令：

```bash
sudo /etc/openvpn/make_client_config.sh client2 [输出目录] [输出文件名]
```

脚本会自动检查客户端证书和密钥是否存在，如果不存在，会提示您先生成证书和密钥。

## 已安装系统的菜单选项

当您在已安装 OpenVPN 的系统上运行脚本时，将显示以下菜单选项：

1. **生成新的客户端配置文件**：为新客户端创建证书和配置文件，无需重新安装整个系统。您可以指定客户端名称、输出目录和文件名。

2. **修复当前安装**：修复常见的 OpenVPN 安装问题，包括：
   - 修复文件权限
   - 确保 IP 转发已启用
   - 检查并修复防火墙规则
   - 重新启动服务

3. **修改连接协议**：修改 OpenVPN 服务器使用的传输协议（UDP/TCP）和端口。

4. **重启 OpenVPN 服务**：重新启动 OpenVPN 服务，适用于配置更改后或服务异常时。

5. **查看服务器信息**：显示 OpenVPN 服务器的详细信息，包括：
   - 服务状态和运行时间
   - 服务器 IP 地址
   - 配置信息（协议、端口、子网、加密算法等）
   - 防火墙状态
   - 当前连接的客户端数量
   - 系统信息（操作系统、内核版本、OpenVPN 版本）

6. **查看 VPN 实时状态**：实时监控 VPN 连接状态，包括：
   - 已连接的客户端列表
   - 客户端详细信息（名称、远程 IP、虚拟 IP、连接时间）
   - 客户端流量统计（接收和发送的数据量）
   - 系统负载和网络接口统计
   - OpenVPN 进程信息

7. **完全卸载 OpenVPN**：完全删除 OpenVPN 及其所有相关文件和配置，包括：
   - 删除 OpenVPN 软件包
   - 删除配置文件和证书
   - 删除日志文件
   - 移除防火墙规则

8. **退出**：退出脚本，不执行任何操作。

## 支持的客户端

- **Windows**: 使用 [OpenVPN GUI](https://openvpn.net/community-downloads/)
- **macOS**: 使用 [Tunnelblick](https://tunnelblick.net/)
- **Linux**: 使用命令行或 NetworkManager
- **Android**: 使用 [OpenVPN Connect](https://play.google.com/store/apps/details?id=net.openvpn.openvpn)
- **iOS**: 使用 [OpenVPN Connect](https://apps.apple.com/us/app/openvpn-connect/id590379981)

## 故障排除

如果遇到问题，请检查日志文件：

```bash
cat /var/log/openvpn-install.log
```

常见问题：

1. **服务无法启动**: 检查 `journalctl -u openvpn@server` 查看详细错误信息
2. **客户端无法连接**: 检查防火墙设置，确保端口已开放
3. **网络问题**: 检查 IP 转发是否已启用 `sysctl net.ipv4.ip_forward`
4. **客户端配置生成失败**: 检查客户端证书和密钥是否存在，可以使用 `ls -la /etc/openvpn/easy-rsa/pki/issued/` 和 `ls -la /etc/openvpn/easy-rsa/pki/private/` 查看
5. **网络接口检测失败**: 如果脚本无法自动检测主网络接口，会使用默认值 eth0，您可能需要手动修改配置

## 安全提示

- 定期更新系统和 OpenVPN 软件
- 使用强密码和证书
- 考虑启用双因素认证
- 定期轮换证书
- 监控 OpenVPN 日志

## 版本历史

### 版本 1.7 (2025-05-30)

- 优化脚本性能和可靠性
- 增强脚本的灵活性和功能
- 添加多项高级配置选项：
  - TLS 版本选择 (1.2, 1.3)
  - 保持连接参数自定义
  - 日志级别设置
  - IPv6 支持
  - 最大客户端连接数设置
  - 重复 Common Name 支持
  - DNS 泄漏防护
  - 客户端之间通信选项
- 改进用户交互体验
- 增强安全性选项
- 更新文档以反映新功能

### 版本 1.6 (2025-05-25)

- 添加功能：安装时可以手动选择 UDP/TCP 传输协议
- 添加功能：检测已安装状态并提供三个选项（生成新配置、修复安装、完全卸载）
- 更新文档以反映新功能

### 版本 1.5 (2025-05-24)

- 添加功能：客户端配置文件默认保存在当前脚本执行目录
- 添加功能：支持自定义生成的配置文件名称
- 更新文档以反映新功能

### 版本 1.4 (2025-05-23)

- 增强防火墙配置，确保 OpenVPN 端口在所有防火墙系统中正确开启
- 添加防火墙端口检查，避免重复规则

### 版本 1.3 (2025-05-22)

- 修复证书生成过程中的确认输入问题
- 优化脚本行尾为 Linux 风格 (LF)

### 版本 1.2 (2023-12-15)

- 添加已存在 OpenVPN 安装检查
- 添加所有用户输入参数的验证
- 添加错误处理和清理机制
- 改进脚本的幂等性，支持多次运行
- 添加信号处理以确保清理

### 版本 1.1 (2023-11-30)

- 添加客户端名称参数验证
- 修复网络接口硬编码问题，动态检测主网络接口
- 修复 UFW 配置中的网络接口硬编码
- 添加客户端证书和密钥文件存在性检查
- 改进客户端配置生成，从服务器配置中读取实际设置
- 添加必要命令检查和自动安装缺失命令

## 许可证

MIT
