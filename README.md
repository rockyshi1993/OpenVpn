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
- 默认使用UDP协议并优化以躲避中国运营商封锁
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
wget https://github.com/rockyshi1993/OpenVpn/blob/master/install.sh -O install.sh
chmod +x install.sh
```

2. 以 root 用户身份运行脚本：

```bash
sudo ./install.sh
```

3. 根据脚本提示进行操作：
   - 如果 OpenVPN 已安装，将显示菜单选项（生成新配置、修复安装、完全卸载）
   - 如果 OpenVPN 未安装，脚本将默认使用UDP协议并自动选择随机端口以避免中国运营商封锁

4. 使用自定义选项运行脚本：

```bash
sudo ./install.sh --port 12345 --client myvpn
sudo ./install.sh --client myvpn --output-dir /home/user/configs --output-file myvpn-config.ovpn
sudo ./install.sh --tls-version 1.3 --keepalive 10,60 --enable-ipv6 --client-to-client
sudo ./install.sh --max-clients 50 --log-level 4 --push-block-dns --duplicate-cn
sudo ./install.sh --mobile-device --client mobile-client
```

注意：
- 脚本默认使用UDP协议并自动选择随机端口以避免中国运营商封锁。
- 高级选项可以与基本选项组合使用，例如：
  ```bash
  sudo ./install.sh --port 12345 --client myvpn --tls-version 1.3 --enable-ipv6
  sudo ./install.sh --mobile-device --client mobile-client --port 12345 --push-block-dns
  ```

## 可用选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `-h, --help` | 显示帮助信息 | - |
| `-p, --port PORT` | 设置 OpenVPN 端口 | 1194 |
| `-t, --protocol` | 设置协议 (仅支持UDP，为避免中国运营商封锁) | udp |
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
| `--mobile-device` | 生成移动设备专用配置 (避免使用不支持的 fragment 指令) | 禁用 |

## 安装过程

脚本执行以下步骤：

1. 检查是否为 root 用户
2. 检测操作系统类型
3. 检查必要的命令并安装缺失的命令
4. 检查 OpenVPN 是否已安装
   - 如果已安装，显示菜单（生成新配置、修复安装、完全卸载）
   - 如果未安装，继续安装流程
5. 安装依赖包
6. 设置UDP协议和随机端口（以避免中国运营商封锁）
7. 设置 PKI 和证书
8. 配置 OpenVPN 服务器
9. 配置网络和防火墙规则（自动检测主网络接口）
10. 生成客户端证书和配置
11. 启动 OpenVPN 服务
12. 显示安装完成信息

## 躲避中国运营商封锁的优化

为了提高在中国网络环境下的连接成功率，脚本实现了以下优化措施：

1. **仅使用UDP协议**：UDP协议比TCP更难被识别和封锁。
2. **随机端口**：默认使用10000-65000范围内的随机端口，避开常见的被监控端口。
3. **数据包分片**：使用`mssfix`和`fragment`参数将数据包分割成较小的片段，减少被深度包检测(DPI)识别的可能性。
4. **使用指定的加密方式**：通过明确设置`cipher`和`data-ciphers`参数，确保使用安全的加密算法。
5. **流量混淆**：使用`scramble obfuscate`参数对OpenVPN流量进行混淆，使其看起来像普通网络流量。
6. **多服务器支持**：客户端配置中添加`remote-random`和`resolv-retry infinite`参数，提高连接成功率。

这些优化措施大大提高了OpenVPN在中国网络环境下的稳定性和连接成功率。

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
sudo /etc/openvpn/make_client_config.sh client2 [输出目录] [输出文件名] [是否为移动设备(true/false)]
```

例如，为移动设备生成配置：
```bash
sudo /etc/openvpn/make_client_config.sh mobile-client /home/user/configs mobile-config.ovpn true
```

脚本会自动检查客户端证书和密钥是否存在，如果不存在，会提示您先生成证书和密钥。

## 移动设备支持

为了支持移动设备连接，脚本提供了 `--mobile-device` 选项，用于生成适用于移动设备的配置文件。移动设备配置会避免使用某些不兼容的指令，特别是 `fragment` 指令，这在某些移动客户端上可能导致连接错误。

使用以下命令为移动设备生成配置：

```bash
sudo ./install.sh --mobile-device --client mobile-client
```

或者在已安装的系统上：

```bash
sudo ./install.sh
```

然后选择选项 "1) 生成新的客户端配置文件"，按照提示输入客户端名称和配置文件名称，并在询问时选择生成移动设备配置。

移动设备配置的主要区别：
1. 移除了 `fragment` 指令，避免出现 "ERR_INVALID_OPTION_VAL: option error: sorry, 'fragment' directive is not supported" 错误
2. 保留了其他优化设置，如 `mssfix`、`remote-random` 等，以提高在受限网络环境下的连接成功率

这些优化使得移动设备能够更可靠地连接到 OpenVPN 服务器，特别是在中国等网络环境受限的地区。

## 已安装系统的菜单选项

当您在已安装 OpenVPN 的系统上运行脚本时，将显示以下菜单选项：

1. **生成新的客户端配置文件**：为新客户端创建证书和配置文件，无需重新安装整个系统。您可以指定客户端名称、输出目录和文件名。

2. **更新客户端ta.key**：当服务器ta.key更新后，使用此选项更新客户端配置文件，解决客户端与服务器ta.key不匹配问题。
   - 可以选择更新单个客户端或所有客户端
   - 自动生成包含新ta.key的客户端配置文件
   - 提供明确的指导，确保用户知道如何分发更新后的配置文件

3. **诊断连接问题**：诊断并自动修复常见的OpenVPN连接问题，包括：
   - 检查并安装OpenVPN（如果未安装）
   - 检查并启动OpenVPN服务（如果未运行）
   - 检查并修复服务配置问题
   - 检查并生成ta.key（如果不存在）
   - 检查并修复文件权限
   - 检查并添加防火墙规则（如果缺失）
   - 检查并启用IP转发（如果未启用）
   - 检查并添加NAT规则（如果缺失）
   - 检查并修复日志文件配置
   - 分析日志文件中的错误并自动修复
   - 重启服务以应用所有更改
   - 提供清晰的诊断结果和解决建议

4. **修复当前安装**：修复常见的 OpenVPN 安装问题，包括：
   - 修复文件权限
   - 确保 IP 转发已启用
   - 检查并修复防火墙规则
   - 重新启动服务

5. **重启 OpenVPN 服务**：重新启动 OpenVPN 服务，适用于配置更改后或服务异常时。

6. **查看服务器信息**：显示 OpenVPN 服务器的详细信息，包括：
   - 服务状态和运行时间
   - 服务器 IP 地址
   - 配置信息（协议、端口、子网、加密算法等）
   - 防火墙状态
   - 当前连接的客户端数量
   - 系统信息（操作系统、内核版本、OpenVPN 版本）

7. **查看 VPN 实时状态**：实时监控 VPN 连接状态，包括：
   - 已连接的客户端列表
   - 客户端详细信息（名称、远程 IP、虚拟 IP、连接时间）
   - 客户端流量统计（接收和发送的数据量）
   - 系统负载和网络接口统计
   - OpenVPN 进程信息

8. **完全卸载 OpenVPN**：完全删除 OpenVPN 及其所有相关文件和配置，包括：
   - 删除 OpenVPN 软件包和依赖
   - 删除所有配置文件、证书和密钥
   - 删除所有客户端配置文件
   - 删除所有日志文件和运行时文件
   - 移除所有网络接口上的防火墙规则
   - 移除 UFW 和 firewalld 中的所有相关规则
   - 删除系统服务文件
   - 移除 IP 转发设置
   - 移除网络接口脚本
   - 清理所有残留的 TUN/TAP 设备
   - 删除所有备份文件和临时文件

9. **退出**：退出脚本，不执行任何操作。

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
6. **客户端连接成功但无法访问互联网**: 这通常是由于网络配置问题导致的，可能的原因包括：
   - IP转发未正确启用
   - NAT规则未正确配置
   - 使用了错误的网络接口
   - 多网卡环境下配置不完整

   脚本现在包含增强的网络检测和配置功能，会自动：
   - 使用多种方法检测正确的网络接口
   - 验证检测到的接口是否有互联网连接
   - 在多网卡环境中为所有接口配置NAT规则
   - 如果主接口无法访问互联网，自动查找并配置可用的备选接口

   如果仍然遇到问题，可以尝试以下命令手动修复：
   ```bash
   # 检查IP转发是否启用
   sysctl net.ipv4.ip_forward

   # 如果未启用，执行以下命令
   echo 1 > /proc/sys/net/ipv4/ip_forward
   sysctl -w net.ipv4.ip_forward=1
   echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
   sysctl -p

   # 查看所有网络接口
   ip -o -4 addr show

   # 为每个可能的出口接口添加NAT规则（替换INTERFACE为实际接口名称）
   iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o INTERFACE -j MASQUERADE
   iptables -A FORWARD -i tun+ -o INTERFACE -j ACCEPT
   iptables -A FORWARD -i INTERFACE -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

   # 保存iptables规则
   iptables-save > /etc/iptables/rules.v4  # Debian/Ubuntu
   service iptables save  # CentOS

   # 重启OpenVPN服务
   systemctl restart openvpn@server
   ```

## 安全提示

- 定期更新系统和 OpenVPN 软件
- 使用强密码和证书
- 考虑启用双因素认证
- 定期轮换证书
- 监控 OpenVPN 日志

## 压缩和加密配置

为了解决OpenVPN的警告信息并提高安全性，脚本对压缩和加密配置进行了以下更新：

1. **压缩配置**：添加了`allow-compression yes`选项，确保压缩功能正常工作，避免出现"Compression for receiving enabled"警告。

2. **加密配置**：添加了`data-ciphers`选项，指定支持的加密算法列表：
   ```
   data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC
   ```
   这解决了"--cipher set to 'AES-256-CBC' but missing in --data-ciphers"警告，并确保兼容性和安全性。

这些配置更新确保了OpenVPN在最新版本中能够正常工作，没有警告信息，同时保持了良好的兼容性和安全性。

## 版本历史

### 版本 1.13 (2025-05-25)

- 增强卸载功能，确保完全清理所有OpenVPN相关文件和配置：
  - 改进卸载过程，确保删除所有OpenVPN相关文件和配置
  - 增强防火墙规则清理，移除所有网络接口上的相关规则
  - 添加系统服务文件和网络接口脚本的清理
  - 添加IP转发设置的恢复
  - 添加客户端配置文件的清理
  - 添加运行时文件和TUN/TAP设备的清理
  - 添加备份文件和临时文件的清理
  - 更新文档以反映增强的卸载功能

### 版本 1.12 (2025-05-23)

- 增强ta.key文件处理和连接可靠性：
  - 改进ta.key文件验证和生成流程，防止自动重新生成导致的连接问题
  - 添加"更新客户端ta.key"功能，解决客户端与服务器ta.key不匹配问题
  - 添加连接问题诊断功能，帮助识别和解决ta.key不匹配等连接问题
  - 优化连接流程，提高连接成功率
  - 添加ta.key更新提示，确保用户知道何时需要更新客户端配置

### 版本 1.11 (2025-05-22)

- 跳过OpenVPN配置文件验证，忽略压缩和ta.key相关警告
- 简化服务启动流程，提高稳定性

### 版本 1.10 (2025-05-22)

- 修复配置文件验证失败问题：
  - 添加`topology subnet`选项，解决拓扑警告
  - 增强ta.key文件处理，自动检测并重新生成
  - 改进配置验证功能，提高稳定性
  - 解决"Cannot pre-load keyfile (ta.key)"错误

### 版本 1.9 (2025-05-22)

- 提高与OpenVPN 2.6.12版本的兼容性：
  - 移除不再支持的`ncp-disable`选项
  - 更新文档中的相关描述
  - 确保服务器和客户端配置的一致性

### 版本 1.8 (2025-05-22)

- 增强脚本的错误处理和诊断能力：
  - 添加配置文件验证功能，在启动服务前检查配置有效性
  - 添加详细的错误日志记录，便于诊断问题
  - 自动检测并修复常见配置问题
- 提高兼容性：
  - 添加OpenVPN版本检测功能
  - 根据OpenVPN版本自动调整配置选项
  - 智能处理不同版本对scramble选项的支持情况
- 优化服务启动流程：
  - 添加服务启动前的配置验证步骤
  - 提供更详细的服务启动错误信息
  - 自动修复文件权限和用户/组设置问题
- 改进客户端配置生成：
  - 确保客户端和服务器配置的一致性
  - 根据服务器配置自动调整客户端选项
- 更新文档以反映新功能和修复

### 版本 1.7 (2025-05-20)

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
- 添加躲避中国运营商封锁的优化措施
- 更新压缩和加密配置，解决警告信息
- 移除TCP选项，默认只使用UDP协议
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
