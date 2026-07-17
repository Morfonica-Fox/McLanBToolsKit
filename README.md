# Minecraft LanB Tools Kit

基于 Python 的 Minecraft 局域网广播（LAN Broadcast）工具包，包含**防火墙**和**广播器**两大组件。

## 组件概览

| 组件 | 入口文件 | 功能 |
|---|---|---|
| LanBroadcast Firewall | `mc_lanb_firewall.py` | 内核级 UDP 广播包拦截，速率限制，防刷屏攻击 |
| LanBroadcaster | `mc_server_udp_broadcast.py` | 多服务器 UDP 组播广播，动态 MOTD，热重载配置 |

## 防火墙

基于 WinDivert 驱动在内核层拦截 Minecraft 局域网广播包（UDP 224.0.2.60:4445），对每个服务器和每个 IP 独立统计包速率，超阈值自动丢弃。
支持完全的用户自定义，至少比任何规则式防火墙更加自由。

### 核心特性

- **双维度速率限制**：同时追踪 Per-Server 和 Per-IP 的 PP1.5s / PPM，任一超限即拦截
- **Bisect 滑动窗口**：基于 `bisect` + `deque` 的 O(log n) 时间序列计数器，精确到毫秒
- **代码热重载**：保存 `mc_lanb_cond.py` 后自动重载处理逻辑和依赖，无需重启进程
- **MOTD 样式解析**：完整支持 Minecraft 颜色代码（§0~§f）、格式代码（§l/§o/§n/§m）、Bedrock 扩展色（§g~§w）和真彩色（§x） (Note: 默认全真彩色ANSI输出 所以不受控制台调整颜色主题影响)
- **双终端模式**：自动检测 `rich` 库并切换 Rich 渲染 / ANSI 转义序列输出
- **自动提权**：通过 `elevate` 自动请求管理员权限
- **Forge 兼容**：自动修正目标地址为 255.255.255.255，修复 (Neo)Forge 客户端收不到广播包的问题
- **组播保活**：自动加入组播组，确保局域网内客户端能发现服务器，修复无客户端主动加入组播组时 部分os默认丢弃组播包的问题

### 控制台输出示例

```
0000-01-01 00:00:00   3   12   1   4  192.168.1.100  ▶  224.0.2.60   25565  utf-8 [Block ✘] §6My Minecraft Server
```

字段依次为：时间戳 → 服务器 PP1.5s → 服务器 PPM → IP PP1.5s → IP PPM → 源 IP → 目标 IP → 端口 → 编码 → 放行/拦截 → MOTD（已解析样式）
(还是可以自己改)

### 依赖

| 包 | 版本要求 | 说明 |
|---|---|---|
| Python | ≥ 3.7 | PyPy 3.11 兼容且推荐 |
| pydivert | ≥ 2.1.0 | WinDivert Python 绑定 |
| charset-normalizer | ≥ 2.0.0 | 自动字符集检测 |
| watchdog | ≥ 6.0.0 | 文件变更监控（热重载） |
| elevate | * | 自动管理员提权 |

### 已知稳定环境

**环境 A（推荐）**
- PyPy 3.11 + pydivert 2.1.0 + charset-normalizer 3.4.7 + watchdog 6.0.0

**环境 B**
- CPython 3.11 + pydivert 3.1.2 + charset-normalizer 3.4.7 + watchdog 6.0.0

### 自定义拦截规则

编辑 `mc_lanb_cond.py`，修改 `handler()` 函数中的阈值：

```python
max_per_1dot5_sec = 5      # 单服务器每 1.5 秒最大包数
max_per_min = 84            # 单服务器每分钟最大包数
ip_max_per_1dot5_sec = max_per_1dot5_sec * 8
ip_max_per_min = max_per_min * 8
```

保存文件后自动热重载，无需重启。

(如果需要 你也可以写任何你想写的python代码进行拦截 但是不建议太复杂/石山/阻塞式操作 否则你的CPU/内存占用率会上升很多 并且客户端感受到明显的广播延迟)

## 广播器

向局域网组播地址 `224.0.2.60:4445` 持续发送 Minecraft 服务器广播包，支持多服务器同时广播。

### 特性

- **多服务器并发**：多个服务器配置各自独立线程广播
- **动态 MOTD**：配置文件支持函数式服务器定义，每次发送实时计算 MOTD
- **可调发送间隔**：每个服务器独立配置发送延迟（支持静态值或 callable）
- **配置热重载**：修改 `mc_servers_config.py` 自动重载，无需重启

### 配置示例

编辑 `mc_servers_config.py`：

```python
import random

def demo_server():
    return {
        'motd': f'Demo Server #{random.randint(1, 100)}',
        'port': 25565,
        'send_delay': random.randint(1, 2)
    }

servers = [demo_server]
```

`send_delay` 为 callable 时每次调用取值，可实现动态间隔。
`motd` 为 callable 时每次调用取值，可实现动态 MOTD。 (核心功能)
`port` 为 callable 时每次调用取值，可实现动态端口。 (可实现无后端玩家分流)

## 快速开始

```bash
# 克隆仓库
git clone https://github.com/your-username/McLanBToolsKit.rich.git
cd McLanBToolsKit.rich

# 安装依赖
pip install pydivert charset-normalizer watchdog rich colorama elevate

# 运行防火墙（需管理员权限）
python mc_lanb_firewall.py

# 运行广播器
python mc_server_udp_broadcast.py
```

防火墙首次运行会自动请求管理员权限。

## 项目结构

```
McLanBToolsKit.rich/
├── mc_lanb_firewall.py         # 防火墙入口，WinDivert 抓包 + 热重载调度
├── mc_lanb_cond.py             # 拦截条件模块，速率计数器 + 包处理逻辑
├── mc_lanb_advtools.py         # 工具模块，字符集检测 + 协议解析 + 样式渲染
├── mc_server_udp_broadcast.py  # 广播器入口，组播发送 + 配置热重载
├── mc_servers_config.py        # 广播器服务器配置文件
└── pyproject.toml              # 项目配置（格式化、Lint）
```

## 原理简述

Minecraft 客户端通过 UDP 组播 `224.0.2.60:4445` 发现局域网服务器。防火墙在 IP 层通过 WinDivert 拦截所有目标端口为 4445 的 UDP 包，解析其中的 MOTD 和端口信息，基于滑动窗口速率计数器判断是否放行。广播器反向操作，向同一组播地址定时发送构造好的广播包。

## 贡献

请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解代码格式化规范和提交流程。

## 许可证

[MIT](LICENSE)
