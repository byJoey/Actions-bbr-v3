# BBRv3 管理脚本

一个用于 Debian/Ubuntu VPS 的 BBRv3 内核安装与网络加速管理脚本。

脚本入口：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/byJoey/Actions-bbr-v3/main/install.sh)
```

脚本会自动识别当前系统架构，从本仓库 GitHub Releases 下载匹配的 BBRv3 内核 `.deb` 包，并提供安装、指定版本安装、状态检查、加速模式切换和卸载功能。

## 支持环境

| 项目 | 要求 |
| --- | --- |
| 系统 | Debian / Ubuntu |
| 包管理器 | `apt-get` |
| 架构 | `x86_64` / `aarch64` |
| 引导方式 | 建议使用 GRUB |
| 使用场景 | VPS / 云服务器 / 独立服务器 |

不建议在树莓派、NanoPi 等依赖 U-Boot 或厂商定制内核链路的设备上使用。此类设备的内核安装和启动流程通常与通用 Debian/Ubuntu VPS 不一致。

## 菜单功能

运行脚本后会进入交互菜单：

```text
1. 安装或更新 BBR v3 最新版
2. 指定版本安装
3. 检查 BBR v3 状态
4. 启用 BBR + FQ
5. 启用 BBR + FQ_CODEL
6. 启用 BBR + FQ_PIE
7. 启用 BBR + CAKE
8. 亚太机器 TCP 调优
9. 卸载 BBR 内核
10. BBR v3 智能带宽优化
11. 清空网络优化配置
```

常用流程：

1. 选择 `1` 安装或更新 BBRv3 内核。
2. 按提示重启系统。
3. 重新运行脚本，选择 `3` 检查 BBRv3 状态。
4. 按需选择 `4` 到 `7` 设置队列算法。
5. 亚太线路机器可选择 `8` 写入 TCP 收发窗口与空闲慢启动调优。
6. 不确定线路参数时可选择 `10` 自动测速并按带宽档位计算 TCP 缓冲区。
7. 需要撤回调优时可选择 `11` 清空脚本写入的网络优化配置。

## 内核与 BBR 策略

本项目的构建目标是：

```text
BBRv3 补丁固定，内核自动跟随 kernel.org 最新 stable 更新。
```

也就是说，BBR 实现不会在自动构建时偷偷更新；自动更新的是 Linux stable 内核版本。构建流程会把仓库内固定的 BBRv3 patch 应用到最新 stable 内核上。

当前 patch 选择规则：

```text
linux-7.0.y -> patches/bbrv3-linux-7.0.patch
linux-7.1.y -> patches/bbrv3-linux-7.1.patch
```

同一个主线系列内的小版本更新会自动复用同一个 patch，例如 `7.0.11 -> 7.0.12`。如果内核跳到新的主线系列但仓库内还没有对应 patch，构建会直接失败，避免产出不可验证的内核包。

## 安装最新版

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/byJoey/Actions-bbr-v3/main/install.sh)
```

选择：

```text
1. 安装或更新 BBR v3 最新版
```

脚本会：

- 检查系统是否为 Debian/Ubuntu。
- 检查架构是否为 `x86_64` 或 `aarch64`。
- 从 GitHub Releases 获取当前架构最新版本。
- 下载非 debug 的内核 `.deb` 包。
- 安装新内核并更新引导配置。
- 提示是否重启。

如果遇到 GitHub API rate limit，可先设置 token：

```bash
export GITHUB_TOKEN=你的 GitHub Token
bash <(curl -fsSL https://raw.githubusercontent.com/byJoey/Actions-bbr-v3/main/install.sh)
```

## 指定版本安装

运行脚本后选择：

```text
2. 指定版本安装
```

脚本会列出当前架构可用的 release tag，并按编号安装指定版本。

release tag 格式：

```text
x86_64-7.0.11
arm64-7.0.11
```

## 检查 BBRv3 状态

运行脚本后选择：

```text
3. 检查 BBR v3 状态
```

脚本会检查：

- `tcp_bbr` 模块版本是否为 `3`。
- 当前 TCP 拥塞控制算法是否为 `bbr`。
- Dirty Frag 相关模块黑名单是否写入。

也可以手动检查：

```bash
uname -r
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.default_qdisc
modinfo tcp_bbr 2>/dev/null | grep '^version:'
```

## 加速模式

脚本支持以下组合：

| 菜单 | 拥塞控制 | 队列算法 |
| --- | --- | --- |
| 4 | `bbr` | `fq` |
| 5 | `bbr` | `fq_codel` |
| 6 | `bbr` | `fq_pie` |
| 7 | `bbr` | `cake` |

选择后脚本会立即尝试应用配置，并询问是否永久写入：

```text
/etc/sysctl.d/99-joeyblog.conf
```

对于需要模块加载的队列算法，脚本会尝试加载对应 `sch_*` 模块，并在需要时写入：

```text
/etc/modules-load.d/joeyblog-qdisc.conf
```

## 亚太机器 TCP 调优

运行脚本后选择：

```text
8. 亚太机器 TCP 调优
```

脚本会立即应用并永久写入以下配置：

```text
net.ipv4.tcp_wmem = 4096 16384 12582912
net.ipv4.tcp_rmem = 4096 131072 33554432
net.ipv4.tcp_limit_output_bytes = 4194304
net.ipv4.tcp_slow_start_after_idle = 0
```

配置文件路径：

```text
/etc/sysctl.d/99-joeyblog.conf
```

## BBR v3 智能带宽优化

运行脚本后选择：

```text
10. BBR v3 智能带宽优化
```

脚本会优先安装并运行 Ookla 官方 `speedtest`，要求用户在中国移动、中国联通、中国电信中选择一个运营商，然后优先尝试中国境内最近的匹配测速节点并获取上传带宽、下载带宽和 Ping；如果找不到匹配节点，会降级为香港节点，最后才使用 Ookla 自动选择。测速失败时会提示手动输入上传带宽。

优化逻辑：

- 自动启用 `bbr` 拥塞控制和 `fq` 队列算法。
- 测速节点优先选择中国境内节点，并要求用户选择三大运营商之一。
- 根据上传带宽和地区模式映射推荐 TCP buffer 档位。
- 亚太线路使用较保守的 buffer，美欧高延迟线路使用更大 buffer。
- 按机器内存设置 TCP buffer 上限，避免小内存 VPS 过度放大缓冲区。
- 同步写入 `net.core.rmem_max` / `net.core.wmem_max` / `tcp_rmem` / `tcp_wmem`。
- 保留 `tcp_limit_output_bytes = 4194304` 和 `tcp_slow_start_after_idle = 0`。

地区模式参考：

| 模式 | RTT 参考 |
| --- | --- |
| 自动判断 | 使用 Speedtest Ping 自动分类 |
| 亚太线路 | 通常小于 `100ms` |
| 美欧线路 | 通常 `150-300ms` |
| 手动 RTT | 按用户输入计算 |

配置同样写入：

```text
/etc/sysctl.d/99-joeyblog.conf
```

## 清空网络优化配置

运行脚本后选择：

```text
11. 清空网络优化配置
```

脚本会清理本项目写入的网络优化持久配置：

- `net.core.default_qdisc`
- `net.ipv4.tcp_congestion_control`
- `net.core.rmem_max` / `net.core.wmem_max`
- `net.ipv4.tcp_rmem` / `net.ipv4.tcp_wmem`
- `net.ipv4.tcp_limit_output_bytes`
- `net.ipv4.tcp_slow_start_after_idle`

同时删除：

```text
/etc/modules-load.d/joeyblog-qdisc.conf
```

该功能只清空网络优化配置，不卸载 BBR 内核，也不移除 Dirty Frag 安全缓解规则。当前运行态参数可能需要重启后完全恢复为系统默认值。

## 安全缓解

脚本启动时会写入 Dirty Frag 风险面收敛规则：

```text
/etc/modprobe.d/99-joeyblog-security.conf
```

包含：

- `esp4` / `esp6` / `rxrpc` 黑名单，用于收敛 Dirty Frag 相关风险面。

如果模块当前已加载，脚本会尝试卸载；如果模块被占用，则黑名单会在重启后生效。

CVE-2026-31431 对应的 AEAD userspace 接口在新构建内核中由内核配置侧收敛：

```text
# CONFIG_CRYPTO_USER_API_AEAD is not set
```

因此安装脚本不再额外写入 `algif_aead` 黑名单。
如果旧版本脚本已经写入过该黑名单，新脚本只会在当前运行内核确认关闭 `CONFIG_CRYPTO_USER_API_AEAD` 后移除它。

## CVE-2026-31431 检测

仅检测，不利用：

```bash
command -v python3 >/dev/null 2>&1 || (sudo apt update && sudo apt install -y python3)
curl -fsSL -o cve_2026_31431_detector.py https://raw.githubusercontent.com/byJoey/Actions-bbr-v3/main/cve_2026_31431_detector.py
chmod +x cve_2026_31431_detector.py
sudo python3 cve_2026_31431_detector.py
```

## 内核包来源

`.deb` 内核包由 GitHub Actions 构建并发布到本仓库 Releases。

构建流程会：

- 读取 kernel.org 最新 stable 版本。
- 下载 `gregkh/linux` 对应 stable 分支。
- 应用仓库内固定 BBRv3 patch。
- 强制默认启用 BBR 和 fq。
- 关闭 debug info。
- 拒绝发布 `*-dbg*.deb` / `*-dbgsym*.deb`。

构建不会自动更新 BBR patch 本身。

## 卸载

运行脚本后选择：

```text
9. 卸载 BBR 内核
```

脚本会卸载由本项目安装的 `joeyblog` 内核包，并更新引导配置。卸载后建议重启。

## 反馈

博客：

[JoeyBlog](https://joeyblog.net)

反馈群组：

[Telegram Feedback Group](https://t.me/+ft-zI76oovgwNmRh)

## 免责声明

内核升级有风险。安装前建议确认 VPS 控制台、救援模式或旧内核启动项可用。使用本项目构建或安装的内核造成的系统启动失败、网络异常或数据损失，由使用者自行承担。

## Star History

<a href="https://star-history.com/#byJoey/Actions-bbr-v3&Timeline">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=byJoey/Actions-bbr-v3&type=Timeline&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=byJoey/Actions-bbr-v3&type=Timeline" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=byJoey/Actions-bbr-v3&type=Timeline" />
 </picture>
</a>
