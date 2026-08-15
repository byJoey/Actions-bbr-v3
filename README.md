# BBRv3 管理脚本

一个用于 Debian/Ubuntu VPS 的 BBRv3 内核安装与网络加速管理脚本。

脚本入口：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/byJoey/Actions-bbr-v3/main/install.sh)
```

首次运行后脚本会自动安装联网快捷命令，后续可直接运行：

```bash
b
```

快捷命令每次都会从 GitHub 拉取最新版脚本执行，不使用本地缓存脚本。

脚本会自动识别当前系统架构，从本仓库 GitHub Releases 下载匹配的 BBRv3 内核 `.deb` 包，并提供安装、指定版本安装、状态检查、加速模式切换和卸载功能。安装内核时可选择标准 BBRv3 或 BBRv3 Max 激进吞吐内核。

## 支持环境

| 项目 | 要求 |
| --- | --- |
| 最低支持系统 | Ubuntu 24.04+ / Debian 12+ |
| 推荐系统 | Ubuntu 24.04+ / Debian 12+ |
| 包管理器 | `apt-get` |
| 架构 | `x86_64` / `aarch64` |
| 引导方式 | 建议使用 GRUB |
| 使用场景 | VPS / 云服务器 / 独立服务器 |

不建议在树莓派、NanoPi 等依赖 U-Boot 或厂商定制内核链路的设备上使用。此类设备的内核安装和启动流程通常与通用 Debian/Ubuntu VPS 不一致。

Debian testing/unstable 如果缺少 `VERSION_ID`，脚本会按 `VERSION_CODENAME` 识别 `bookworm`、`trixie`、`forky` 和 `sid`。Alpine Linux 暂不支持安装本项目内核包，因为当前 release 产物是 `.deb`，安装和引导流程依赖 Debian/Ubuntu 的包管理与内核安装链路。

本项目当前内核主线为 Linux 7.x。安装内核时脚本会按最低支持系统拦截过旧环境，避免因用户态、initramfs 或引导链路过旧导致启动失败或 kernel panic。推荐系统是更稳妥的部署选择；旧系统仍可使用状态检查、网络调优、清空优化和卸载功能。

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
12. BBR v3 疯批模式（极限测速挑战）
```

常用流程：

1. 选择 `1` 安装或更新 BBRv3 内核，并按提示选择标准版或 Max 极限版。
2. 按提示重启系统。
3. 重新运行脚本，选择 `3` 检查 BBRv3 状态。
4. 按需选择 `4` 到 `7` 设置队列算法。
5. 亚太线路机器可选择 `8` 写入 TCP 收发窗口与空闲慢启动调优。
6. 不确定线路参数时可选择 `10` 自动测速并按带宽档位计算 TCP 缓冲区。
7. 做自有链路极限测速挑战时可选择 `12` 写入激进冲速率参数。
8. 需要撤回调优时可选择 `11` 清空脚本写入的网络优化配置。

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

首次运行后也可以直接输入：

```bash
b
```

该命令会联网拉取最新版脚本后运行。

选择：

```text
1. 安装或更新 BBR v3 最新版
```

脚本会：

- 检查系统是否为 Debian/Ubuntu。
- 检查架构是否为 `x86_64` 或 `aarch64`。
- 让用户选择标准 BBRv3 或 BBRv3 Max 激进吞吐内核。
- 从 GitHub Releases 获取当前架构和内核类型匹配的最新版本。
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

脚本会先让用户选择标准 BBRv3 或 BBRv3 Max，再列出当前架构可用的 release tag，并按编号安装指定版本。

release tag 格式：

```text
x86_64-7.0.11
arm64-7.0.11
x86_64-7.0.11-max
arm64-7.0.11-max
```

其中不带 `-max` 的 tag 是标准 BBRv3 内核，带 `-max` 的 tag 是 BBRv3 Max 激进吞吐内核。Max 版会提高 Startup、ProbeBW 和 cwnd 策略的进攻性，但保留 BBRv3 的 loss、ECN、inflight 和 ProbeBW 反馈闭环，只适合自有链路吞吐测试，不建议日常生产使用。

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

脚本不仅会写入 `net.core.default_qdisc`，还会尝试把当前默认路由出口网卡的 root qdisc 立即替换为所选算法，避免只对新建队列生效、当前网卡实际仍保持旧队列。

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

脚本会优先安装并运行 Ookla 官方 `speedtest 1.2.0`，自动尝试附近测速服务器并获取上传/下载带宽；如果检测到 Python 版 `speedtest-cli`，会先自动移除并安装需要的 Ookla 官方版本。测速失败时会提示手动输入上传带宽。Speedtest 的测速节点延迟会被隐藏，不展示也不参与 RTT 计算，避免把测速节点延迟误当作真实业务线路延迟。

优化逻辑：

- 自动启用 `bbr` 拥塞控制和 `fq` 队列算法。
- 根据上传带宽和地区模式映射推荐 TCP buffer 档位。
- RTT 必须由用户手动输入，应填写真实链接延迟，使用 v2rayN 测出来的结果即可；不使用 Speedtest 测出来的 Ping。
- 用户手动选择亚太、美欧或手动 RTT + buffer 档位，不再按测速 RTT 自动判断。
- 亚太线路使用较保守的 buffer，美欧高延迟线路使用更大 buffer。
- 按机器内存设置 TCP buffer 上限，避免小内存 VPS 过度放大缓冲区。
- 同步写入 `net.core.rmem_max` / `net.core.wmem_max` / `tcp_rmem` / `tcp_wmem`。
- 保留 `tcp_limit_output_bytes = 4194304` 和 `tcp_slow_start_after_idle = 0`。

地区模式参考：

| 模式 | RTT 参考 |
| --- | --- |
| 亚太线路 | 通常小于 `100ms` |
| 美欧线路 | 通常 `150-300ms` |
| 手动 RTT | 按用户输入 RTT，并手动选择亚太或美欧 buffer 档位 |

配置同样写入：

```text
/etc/sysctl.d/99-joeyblog.conf
```

## BBR v3 疯批模式

运行脚本后选择：

```text
12. BBR v3 疯批模式（极限测速挑战）
```

该模式只面向自有链路的极限测速挑战，不建议日常使用。目标是尽量压榨单向吞吐和跑满带宽上限，会主动牺牲重传率、延迟抖动、排队延迟、连接稳定性、交互体验和流量公平性。

脚本会强制启用 `bbr` 拥塞控制和 `fq` 队列算法，并立即尝试替换当前默认路由出口网卡的 root qdisc。

写入参数：

```text
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max = 1073741824
net.core.wmem_max = 1073741824
net.core.optmem_max = 1073741824
net.core.netdev_max_backlog = 1000000
net.core.somaxconn = 65535
net.ipv4.tcp_wmem = 4096 1048576 1073741824
net.ipv4.tcp_rmem = 4096 1048576 1073741824
net.ipv4.tcp_limit_output_bytes = 268435456
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 4294967295
net.ipv4.tcp_autocorking = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_ecn = 0
```

脚本还会把当前默认出口网卡的运行态 `txqueuelen` 拉高到 `100000`，让测速时本机发送队列更激进。该项不是 sysctl 参数，不会写入 `/etc/sysctl.d/99-joeyblog.conf`。

其中核心参数应用失败会中止；不同内核可能不支持部分附加参数，脚本会尽量写入，失败的附加项不会阻断整个模式。

## 清空网络优化配置

运行脚本后选择：

```text
11. 清空网络优化配置
```

脚本会清理本项目写入的网络优化持久配置：

- `net.core.default_qdisc`
- `net.ipv4.tcp_congestion_control`
- `net.core.rmem_max` / `net.core.wmem_max` / `net.core.optmem_max`
- `net.core.netdev_max_backlog` / `net.core.somaxconn`
- `net.ipv4.tcp_rmem` / `net.ipv4.tcp_wmem`
- `net.ipv4.tcp_limit_output_bytes`
- `net.ipv4.tcp_slow_start_after_idle`
- `net.ipv4.tcp_notsent_lowat`
- `net.ipv4.tcp_autocorking`
- `net.ipv4.tcp_no_metrics_save`
- `net.ipv4.tcp_mtu_probing`
- `net.ipv4.tcp_fastopen`
- `net.ipv4.tcp_window_scaling`
- `net.ipv4.tcp_moderate_rcvbuf`
- `net.ipv4.tcp_ecn`

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

<a href="https://star-history.dera.page/#byJoey/Actions-bbr-v3&Timeline">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://star-history.dera.page/svg?repos=byJoey/Actions-bbr-v3&type=Timeline&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://star-history.dera.page/svg?repos=byJoey/Actions-bbr-v3&type=Timeline" />
   <img alt="Star History Chart" src="https://star-history.dera.page/svg?repos=byJoey/Actions-bbr-v3&type=Timeline" />
 </picture>
</a>
