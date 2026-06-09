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
8. 卸载 BBR 内核
```

常用流程：

1. 选择 `1` 安装或更新 BBRv3 内核。
2. 按提示重启系统。
3. 重新运行脚本，选择 `3` 检查 BBRv3 状态。
4. 按需选择 `4` 到 `7` 设置队列算法。

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
- CVE-2026-31431 缓解是否写入。
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

## 安全缓解

脚本启动时会写入安全缓解规则：

```text
/etc/modprobe.d/99-joeyblog-security.conf
```

包含：

- `algif_aead` 黑名单，用于收敛 CVE-2026-31431 风险面。
- `esp4` / `esp6` / `rxrpc` 黑名单，用于收敛 Dirty Frag 相关风险面。

如果模块当前已加载，脚本会尝试卸载；如果模块被占用，则黑名单会在重启后生效。

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
- 强制默认启用 BBR。
- 关闭 debug info。
- 拒绝发布 `*-dbg*.deb`。

构建不会自动更新 BBR patch 本身。

## 卸载

运行脚本后选择：

```text
8. 卸载 BBR 内核
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
