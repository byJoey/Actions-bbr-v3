# ✨BBR 管理脚本✨  

一个为 Debian/Ubuntu 用户设计的，简单、高效且功能丰富的 BBR 管理脚本。

无论是想一键安装最新的 **BBR v3** 内核，还是在不同的网络加速方案之间灵活切换，本脚本都能帮你轻松搞定。

> **我们致力于提供优雅的界面和流畅的操作，让内核管理不再是件头疼事。**

---

### 🎯 **目标用户与支持环境**

在运行脚本前，请确保你的设备符合以下要求：

| 项目 | 要求 |
| :--- | :--- |
| **支持架构** | `x86_64` / `aarch64` |
| **支持系统** | Debian 10+ / Ubuntu 18.04+ |
| **目标设备** | **云服务器 (VPS/Cloud Server)** 或 **独立服务器** |
| **引导方式** | 使用标准 `GRUB` 引导加载程序 |

> ⚠️ **重要说明**
> 本脚本**不适用**于大多数单板计算机（SBC），例如**树莓派 (Raspberry Pi)、NanoPi** 等。这些设备通常使用 U-Boot 等非 GRUB 引导方式，脚本会执行失败。

---

---

### 🌟 功能列表  

👑 **一键安装 BBR v3 内核**  
🍰 **切换加速模式（BBR+FQ、BBR+CAKE 等）**  
⚙️ **开启/关闭 BBR 加速**  
🗑️ **卸载内核，告别不需要的内核版本**  
👀 **实时查看当前 TCP 拥塞算法和队列算法**  
🛡️ **默认启用 CVE-2026-31431 缓解（禁用 `algif_aead`）**  
🛡️ **默认启用 Dirty Frag 缓解（屏蔽 `esp4/esp6/rxrpc`）**  
🎨 **美化的输出界面，让脚本更有灵魂**  

---

### 🚀 如何使用？

1. **一键运行**  
   ```bash
   bash <(curl -l -s https://raw.githubusercontent.com/byJoey/Actions-bbr-v3/refs/heads/main/install.sh)
   ```

2. **运行 CVE-2026-31431 风险面检测脚本（仅检测，不利用）**  
   ```bash
   command -v python3 >/dev/null 2>&1 || (sudo apt update && sudo apt install -y python3)
   curl -fsSL -o cve_2026_31431_detector.py https://raw.githubusercontent.com/byJoey/Actions-bbr-v3/main/cve_2026_31431_detector.py
   chmod +x cve_2026_31431_detector.py
   sudo python3 cve_2026_31431_detector.py
   ```

   输出说明：
   - `检测到高风险暴露面`：风险面暴露，建议立即升级并收敛配置
   - `风险面已收敛/已缓解`：当前风险面已收敛
   - `结果不确定`：信息不足，需继续核查内核补丁级别

---

### 🌟 操作界面  

每次运行脚本，你都会进入一个活泼又实用的选项界面：

```bash
╭( ･ㅂ･)و ✧ 你可以选择以下操作哦：
  1. 🛠️  安装 BBR v3
  2. 🔍 检查是否为 BBR v3
  3. ⚡ 使用 BBR + FQ 加速
  4. ⚡ 使用 BBR + FQ_PIE 加速
  5. ⚡ 使用 BBR + CAKE 加速
  6. 🔧 开启或关闭 BBR
  7. 🗑️  卸载
```

> **小提示：** 如果选错了也没关系，脚本会乖乖告诉你该怎么办！  

---

### 🌟 常见问题  

**Q: 为什么下载失败啦？**  
A: 有可能是 GitHub 链接过期了，来群里吐槽一下吧！  

**Q: 提示 GitHub API rate limit exceeded 怎么办？**  
A: 先设置 `GITHUB_TOKEN` 后再运行脚本，例如：`export GITHUB_TOKEN=你的令牌`。  

**Q: 我不是 BBR 专家，不知道选哪个加速方案？**  
A: 放心，BBR + FQ 是最常见的方案，适用于大多数场景～  

**Q: 如果不小心把系统搞崩了怎么办？**  
A: 别慌！记得备份你的内核，或者到 [Joey's Blog](https://joeyblog.net) 查看修复教程。

**Q: CVE-2026-31431 怎么处理？**  
A: 新版脚本会自动写入 `algif_aead` 黑名单并在构建流程中关闭 `CONFIG_CRYPTO_USER_API_AEAD`，避免暴露该漏洞利用面。  

**Q: daed/dae 报 no BTF found 怎么办？**  
A: 新构建流程已强制开启 `CONFIG_DEBUG_INFO_BTF`，升级到最新 release 并重启即可。  

**Q: Dirty Frag 怎么处理？**  
A: 新版构建会关闭 `XFRM_ESP/INET_ESP/INET6_ESP/AF_RXRPC`，脚本运行时会写入 `esp4/esp6/rxrpc` 黑名单并尝试卸载模块。  

---

### 🌈 作者信息  

**Joey**  
📖 博客：[JoeyBlog](https://joeyblog.net)  
💬 群组：[Telegram Feedback Group](https://t.me/+ft-zI76oovgwNmRh)

---

### ❤️ 开源协议  

欢迎使用、修改和传播这个脚本！如果你觉得它对你有帮助，记得来点个 Star ⭐ 哦～  

> 💡 **免责声明：** 本脚本由作者热爱 Linux 的灵魂驱动编写，虽尽力确保安全，但任何使用问题请自负风险！
### 🌟 特别鸣谢  
感谢 [Naochen2799/Latest-Kernel-BBR3](https://github.com/Naochen2799/Latest-Kernel-BBR3) 项目提供的技术支持与灵感参考。  
## 💡 赞助声明

本项目由 [VTEXS](https://console.vtexs.com/?affid=1513) 的「开源项目免费 VPS 计划」提供算力支持。  
感谢 VTEXS 对开源社区的支持！


🎉 **快来体验不一样的 BBR 管理工具吧！** 🎉  
## Star History

<a href="https://star-history.com/#byJoey/Actions-bbr-v3&Timeline">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=byJoey/Actions-bbr-v3&type=Timeline&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=byJoey/Actions-bbr-v3&type=Timeline" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=byJoey/Actions-bbr-v3&type=Timeline" />
 </picture>
</a>
