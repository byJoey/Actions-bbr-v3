#!/bin/bash

# 限制脚本仅支持基于 Debian/Ubuntu 的系统
if ! command -v apt-get &> /dev/null; then
    echo -e "\033[31m此脚本仅支持基于 Debian/Ubuntu 的系统，请在支持 apt-get 的系统上运行！\033[0m"
    exit 1
fi

# 在 root 环境且未安装 sudo 时提供兼容包装，避免命令直接失败
if ! command -v sudo &> /dev/null; then
    if [[ "$(id -u)" -eq 0 ]]; then
        sudo() { "$@"; }
    else
        echo -e "\033[31m缺少依赖：sudo。请先安装 sudo 后重试。\033[0m"
        exit 1
    fi
fi

# 检查并安装必要的依赖
REQUIRED_CMDS=("curl" "wget" "dpkg" "awk" "sed" "sysctl" "jq")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "\033[33m缺少依赖：$cmd，正在安装...\033[0m"
        sudo apt-get update && sudo apt-get install -y $cmd > /dev/null 2>&1
    fi
done

# 检测系统架构
ARCH=$(uname -m)
if [[ "$ARCH" != "aarch64" && "$ARCH" != "x86_64" ]]; then
    echo -e "\033[31m(￣□￣)哇！这个脚本只支持 ARM 和 x86_64 架构哦~ 您的系统架构是：$ARCH\033[0m"
    exit 1
fi

# 获取当前 BBR 状态
CURRENT_ALGO=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
CURRENT_QDISC=$(sysctl net.core.default_qdisc | awk '{print $3}')

# sysctl 配置文件路径
SYSCTL_CONF="/etc/sysctl.d/99-joeyblog.conf"
# 模块自动加载配置文件路径
MODULES_CONF="/etc/modules-load.d/joeyblog-qdisc.conf"
# 安全加固配置（缓解 CVE-2026-31431）
SECURITY_MODPROBE_CONF="/etc/modprobe.d/99-joeyblog-security.conf"
# 可选：提升 GitHub API 限额（支持 GITHUB_TOKEN / GH_TOKEN）
GITHUB_API_TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

gh_api_get() {
    local url="$1"
    if [[ -n "$GITHUB_API_TOKEN" ]]; then
        curl -fsSL \
            -H "Authorization: Bearer $GITHUB_API_TOKEN" \
            -H "Accept: application/vnd.github+json" \
            "$url"
    else
        curl -fsSL "$url"
    fi
}

check_release_api_response() {
    local response="$1"
    local api_message=""
    api_message=$(echo "$response" | jq -r 'if type=="object" then .message // "" else "" end')

    if [[ -n "$api_message" ]]; then
        echo -e "\033[31mGitHub API 返回错误：$api_message\033[0m"
        if echo "$api_message" | grep -qi "rate limit exceeded"; then
            echo -e "\033[33m提示：可先执行 export GITHUB_TOKEN=你的令牌，再重新运行脚本。\033[0m"
        fi
        return 1
    fi

    if ! echo "$response" | jq -e 'type=="array"' > /dev/null 2>&1; then
        echo -e "\033[31mGitHub API 返回数据格式异常，无法继续。\033[0m"
        return 1
    fi
}

# 函数：清理 sysctl.d 中的旧配置
clean_sysctl_conf() {
    sudo touch "$SYSCTL_CONF"
    sudo sed -i '/net.core.default_qdisc/d' "$SYSCTL_CONF"
    sudo sed -i '/net.ipv4.tcp_congestion_control/d' "$SYSCTL_CONF"
}

# 函数：加载队列调度模块
load_qdisc_module() {
    local qdisc_name="$1"
    local module_name="sch_$qdisc_name"
    
    # 检查队列算法是否已可用（通过尝试读取当前可用的 qdisc）
    # 如果 sysctl 能成功设置，说明模块已存在
    if sudo sysctl -w net.core.default_qdisc="$qdisc_name" > /dev/null 2>&1; then
        # 恢复原设置
        sudo sysctl -w net.core.default_qdisc="$CURRENT_QDISC" > /dev/null 2>&1
        return 0
    fi
    
    # 检查模块是否已加载
    if lsmod | grep -q "^${module_name//-/_}"; then
        return 0
    fi
    
    # 模块不存在，尝试加载
    echo -e "\033[36m正在加载内核模块 $module_name...\033[0m"
    if sudo modprobe "$module_name" 2>/dev/null; then
        echo -e "\033[1;32m✔ 模块 $module_name 加载成功\033[0m"
        return 0
    else
        echo -e "\033[33m⚠ 模块 $module_name 加载失败，可能内核不支持\033[0m"
        return 1
    fi
}

# 函数：应用 CVE-2026-31431 防护（禁用 algif_aead）
apply_cve_2026_31431_mitigation() {
    local changed=0
    if [[ ! -f "$SECURITY_MODPROBE_CONF" ]] || ! grep -q "algif_aead" "$SECURITY_MODPROBE_CONF"; then
        cat <<'EOF' | sudo tee "$SECURITY_MODPROBE_CONF" > /dev/null
# Managed by Actions-bbr-v3
# CVE-2026-31431 mitigation: block loading algif_aead from userspace path.
blacklist algif_aead
install algif_aead /bin/false
EOF
        changed=1
    fi

    if lsmod | grep -q "^algif_aead"; then
        if sudo modprobe -r algif_aead 2>/dev/null; then
            echo -e "\033[1;32m✔ 已卸载 algif_aead 模块，当前会话已完成缓解\033[0m"
        else
            echo -e "\033[33m⚠ algif_aead 当前被占用，已写入黑名单，重启后将生效\033[0m"
        fi
    fi

    if [[ "$changed" -eq 1 ]]; then
        echo -e "\033[1;32m✔ 已写入安全策略：$SECURITY_MODPROBE_CONF\033[0m"
    fi
}

# 函数：询问是否永久保存更改
ask_to_save() {
    # 首先尝试加载队列调度模块
    load_qdisc_module "$QDISC"
    
    # 立即应用设置
    echo -e "\033[36m正在应用配置...\033[0m"
    sudo sysctl -w net.core.default_qdisc="$QDISC" > /dev/null 2>&1
    sudo sysctl -w net.ipv4.tcp_congestion_control="$ALGO" > /dev/null 2>&1
    
    # 验证是否生效
    NEW_QDISC=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    NEW_ALGO=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    
    if [[ "$NEW_QDISC" == "$QDISC" && "$NEW_ALGO" == "$ALGO" ]]; then
        echo -e "\033[1;32m✔ 配置已立即生效！\033[0m"
        echo -e "\033[36m  当前队列算法：\033[1;32m$NEW_QDISC\033[0m"
        echo -e "\033[36m  当前拥塞控制：\033[1;32m$NEW_ALGO\033[0m"
    else
        echo -e "\033[31m✘ 配置应用失败！\033[0m"
        echo -e "\033[33m  队列算法期望：$QDISC，实际：$NEW_QDISC\033[0m"
        echo -e "\033[33m  拥塞控制期望：$ALGO，实际：$NEW_ALGO\033[0m"
        echo -e "\033[33m  可能原因：当前内核不支持 $QDISC 队列算法\033[0m"
        return 1
    fi
    
    echo -n -e "\033[36m(｡♥‿♥｡) 要将这些配置永久保存到 $SYSCTL_CONF 吗？(y/n): \033[0m"
    read -r SAVE
    if [[ "$SAVE" == "y" || "$SAVE" == "Y" ]]; then
        clean_sysctl_conf
        echo "net.core.default_qdisc=$QDISC" | sudo tee -a "$SYSCTL_CONF" > /dev/null
        echo "net.ipv4.tcp_congestion_control=$ALGO" | sudo tee -a "$SYSCTL_CONF" > /dev/null
        sudo sysctl --system > /dev/null 2>&1
        
        # 配置模块开机自动加载（fq 和 fq_codel 是内置的不需要）
        if [[ "$QDISC" == "fq" || "$QDISC" == "fq_codel" ]]; then
            # fq 和 fq_codel 是内核内置的，删除旧的模块配置文件
            sudo rm -f "$MODULES_CONF"
            echo -e "\033[1;32m(☆^ー^☆) 更改已永久保存啦~\033[0m"
        else
            echo "sch_$QDISC" | sudo tee "$MODULES_CONF" > /dev/null
            echo -e "\033[1;32m(☆^ー^☆) 更改已永久保存，模块 sch_$QDISC 将在开机时自动加载~\033[0m"
        fi
    else
        echo -e "\033[33m(⌒_⌒;) 好吧，没有永久保存，重启后会恢复原设置呢~\033[0m"
    fi
}

# 函数：获取已安装的 joeyblog 内核版本
get_installed_version() {
    dpkg -l | grep "linux-image" | grep "joeyblog" | awk '{print $2}' | sed 's/linux-image-//' | head -n 1
}

# 函数：智能更新引导加载程序
update_bootloader() {
    echo -e "\033[36m正在更新引导加载程序...\033[0m"
    if command -v update-grub &> /dev/null; then
        echo -e "\033[33m检测到 GRUB，正在执行 update-grub...\033[0m"
        if sudo update-grub; then
            echo -e "\033[1;32mGRUB 更新成功！\033[0m"
            return 0
        else
            echo -e "\033[1;31mGRUB 更新失败！\033[0m"
            return 1
        fi
    else
        echo -e "\033[33m未找到 'update-grub'。您的系统可能使用 U-Boot 或其他引导程序。\033[0m"
        echo -e "\033[33m在许多 ARM 系统上，内核安装包会自动处理引导更新，通常无需手动操作。\033[0m"
        echo -e "\033[33m如果重启后新内核未生效，您可能需要手动更新引导配置，请参考您系统的文档。\033[0m"
        return 0
    fi
}

# 函数：安全地安装下载的包
install_packages() {
    if ! ls /tmp/linux-*.deb &> /dev/null; then
        echo -e "\033[31m错误：未在 /tmp 目录下找到内核文件，安装中止。\033[0m"
        return 1
    fi

    for deb_file in /tmp/linux-*.deb; do
        if ! dpkg-deb -I "$deb_file" > /dev/null 2>&1; then
            echo -e "\033[31m当前系统无法读取安装包：$deb_file\033[0m"
            echo -e "\033[33m可能原因：dpkg 版本过旧，不支持该压缩格式。建议升级 dpkg 后重试。\033[0m"
            return 1
        fi
    done
    
    echo -e "\033[36m开始卸载旧版内核... \033[0m"
    INSTALLED_PACKAGES=$(dpkg -l | grep "joeyblog" | awk '{print $2}' | tr '\n' ' ')
    if [[ -n "$INSTALLED_PACKAGES" ]]; then
        sudo apt-get remove --purge $INSTALLED_PACKAGES -y > /dev/null 2>&1
    fi

    echo -e "\033[36m开始安装新内核... \033[0m"
    if sudo dpkg -i /tmp/linux-*.deb && update_bootloader; then
        echo -e "\033[1;32m内核安装并配置完成！\033[0m"
        echo -n -e "\033[33m需要重启系统来加载新内核。是否立即重启？ (y/n): \033[0m"
        read -r REBOOT_NOW
        if [[ "$REBOOT_NOW" == "y" || "$REBOOT_NOW" == "Y" ]]; then
            echo -e "\033[36m系统即将重启...\033[0m"
            sudo reboot
        else
            echo -e "\033[33m操作完成。请记得稍后手动重启 ('sudo reboot') 来应用新内核。\033[0m"
        fi
    else
        echo -e "\033[1;31m内核安装或引导更新失败！系统可能处于不稳定状态。请不要重启并寻求手动修复！\033[0m"
    fi
}

# 函数：检查并安装最新版本
install_latest_version() {
    echo -e "\033[36m正在从 GitHub 获取最新版本信息...\033[0m"
    BASE_URL="https://api.github.com/repos/byJoey/Actions-bbr-v3/releases"
    RELEASE_DATA=$(gh_api_get "$BASE_URL")
    if [[ -z "$RELEASE_DATA" ]]; then
        echo -e "\033[31m从 GitHub 获取版本信息失败。请检查网络连接或 API 状态。\033[0m"
        return 1
    fi
    check_release_api_response "$RELEASE_DATA" || return 1

    local ARCH_FILTER=""
    [[ "$ARCH" == "aarch64" ]] && ARCH_FILTER="arm64"
    [[ "$ARCH" == "x86_64" ]] && ARCH_FILTER="x86_64"

    LATEST_TAG_NAME=$(echo "$RELEASE_DATA" | jq -r --arg filter "$ARCH_FILTER" 'map(select(.tag_name | test($filter; "i"))) | sort_by(.published_at) | .[-1].tag_name')

    if [[ -z "$LATEST_TAG_NAME" || "$LATEST_TAG_NAME" == "null" ]]; then
        echo -e "\033[31m未找到适合当前架构 ($ARCH) 的最新版本。\033[0m"
        return 1
    fi
    echo -e "\033[36m检测到最新版本：\033[0m\033[1;32m$LATEST_TAG_NAME\033[0m"

    INSTALLED_VERSION=$(get_installed_version)
    echo -e "\033[36m当前已安装版本：\033[0m\033[1;32m${INSTALLED_VERSION:-"未安装"}\033[0m"

    CORE_LATEST_VERSION="${LATEST_TAG_NAME#x86_64-}"
    CORE_LATEST_VERSION="${CORE_LATEST_VERSION#arm64-}"

    if [[ -n "$INSTALLED_VERSION" && "$INSTALLED_VERSION" == "$CORE_LATEST_VERSION"* ]]; then
        # 修复了此处的颜文字，将反引号 ` 替换为单引号 '
        echo -e "\033[1;32m(o'▽'o) 您已安装最新版本，无需更新！\033[0m"
        return 0
    fi

    echo -e "\033[33m发现新版本或未安装内核，准备下载...\033[0m"
    ASSET_URLS=$(echo "$RELEASE_DATA" | jq -r --arg tag "$LATEST_TAG_NAME" '.[] | select(.tag_name == $tag) | .assets[].browser_download_url')
    
    rm -f /tmp/linux-*.deb

    for URL in $ASSET_URLS; do
        echo -e "\033[36m正在下载文件：$URL\033[0m"
        wget -q --show-progress "$URL" -P /tmp/ || { echo -e "\033[31m下载失败：$URL\033[0m"; return 1; }
    done
    
    install_packages
}

# 函数：安装指定版本
install_specific_version() {
    BASE_URL="https://api.github.com/repos/byJoey/Actions-bbr-v3/releases"
    RELEASE_DATA=$(gh_api_get "$BASE_URL")
    if [[ -z "$RELEASE_DATA" ]]; then
        echo -e "\033[31m从 GitHub 获取版本信息失败。请检查网络连接或 API 状态。\033[0m"
        return 1
    fi
    check_release_api_response "$RELEASE_DATA" || return 1

    local ARCH_FILTER=""
    [[ "$ARCH" == "aarch64" ]] && ARCH_FILTER="arm64"
    [[ "$ARCH" == "x86_64" ]] && ARCH_FILTER="x86_64"
    
    MATCH_TAGS=$(echo "$RELEASE_DATA" | jq -r --arg filter "$ARCH_FILTER" '.[] | select(.tag_name | test($filter; "i")) | .tag_name')

    if [[ -z "$MATCH_TAGS" ]]; then
        echo -e "\033[31m未找到适合当前架构的版本。\033[0m"
        return 1
    fi

    echo -e "\033[36m以下为适用于当前架构的版本：\033[0m"
    IFS=$'\n' read -rd '' -a TAG_ARRAY <<<"$MATCH_TAGS"

    for i in "${!TAG_ARRAY[@]}"; do
        echo -e "\033[33m $((i+1)). ${TAG_ARRAY[$i]}\033[0m"
    done

    echo -n -e "\033[36m请输入要安装的版本编号（例如 1）：\033[0m"
    read -r CHOICE
    
    if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || (( CHOICE < 1 || CHOICE > ${#TAG_ARRAY[@]} )); then
        echo -e "\033[31m输入无效编号，取消操作。\033[0m"
        return 1
    fi
    
    INDEX=$((CHOICE-1))
    SELECTED_TAG="${TAG_ARRAY[$INDEX]}"
    echo -e "\033[36m已选择版本：\033[0m\033[1;32m$SELECTED_TAG\033[0m"

    ASSET_URLS=$(echo "$RELEASE_DATA" | jq -r --arg tag "$SELECTED_TAG" '.[] | select(.tag_name == $tag) | .assets[].browser_download_url')
    
    rm -f /tmp/linux-*.deb
    
    for URL in $ASSET_URLS; do
        echo -e "\033[36m下载中：$URL\033[0m"
        wget -q --show-progress "$URL" -P /tmp/ || { echo -e "\033[31m下载失败：$URL\033[0m"; return 1; }
    done

    install_packages
}

# 美化输出的分隔线
print_separator() {
    echo -e "\033[34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
}

# --- 主要执行流程 ---

clear
apply_cve_2026_31431_mitigation
print_separator
echo -e "\033[1;35m(☆ω☆)✧*｡ 欢迎来到 BBR 管理脚本世界哒！ ✧*｡(☆ω☆)\033[0m"
print_separator
echo -e "\033[36m当前 TCP 拥塞控制算法：\033[0m\033[1;32m$CURRENT_ALGO\033[0m"
echo -e "\033[36m当前队列管理算法：    \033[0m\033[1;32m$CURRENT_QDISC\033[0m"
print_separator
echo -e "\033[1;33m作者：Joey  |  博客：https://joeyblog.net  |  反馈群组：https://t.me/+ft-zI76oovgwNmRh\033[0m"
print_separator

echo -e "\033[1;33m╭( ･ㅂ･)و ✧ 你可以选择以下操作哦：\033[0m"
echo -e "\033[33m 1. 🚀 安装或更新 BBR v3 (最新版)\033[0m"
echo -e "\033[33m 2. 📚 指定版本安装\033[0m"
echo -e "\033[33m 3. 🔍 检查 BBR v3 状态\033[0m"
echo -e "\033[33m 4. ⚡ 启用 BBR + FQ\033[0m"
echo -e "\033[33m 5. ⚡ 启用 BBR + FQ_CODEL\033[0m"
echo -e "\033[33m 6. ⚡ 启用 BBR + FQ_PIE\033[0m"
echo -e "\033[33m 7. ⚡ 启用 BBR + CAKE\033[0m"
echo -e "\033[33m 8. 🗑️  卸载 BBR 内核\033[0m"
print_separator
echo -n -e "\033[36m请选择一个操作 (1-8) (｡･ω･｡): \033[0m"
read -r ACTION

case "$ACTION" in
    1)
        echo -e "\033[1;32m٩(｡•́‿•̀｡)۶ 您选择了安装或更新 BBR v3！\033[0m"
        install_latest_version
        ;;
    2)
        echo -e "\033[1;32m(｡･∀･)ﾉﾞ 您选择了安装指定版本的 BBR！\033[0m"
        install_specific_version
        ;;
    3)
        echo -e "\033[1;32m(｡･ω･｡) 检查是否为 BBR v3...\033[0m"
        BBR_MODULE_INFO=$(modinfo tcp_bbr 2>/dev/null)
        if [[ -z "$BBR_MODULE_INFO" ]]; then
            echo -e "\033[36m正在刷新模块依赖...\033[0m"
            depmod -a
            BBR_MODULE_INFO=$(modinfo tcp_bbr 2>/dev/null)
        fi
        if [[ -z "$BBR_MODULE_INFO" ]]; then
            echo -e "\033[31m(⊙﹏⊙) 未加载 tcp_bbr 模块，无法检查版本。请先安装内核并重启。\033[0m"
            exit 1
        fi
        BBR_VERSION=$(echo "$BBR_MODULE_INFO" | awk '/^version:/ {print $2}')
        if [[ "$BBR_VERSION" == "3" ]]; then
            echo -e "\033[36m✔ BBR 模块版本：\033[0m\033[1;32m$BBR_VERSION (v3)\033[0m"
        else
            echo -e "\033[33m(￣﹃￣) 检测到 BBR 模块，但版本是：$BBR_VERSION，不是 v3！\033[0m"
        fi
        
        CURRENT_ALGO=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
        if [[ "$CURRENT_ALGO" == "bbr" ]]; then
            echo -e "\033[36m✔ TCP 拥塞控制算法：\033[0m\033[1;32m$CURRENT_ALGO\033[0m"
        else
            echo -e "\033[31m(⊙﹏⊙) 当前算法不是 bbr，而是：$CURRENT_ALGO\033[0m"
        fi

        if [[ "$BBR_VERSION" == "3" && "$CURRENT_ALGO" == "bbr" ]]; then
            echo -e "\033[1;32mヽ(✿ﾟ▽ﾟ)ノ 检测完成，BBR v3 已正确安装并生效！\033[0m"
        else
            echo -e "\033[33mBBR v3 未完全生效。请确保已安装内核并重启，然后使用选项 4-7 启用。\033[0m"
        fi

        if grep -Eq '^\s*blacklist\s+algif_aead' "$SECURITY_MODPROBE_CONF" 2>/dev/null; then
            echo -e "\033[1;32m✔ CVE-2026-31431 缓解状态：已启用（algif_aead 已黑名单）\033[0m"
        else
            echo -e "\033[31m✘ CVE-2026-31431 缓解状态：未启用\033[0m"
            echo -e "\033[33m  建议重新运行脚本，或手动写入 $SECURITY_MODPROBE_CONF\033[0m"
        fi
        ;;
    4)
        echo -e "\033[1;32m(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧ 使用 BBR + FQ 加速！\033[0m"
        ALGO="bbr"
        QDISC="fq"
        ask_to_save
        ;;
    5)
        echo -e "\033[1;32m(๑•̀ㅂ•́)و✧ 使用 BBR + FQ_CODEL 加速！\033[0m"
        ALGO="bbr"
        QDISC="fq_codel"
        ask_to_save
        ;;
    6)
        echo -e "\033[1;32m٩(•‿•)۶ 使用 BBR + FQ_PIE 加速！\033[0m"
        ALGO="bbr"
        QDISC="fq_pie"
        ask_to_save
        ;;
    7)
        echo -e "\033[1;32m(ﾉ≧∀≦)ﾉ 使用 BBR + CAKE 加速！\033[0m"
        ALGO="bbr"
        QDISC="cake"
        ask_to_save
        ;;
    8)
        echo -e "\033[1;32mヽ(・∀・)ノ 您选择了卸载 BBR 内核！\033[0m"
        PACKAGES_TO_REMOVE=$(dpkg -l | grep "joeyblog" | awk '{print $2}' | tr '\n' ' ')
        if [[ -n "$PACKAGES_TO_REMOVE" ]]; then
            echo -e "\033[36m将要卸载以下内核包: \033[33m$PACKAGES_TO_REMOVE\033[0m"
            sudo apt-get remove --purge $PACKAGES_TO_REMOVE -y
            update_bootloader
            echo -e "\033[1;32m内核包已卸载。请记得重启系统。\033[0m"
        else
            echo -e "\033[33m未找到由本脚本安装的 'joeyblog' 内核包。\033[0m"
        fi
        ;;
    *)
        echo -e "\033[31m(￣▽￣)ゞ 无效的选项，请输入 1-8 之间的数字哦~\033[0m"
        ;;
esac
