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
# 安全加固配置（Dirty Frag 风险面收敛）
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

# 函数：清理智能带宽优化配置
clean_smart_tuning_conf() {
    sudo touch "$SYSCTL_CONF"
    sudo sed -i '/net.core.rmem_max/d' "$SYSCTL_CONF"
    sudo sed -i '/net.core.wmem_max/d' "$SYSCTL_CONF"
    sudo sed -i '/net.ipv4.tcp_wmem/d' "$SYSCTL_CONF"
    sudo sed -i '/net.ipv4.tcp_rmem/d' "$SYSCTL_CONF"
    sudo sed -i '/net.ipv4.tcp_limit_output_bytes/d' "$SYSCTL_CONF"
    sudo sed -i '/net.ipv4.tcp_slow_start_after_idle/d' "$SYSCTL_CONF"
}

# 函数：清理亚太线路调优配置
clean_apac_tuning_conf() {
    clean_smart_tuning_conf
}

# 函数：应用亚太机器 TCP 调优
apply_apac_tuning() {
    echo -e "\033[36m正在应用亚太机器 TCP 调优...\033[0m"

    if sudo sysctl -w net.ipv4.tcp_wmem="4096 16384 12582912" > /dev/null \
        && sudo sysctl -w net.ipv4.tcp_rmem="4096 131072 33554432" > /dev/null \
        && sudo sysctl -w net.ipv4.tcp_limit_output_bytes="4194304" > /dev/null \
        && sudo sysctl -w net.ipv4.tcp_slow_start_after_idle="0" > /dev/null; then
        echo -e "\033[1;32m✔ 亚太机器 TCP 调优已立即生效\033[0m"
    else
        echo -e "\033[31m✘ 亚太机器 TCP 调优应用失败，请检查当前内核是否支持这些 sysctl 项。\033[0m"
        return 1
    fi

    clean_apac_tuning_conf
    {
        echo "net.ipv4.tcp_wmem = 4096 16384 12582912"
        echo "net.ipv4.tcp_rmem = 4096 131072 33554432"
        echo "net.ipv4.tcp_limit_output_bytes = 4194304"
        echo "net.ipv4.tcp_slow_start_after_idle = 0"
    } | sudo tee -a "$SYSCTL_CONF" > /dev/null

    echo -e "\033[1;32m✔ 亚太机器 TCP 调优已永久写入：$SYSCTL_CONF\033[0m"
    echo -e "\033[36m  tcp_wmem:                 \033[1;32m$(sysctl -n net.ipv4.tcp_wmem)\033[0m"
    echo -e "\033[36m  tcp_rmem:                 \033[1;32m$(sysctl -n net.ipv4.tcp_rmem)\033[0m"
    echo -e "\033[36m  tcp_limit_output_bytes:   \033[1;32m$(sysctl -n net.ipv4.tcp_limit_output_bytes)\033[0m"
    echo -e "\033[36m  tcp_slow_start_after_idle:\033[1;32m $(sysctl -n net.ipv4.tcp_slow_start_after_idle)\033[0m"
}

# 函数：判断是否为正数
is_positive_number() {
    awk -v value="$1" 'BEGIN { exit !(value > 0) }'
}

# 函数：按内存容量限制智能优化 buffer，单位：MB
get_tcp_buffer_cap_mb() {
    local mem_kb
    mem_kb=$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)

    if ! [[ "$mem_kb" =~ ^[0-9]+$ ]]; then
        echo 64
    elif (( mem_kb < 524288 )); then
        echo 16
    elif (( mem_kb < 1048576 )); then
        echo 32
    else
        echo 64
    fi
}

# 函数：按带宽和地区映射智能优化 buffer，单位：MB
calculate_smart_buffer_mb() {
    local bandwidth="$1"
    local region="$2"
    local cap_mb="$3"
    local buffer_mb=16

    bandwidth="${bandwidth%.*}"
    if ! [[ "$bandwidth" =~ ^[0-9]+$ ]] || (( bandwidth <= 0 )); then
        bandwidth=1000
    fi

    if [[ "$region" == "overseas" ]]; then
        if (( bandwidth < 500 )); then
            buffer_mb=16
        elif (( bandwidth < 1000 )); then
            buffer_mb=48
        else
            buffer_mb=64
        fi
    else
        if (( bandwidth < 500 )); then
            buffer_mb=8
        elif (( bandwidth < 1000 )); then
            buffer_mb=12
        elif (( bandwidth < 2000 )); then
            buffer_mb=16
        elif (( bandwidth < 5000 )); then
            buffer_mb=24
        elif (( bandwidth < 10000 )); then
            buffer_mb=28
        else
            buffer_mb=32
        fi
    fi

    if (( buffer_mb > cap_mb )); then
        buffer_mb="$cap_mb"
    fi
    echo "$buffer_mb"
}

# 函数：确保 Ookla 官方 speedtest 可用
ensure_ookla_speedtest() {
    if command -v speedtest > /dev/null 2>&1; then
        return 0
    fi

    local cpu_arch
    local download_url
    cpu_arch=$(uname -m)
    case "$cpu_arch" in
        x86_64)
            download_url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz"
            ;;
        aarch64)
            download_url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz"
            ;;
        *)
            echo -e "\033[33m⚠ 当前架构 $cpu_arch 暂无内置 Ookla speedtest 下载地址。\033[0m"
            return 1
            ;;
    esac

    echo -e "\033[33m未检测到 Ookla speedtest，正在安装...\033[0m"
    (
        cd /tmp || exit 1
        rm -rf speedtest speedtest.tgz speedtest.5 speedtest.md
        wget -q "$download_url" -O speedtest.tgz
        tar -xzf speedtest.tgz
        sudo mv speedtest /usr/local/bin/speedtest
        sudo chmod +x /usr/local/bin/speedtest
        rm -f speedtest.tgz speedtest.5 speedtest.md
    )
}

# 函数：选择中国境内测速运营商
select_china_speedtest_isp() {
    local choice=""

    while true; do
        echo -e "\033[36m请选择中国境内测速运营商：\033[0m" >&2
        echo -e "\033[33m 1. 中国移动 / CMCC\033[0m" >&2
        echo -e "\033[33m 2. 中国联通 / CUCC\033[0m" >&2
        echo -e "\033[33m 3. 中国电信 / CTCC\033[0m" >&2
        echo -n -e "\033[36m请选择 (1-3): \033[0m" >&2
        read -r choice

        case "$choice" in
            1)
                SPEEDTEST_ISP_LABEL="中国移动"
                SPEEDTEST_ISP_PATTERN='(Mobile|CMCC|China Mobile|中国移动|移动)'
                return 0
                ;;
            2)
                SPEEDTEST_ISP_LABEL="中国联通"
                SPEEDTEST_ISP_PATTERN='(Unicom|CUCC|China Unicom|中国联通|联通)'
                return 0
                ;;
            3)
                SPEEDTEST_ISP_LABEL="中国电信"
                SPEEDTEST_ISP_PATTERN='(Telecom|CTCC|China Telecom|中国电信|电信)'
                return 0
                ;;
            *)
                echo -e "\033[31m请输入 1、2 或 3 选择测速运营商。\033[0m" >&2
                ;;
        esac
    done
}

# 函数：从 Ookla server list 中筛选中国境内节点
get_china_speedtest_servers() {
    local isp_pattern="$1"
    local server_output
    local china_pattern='(China|Beijing|Shanghai|Guangzhou|Shenzhen|Hangzhou|Nanjing|Wuhan|Chengdu|Chongqing|Tianjin|Xi.?an|Zhengzhou|Changsha|Jinan|Qingdao|Fuzhou|Xiamen|Hefei|Suzhou|Ningbo|Dongguan|Foshan|中国|北京|上海|广州|深圳|杭州|南京|武汉|成都|重庆|天津|西安|郑州|长沙|济南|青岛|福州|厦门|合肥|苏州|宁波|东莞|佛山)'

    server_output=$(speedtest --accept-license --accept-gdpr --servers 2>/dev/null || true)
    if [[ -z "$server_output" ]]; then
        return 1
    fi

    echo "$server_output" \
        | grep -Ei "$china_pattern" \
        | grep -Ei "$isp_pattern" \
        | sed -nE 's/^[[:space:]]*([0-9]+).*/\1/p'
}

# 函数：从 Ookla server list 中筛选香港节点
get_hongkong_speedtest_servers() {
    local server_output
    local hongkong_pattern='(Hong[ -]?Kong|Hongkong|香港|HKBN|HKT|CMHK|SmarTone|HGC|PCCW|Netvigator)'

    server_output=$(speedtest --accept-license --accept-gdpr --servers 2>/dev/null || true)
    if [[ -z "$server_output" ]]; then
        return 1
    fi

    echo "$server_output" \
        | grep -Ei "$hongkong_pattern" \
        | sed -nE 's/^[[:space:]]*([0-9]+).*/\1/p'
}

# 函数：运行 Ookla Speedtest 并解析 Ping/Download/Upload
run_speedtest_measurement() {
    SPEEDTEST_PING=""
    SPEEDTEST_DOWNLOAD=""
    SPEEDTEST_UPLOAD=""

    ensure_ookla_speedtest || return 1

    select_china_speedtest_isp
    echo -e "\033[36m正在运行 Ookla Speedtest 测速，请稍候...\033[0m"
    echo -e "\033[36m优先选择：中国境内最近的 ${SPEEDTEST_ISP_LABEL} 节点\033[0m"
    local servers_list
    local speedtest_output=""
    local attempt=0
    servers_list=$(get_china_speedtest_servers "$SPEEDTEST_ISP_PATTERN" | head -n 10)
    if [[ -z "$servers_list" ]]; then
        echo -e "\033[33m⚠ 未找到匹配运营商的中国境内节点，改用香港节点。\033[0m"
        servers_list=$(get_hongkong_speedtest_servers | head -n 10)
    fi
    if [[ -z "$servers_list" ]]; then
        echo -e "\033[33m⚠ 未找到香港节点，改用 Ookla 自动选择。\033[0m"
        servers_list="auto"
    fi

    for server_id in $servers_list; do
        attempt=$((attempt + 1))
        if (( attempt > 5 )); then
            break
        fi

        if [[ "$server_id" == "auto" ]]; then
            speedtest_output=$(speedtest --accept-license --accept-gdpr 2>&1)
        else
            speedtest_output=$(speedtest --accept-license --accept-gdpr --server-id="$server_id" 2>&1)
        fi

        SPEEDTEST_PING=$(echo "$speedtest_output" | sed -nE 's/.*(Idle Latency|Latency|Ping):[[:space:]]*([0-9]+(\.[0-9]+)?).*/\2/p' | head -n1)
        SPEEDTEST_DOWNLOAD=$(echo "$speedtest_output" | sed -nE 's/.*[Dd]ownload:[[:space:]]*([0-9]+(\.[0-9]+)?).*/\1/p' | head -n1)
        SPEEDTEST_UPLOAD=$(echo "$speedtest_output" | sed -nE 's/.*[Uu]pload:[[:space:]]*([0-9]+(\.[0-9]+)?).*/\1/p' | head -n1)

        if is_positive_number "$SPEEDTEST_UPLOAD" && ! echo "$speedtest_output" | grep -qi "FAILED\|error"; then
            break
        fi

        SPEEDTEST_PING=""
        SPEEDTEST_DOWNLOAD=""
        SPEEDTEST_UPLOAD=""
    done

    if is_positive_number "$SPEEDTEST_UPLOAD"; then
        echo -e "\033[36m  Ping:     \033[1;32m${SPEEDTEST_PING:-未知} ms\033[0m"
        echo -e "\033[36m  Download: \033[1;32m${SPEEDTEST_DOWNLOAD:-0} Mbit/s\033[0m"
        echo -e "\033[36m  Upload:   \033[1;32m${SPEEDTEST_UPLOAD} Mbit/s\033[0m"
        return 0
    fi

    echo -e "\033[33m⚠ Speedtest 输出解析失败，将改为手动输入带宽和 RTT。\033[0m"
    return 1
}

# 函数：读取正数输入
read_positive_value() {
    local prompt="$1"
    local default_value="$2"
    local value=""

    while true; do
        echo -n -e "$prompt" >&2
        read -r value
        value="${value:-$default_value}"
        if is_positive_number "$value"; then
            echo "$value"
            return 0
        fi
        echo -e "\033[31m请输入有效的正数。\033[0m" >&2
    done
}

# 函数：选择地区/RTT 模式
select_tuning_rtt() {
    local measured_ping="$1"
    local choice=""
    local default_rtt=""

    echo -e "\033[36m请选择线路模式：\033[0m"
    echo -e "\033[33m 1. 自动判断（按 Speedtest RTT）\033[0m"
    echo -e "\033[33m 2. 亚太线路（RTT < 100ms）\033[0m"
    echo -e "\033[33m 3. 美欧线路（RTT 150-300ms）\033[0m"
    echo -e "\033[33m 4. 手动输入 RTT\033[0m"
    echo -n -e "\033[36m请选择 (1-4，默认 1): \033[0m"
    read -r choice
    choice="${choice:-1}"

    case "$choice" in
        1)
            if is_positive_number "$measured_ping"; then
                SMART_RTT_MS="$measured_ping"
                if awk -v rtt="$SMART_RTT_MS" 'BEGIN { exit !(rtt < 100) }'; then
                    SMART_REGION="亚太"
                    SMART_REGION_CODE="asia"
                elif awk -v rtt="$SMART_RTT_MS" 'BEGIN { exit !(rtt <= 300) }'; then
                    SMART_REGION="美欧"
                    SMART_REGION_CODE="overseas"
                else
                    SMART_REGION="高延迟"
                    SMART_REGION_CODE="overseas"
                fi
            else
                SMART_REGION="手动"
                SMART_REGION_CODE="asia"
                SMART_RTT_MS=$(read_positive_value "\033[36m请输入实际 RTT(ms，默认 80): \033[0m" "80")
            fi
            ;;
        2)
            SMART_REGION="亚太"
            SMART_REGION_CODE="asia"
            default_rtt="80"
            if is_positive_number "$measured_ping"; then
                default_rtt="$measured_ping"
            fi
            SMART_RTT_MS=$(read_positive_value "\033[36m请输入实际 RTT(ms，默认 ${default_rtt}): \033[0m" "$default_rtt")
            ;;
        3)
            SMART_REGION="美欧"
            SMART_REGION_CODE="overseas"
            default_rtt="220"
            if is_positive_number "$measured_ping"; then
                default_rtt="$measured_ping"
            fi
            SMART_RTT_MS=$(read_positive_value "\033[36m请输入实际 RTT(ms，默认 ${default_rtt}): \033[0m" "$default_rtt")
            ;;
        4)
            SMART_REGION="手动"
            SMART_RTT_MS=$(read_positive_value "\033[36m请输入实际 RTT(ms，默认 100): \033[0m" "100")
            if awk -v rtt="$SMART_RTT_MS" 'BEGIN { exit !(rtt < 120) }'; then
                SMART_REGION_CODE="asia"
            else
                SMART_REGION_CODE="overseas"
            fi
            ;;
        *)
            echo -e "\033[31m输入无效，使用自动判断。\033[0m"
            select_tuning_rtt "$measured_ping"
            ;;
    esac
}

# 函数：应用 BBR v3 智能带宽优化
apply_smart_bandwidth_tuning() {
    local upload_mbps=""
    local download_mbps=""
    local cap_mb=""
    local buffer_mb=""
    local buffer_bytes=""
    local output_bytes="4194304"
    local smart_algo="bbr"
    local smart_qdisc="fq"

    echo -e "\033[36m正在准备 BBR v3 智能带宽优化...\033[0m"
    load_qdisc_module "$smart_qdisc"

    if sudo sysctl -w net.core.default_qdisc="$smart_qdisc" > /dev/null \
        && sudo sysctl -w net.ipv4.tcp_congestion_control="$smart_algo" > /dev/null; then
        echo -e "\033[1;32m✔ 已启用 BBR + FQ\033[0m"
    else
        echo -e "\033[31m✘ BBR + FQ 启用失败，请确认当前内核支持 BBR 和 fq。\033[0m"
        return 1
    fi

    if run_speedtest_measurement; then
        upload_mbps="${SPEEDTEST_UPLOAD%.*}"
        download_mbps="${SPEEDTEST_DOWNLOAD%.*}"
    else
        upload_mbps=$(read_positive_value "\033[36m请输入上传带宽(Mbit/s，默认 1000): \033[0m" "1000")
        download_mbps="$upload_mbps"
    fi

    if ! [[ "$upload_mbps" =~ ^[0-9]+$ ]] || (( upload_mbps <= 0 )); then
        upload_mbps="1000"
    fi
    if ! [[ "$download_mbps" =~ ^[0-9]+$ ]] || (( download_mbps <= 0 )); then
        download_mbps="$upload_mbps"
    fi

    select_tuning_rtt "$SPEEDTEST_PING"

    cap_mb=$(get_tcp_buffer_cap_mb)
    buffer_mb=$(calculate_smart_buffer_mb "$upload_mbps" "$SMART_REGION_CODE" "$cap_mb")
    buffer_bytes=$((buffer_mb * 1024 * 1024))

    if sudo sysctl -w net.core.rmem_max="$buffer_bytes" > /dev/null \
        && sudo sysctl -w net.core.wmem_max="$buffer_bytes" > /dev/null \
        && sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 $buffer_bytes" > /dev/null \
        && sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 $buffer_bytes" > /dev/null \
        && sudo sysctl -w net.ipv4.tcp_limit_output_bytes="$output_bytes" > /dev/null \
        && sudo sysctl -w net.ipv4.tcp_slow_start_after_idle="0" > /dev/null; then
        echo -e "\033[1;32m✔ BBR v3 智能带宽优化已立即生效\033[0m"
    else
        echo -e "\033[31m✘ BBR v3 智能带宽优化应用失败，请检查当前内核是否支持这些 sysctl 项。\033[0m"
        return 1
    fi

    clean_sysctl_conf
    clean_smart_tuning_conf
    {
        echo "net.core.default_qdisc=$smart_qdisc"
        echo "net.ipv4.tcp_congestion_control=$smart_algo"
        echo "net.core.rmem_max = $buffer_bytes"
        echo "net.core.wmem_max = $buffer_bytes"
        echo "net.ipv4.tcp_wmem = 4096 65536 $buffer_bytes"
        echo "net.ipv4.tcp_rmem = 4096 87380 $buffer_bytes"
        echo "net.ipv4.tcp_limit_output_bytes = $output_bytes"
        echo "net.ipv4.tcp_slow_start_after_idle = 0"
    } | sudo tee -a "$SYSCTL_CONF" > /dev/null

    echo -e "\033[1;32m✔ 智能优化配置已永久写入：$SYSCTL_CONF\033[0m"
    echo -e "\033[36m  线路模式：               \033[1;32m$SMART_REGION\033[0m"
    echo -e "\033[36m  计算 RTT：                \033[1;32m${SMART_RTT_MS} ms\033[0m"
    echo -e "\033[36m  上传/下载：               \033[1;32m${upload_mbps}/${download_mbps} Mbit/s\033[0m"
    echo -e "\033[36m  推荐缓冲区：             \033[1;32m${buffer_mb}MB\033[0m"
    echo -e "\033[36m  内存保护上限：           \033[1;32m${cap_mb}MB\033[0m"
    echo -e "\033[36m  队列算法：               \033[1;32m$(sysctl -n net.core.default_qdisc)\033[0m"
    echo -e "\033[36m  拥塞控制：               \033[1;32m$(sysctl -n net.ipv4.tcp_congestion_control)\033[0m"
    echo -e "\033[36m  tcp_wmem:                 \033[1;32m$(sysctl -n net.ipv4.tcp_wmem)\033[0m"
    echo -e "\033[36m  tcp_rmem:                 \033[1;32m$(sysctl -n net.ipv4.tcp_rmem)\033[0m"
    echo -e "\033[36m  tcp_limit_output_bytes:   \033[1;32m$(sysctl -n net.ipv4.tcp_limit_output_bytes)\033[0m"
    echo -e "\033[36m  tcp_slow_start_after_idle:\033[1;32m $(sysctl -n net.ipv4.tcp_slow_start_after_idle)\033[0m"
}

# 函数：清空本脚本写入的网络优化配置
clear_network_optimizations() {
    echo -e "\033[36m正在清空本脚本写入的网络优化配置...\033[0m"
    clean_sysctl_conf
    clean_smart_tuning_conf
    sudo rm -f "$MODULES_CONF"
    sudo sysctl --system > /dev/null 2>&1 || true

    echo -e "\033[1;32m✔ 已清空网络优化持久配置\033[0m"
    echo -e "\033[36m  已清理：$SYSCTL_CONF 中的 BBR/qdisc/TCP buffer 参数\033[0m"
    echo -e "\033[36m  已删除：$MODULES_CONF\033[0m"
    echo -e "\033[33m  当前运行态参数可能要到重启后完全恢复为系统默认值。\033[0m"
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

# 函数：确保安全规则存在（不存在则追加）
ensure_security_rule() {
    local rule="$1"
    local changed_var="$2"
    if ! grep -Fqx "$rule" "$SECURITY_MODPROBE_CONF" 2>/dev/null; then
        echo "$rule" | sudo tee -a "$SECURITY_MODPROBE_CONF" > /dev/null
        eval "$changed_var=1"
    fi
}

current_kernel_disables_aead() {
    local kernel_release
    local boot_config

    kernel_release=$(uname -r)
    boot_config="/boot/config-$kernel_release"

    if [[ -r "$boot_config" ]]; then
        grep -Fqx "# CONFIG_CRYPTO_USER_API_AEAD is not set" "$boot_config"
        return $?
    fi

    if [[ -r /proc/config.gz ]] && command -v gzip >/dev/null 2>&1; then
        gzip -dc /proc/config.gz 2>/dev/null | grep -Fqx "# CONFIG_CRYPTO_USER_API_AEAD is not set"
        return $?
    fi

    return 1
}

# 函数：应用安全缓解（Dirty Frag）
apply_security_mitigations() {
    local changed=0

    sudo touch "$SECURITY_MODPROBE_CONF"
    if ! grep -Fqx "# Managed by Actions-bbr-v3" "$SECURITY_MODPROBE_CONF" 2>/dev/null; then
        echo "# Managed by Actions-bbr-v3" | sudo tee -a "$SECURITY_MODPROBE_CONF" > /dev/null
        changed=1
    fi

    # The latest kernel builds disable CONFIG_CRYPTO_USER_API_AEAD, so remove
    # legacy algif_aead runtime blacklists written by older script versions.
    if grep -Eq '^(blacklist algif_aead|install algif_aead /bin/false)$' "$SECURITY_MODPROBE_CONF" 2>/dev/null; then
        if current_kernel_disables_aead; then
            sudo sed -i '/^blacklist algif_aead$/d' "$SECURITY_MODPROBE_CONF"
            sudo sed -i '/^install algif_aead \/bin\/false$/d' "$SECURITY_MODPROBE_CONF"
            changed=1
            echo -e "\033[1;32m✔ 已移除旧的 algif_aead 黑名单；CVE-2026-31431 风险由当前内核配置侧收敛\033[0m"
        else
            echo -e "\033[33m⚠ 当前运行内核尚未确认关闭 CRYPTO_USER_API_AEAD，暂保留旧的 algif_aead 黑名单\033[0m"
        fi
    fi

    # Dirty Frag mitigation
    ensure_security_rule "blacklist esp4" changed
    ensure_security_rule "install esp4 /bin/false" changed
    ensure_security_rule "blacklist esp6" changed
    ensure_security_rule "install esp6 /bin/false" changed
    ensure_security_rule "blacklist rxrpc" changed
    ensure_security_rule "install rxrpc /bin/false" changed

    for mod in esp4 esp6 rxrpc; do
        if lsmod | grep -q "^$mod"; then
            if sudo modprobe -r "$mod" 2>/dev/null; then
                echo -e "\033[1;32m✔ 已卸载 $mod 模块，当前会话已完成缓解\033[0m"
            else
                echo -e "\033[33m⚠ $mod 当前被占用，已写入黑名单，重启后将生效\033[0m"
            fi
        fi
    done

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
    ASSET_URLS=$(echo "$RELEASE_DATA" | jq -r --arg tag "$LATEST_TAG_NAME" '
      .[] | select(.tag_name == $tag) | .assets[].browser_download_url
      | select(test("(-dbg_|-dbgsym_)"; "i") | not)
    ')
    
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

    ASSET_URLS=$(echo "$RELEASE_DATA" | jq -r --arg tag "$SELECTED_TAG" '
      .[] | select(.tag_name == $tag) | .assets[].browser_download_url
      | select(test("(-dbg_|-dbgsym_)"; "i") | not)
    ')
    
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
apply_security_mitigations
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
echo -e "\033[33m 8. 🌏 亚太机器 TCP 调优\033[0m"
echo -e "\033[33m 9. 🗑️  卸载 BBR 内核\033[0m"
echo -e "\033[33m10. 🧠 BBR v3 智能带宽优化\033[0m"
echo -e "\033[33m11. 🧹 清空网络优化配置\033[0m"
print_separator
echo -n -e "\033[36m请选择一个操作 (1-11) (｡･ω･｡): \033[0m"
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

        if grep -Eq '^\s*blacklist\s+esp4' "$SECURITY_MODPROBE_CONF" 2>/dev/null \
           && grep -Eq '^\s*blacklist\s+esp6' "$SECURITY_MODPROBE_CONF" 2>/dev/null \
           && grep -Eq '^\s*blacklist\s+rxrpc' "$SECURITY_MODPROBE_CONF" 2>/dev/null; then
            echo -e "\033[1;32m✔ Dirty Frag 缓解状态：已启用（esp4/esp6/rxrpc 已黑名单）\033[0m"
        else
            echo -e "\033[31m✘ Dirty Frag 缓解状态：未启用\033[0m"
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
        echo -e "\033[1;32m(๑•̀ㅂ•́)و✧ 您选择了亚太机器 TCP 调优！\033[0m"
        apply_apac_tuning
        ;;
    9)
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
    10)
        echo -e "\033[1;32m(๑•̀ㅂ•́)و✧ 您选择了 BBR v3 智能带宽优化！\033[0m"
        apply_smart_bandwidth_tuning
        ;;
    11)
        echo -e "\033[1;32m(๑•̀ㅂ•́)و✧ 您选择了清空网络优化配置！\033[0m"
        clear_network_optimizations
        ;;
    *)
        echo -e "\033[31m(￣▽￣)ゞ 无效的选项，请输入 1-11 之间的数字哦~\033[0m"
        ;;
esac
