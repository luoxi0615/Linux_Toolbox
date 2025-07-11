#!/bin/bash

# ==============================================================================
# Linux综合运维工具箱
# ==============================================================================

# --- 全局变量与颜色定义 ---
GREEN=''
RED=''
YELLOW=''
BLUE=''
NC=''

# --- 辅助函数 ---

# 检查并安装软件包
check_and_install_pkg() {
    local pkg_name=$1
    local cmd_name=${2:-$1}
    if ! command -v "$cmd_name" &> /dev/null; then
        echo "检测到命令 '$cmd_name' 未安装，正在尝试安装软件包 '$pkg_name'..."
        # 识别包管理器
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y "$pkg_name"
        elif command -v yum &> /dev/null; then
            # CentOS/RHEL, 确保EPEL源对某些工具可用
            if ! rpm -q epel-release &>/dev/null && [[ "$pkg_name" == "iftop" || "$pkg_name" == "sysbench" || "$pkg_name" == "htop" ]]; then
                 sudo yum install -y epel-release
            fi
            sudo yum install -y "$pkg_name"
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y "$pkg_name"
        else
            echo "无法识别的包管理器，请手动安装 '$pkg_name'。"
            return 1
        fi
        # 验证安装是否成功
        if ! command -v "$cmd_name" &> /dev/null; then
             echo "软件包 '$pkg_name' 安装失败，请检查您的包管理器和网络。"
             return 1
        fi
        echo "软件包 '$pkg_name' 安装成功。"
    fi
    return 0
}

# 问候语
get_greeting() {
    local hour=$(date +"%H")
    if (( hour >= 5 && hour < 12 )); then
        echo "上午好！"
    elif (( hour >= 12 && hour < 18 )); then
        echo "下午好！"
    else
        echo "晚上好！"
    fi
}

# 按任意键继续
press_any_key() {
    echo ""
    # 修复：强制从终端读取输入
    read -n 1 -s -r -p "按任意键返回菜单..." < /dev/tty
}

# 获取操作系统ID
get_os_id() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# --- 菜单定义 ---

# 主菜单
show_main_menu() {
    clear
    # 基础信息获取
    SERVER_IP=$(hostname -I | awk '{print $1}')
    UPTIME_STR=$(uptime -p | sed 's/up/已运行/')

    echo "================================================================"
    echo "                    Linux 综合运维工具箱                    "
    echo "================================================================"

    # 广告位
    echo "--> 广告位 <--"
    echo "--> 广告位 <--"
    echo "--> 广告位 <--"
    echo "----------------------------------------------------------------"

    echo "服务器IP: $SERVER_IP"
    echo "系统运行时间: $UPTIME_STR"
    echo "当前时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "$(get_greeting) 欢迎使用本工具箱！"
    echo "----------------------------------------------------------------"
    echo " 1. 系统与用户管理"
    echo " 2. 网络与连接管理"
    echo " 3. 磁盘与文件系统"
    echo " 4. 虚拟化与资源优化"
    echo " 5. 软件与服务部署"
    echo " 6. 主机性能与超售风险评估"
    echo " 7. 系统安全与日志审计"
    echo "----------------------------------------------------------------"
    echo " q. 退出脚本"
    echo "================================================================"
}

# 1. 系统与用户管理
system_menu() {
    clear
    echo "--- 系统与用户管理 ---"
    echo " 1.  系统重启"
    echo " 2.  修改当前用户密码"
    echo " 3.  修改服务器主机名"
    echo " 4.  配置时区与时间同步 (上海)"
    echo " 5.  系统更新 (自动识别发行版)"
    echo " 6.  更换包管理器源 (阿里云)"
    echo " 7.  创建新用户 (可设为管理员)"
    echo " 8.  查看系统综合信息"
    echo " 9.  查看系统实时负载 (htop)"
    echo " 10. 查找占用空间最大的文件/目录"
    echo " q.  返回主菜单"
    echo "----------------------"
}

# 2. 网络与连接管理
network_menu() {
    clear
    echo "--- 网络与连接管理 ---"
    echo " 1.  重启网络服务"
    echo " 2.  配置DNS服务器"
    echo " 3.  启用/禁用 ICMP (Ping)"
    echo " 4.  配置附加IP地址 (临时)"
    echo " 5.  查询IP地理位置"
    echo " 6.  查看当前网络连接与监听端口"
    echo " 7.  实时流量监控 (iftop)"
    echo " 8.  测试UDP连通性 (DNS)"
    echo " 9.  测试常用邮件端口 (25, 465, 587)"
    echo " 10. 配置L4端口转发"
    echo " 11. 清除所有L4转发规则"
    echo " 12. MTR网络链路诊断"
    echo " q.  返回主菜单"
    echo "----------------------"
}

# 3. 磁盘与文件系统
disk_menu() {
    clear
    echo "--- 磁盘与文件系统 ---"
    echo " 1.  列出所有磁盘分区"
    echo " 2.  格式化指定磁盘分区"
    echo " 3.  挂载磁盘分区 (支持设为开机自启)"
    echo " 4.  卸载磁盘分区"
    echo " 5.  修复XFS文件系统超级块"
    echo " 6.  配置开机自动执行脚本"
    echo " 7.  文件内容关键字搜索"
    echo " 8.  远程文件传输 (SCP)"
    echo " q.  返回主菜单"
    echo "----------------------"
}

# 4. 虚拟化与资源优化
virtualization_menu() {
    clear
    echo "--- 虚拟化与资源优化 ---"
    echo " 1.  启用嵌套虚拟化 (KVM)"
    echo " 2.  配置SWAP虚拟内存"
    echo " 3.  禁用SWAP虚拟内存"
    echo " 4.  启用/禁用KSM内存合并"
    echo " q.  返回主菜单"
    echo "--------------------------"
}

# 5. 软件与服务部署
software_menu() {
    clear
    echo "--- 软件与服务部署 ---"
    echo " 1.  安装宝塔面板 (BT-Panel)"
    echo " 2.  安装Docker并启动"
    echo " 3.  管理Docker容器 (简易菜单)"
    echo " 4.  安装常用开发工具包 (build-essential, git等)"
    echo " 5.  安装Kangle EP"
    echo " 6.  安装宝塔云WAF"
    echo " q.  返回主菜单"
    echo "----------------------"
}

# 6. 主机性能与超售风险评估
oversubscription_check_menu() {
    clear
    echo "--- 主机性能与超售风险评估 ---"
    echo "此功能通过多维度测试来评估主机资源健康状况。"
    echo "高CPU Steal、低I/O或不稳定的网络是超售的常见指标。"
    echo "---------------------------------------------------"
    echo " 1.  开始综合评估 (全面检测)"
    echo " 2.  单独测试 - CPU Steal Time"
    echo " 3.  单独测试 - 磁盘I/O性能"
    echo " 4.  单独测试 - 网络质量 (Speedtest)"
    echo " 5.  单独测试 - CPU性能基准 (Sysbench)"
    echo " q.  返回主菜单"
    echo "---------------------------------------------------"
}

# 7. 系统安全与日志审计
security_menu() {
    clear
    echo "--- 系统安全与日志审计 ---"
    echo " 1.  基础安全审计 (检查root登录等)"
    echo " 2.  管理SSH服务 (启用/禁用)"
    echo " 3.  修改SSH端口"
    echo " 4.  禁用SELinux (设为Permissive)"
    echo " 5.  查看SSH成功登录历史"
    echo " 6.  查看当前会话连接IP"
    echo " 7.  查看并管理Shell历史命令"
    echo " 8.  使用 lsof 查看监听服务"
    echo " 9.  查看 sudo 命令执行日志"
    echo " q.  返回主菜单"
    echo "---------------------------"
}


# --- 功能实现 (所有read命令已修复) ---

# 1. 系统与用户管理
system_reboot() {
    read -p "警告：您确定要立即重启服务器吗？ (y/n): " confirm < /dev/tty
    if [[ "$confirm" == "y" ]]; then
        echo "服务器正在重启..."
        sudo reboot
    else
        echo "操作已取消。"
    fi
}

change_current_user_password() {
    echo "正在为当前用户 ($(whoami)) 修改密码..."
    sudo passwd "$(whoami)"
    echo "密码修改完成。"
}

change_hostname_func() {
    read -p "请输入新的服务器主机名: " new_hostname < /dev/tty
    if [[ -n "$new_hostname" ]]; then
        sudo hostnamectl set-hostname "$new_hostname"
        echo "主机名已成功修改为: $new_hostname"
        echo "请注意，新的主机名可能需要重新登录终端才能完全生效。"
    else
        echo "主机名不能为空。"
    fi
}

sync_time_func() {
    echo "正在配置时区为 'Asia/Shanghai' 并同步网络时间..."
    sudo timedatectl set-timezone Asia/Shanghai
    if ! check_and_install_pkg "ntpdate"; then return; fi
    sudo ntpdate ntp.aliyun.com
    echo "时区与时间同步完成。当前时间: $(date '+%Y-%m-%d %H:%M:%S')"
}

update_system() {
    echo "即将对系统进行全面更新..."
    read -p "确定要继续吗? (y/n): " confirm < /dev/tty
    if [[ "$confirm" != "y" ]]; then
        echo "操作已取消。"
        return
    fi
    
    os_id=$(get_os_id)
    case "$os_id" in
        ubuntu|debian)
            sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get autoremove -y
            ;;
        centos|rhel|almalinux|rocky)
            sudo yum update -y
            ;;
        *)
            echo "不支持的操作系统: $os_id"
            return
            ;;
    esac
    echo "系统更新完成。建议重启服务器以应用所有更新。"
}

change_repo_source() {
    os_id=$(get_os_id)
    echo "正在尝试将包管理器源更换为阿里云镜像..."
    read -p "此操作会覆盖您当前的源列表，确定吗? (y/n): " confirm < /dev/tty
    if [[ "$confirm" != "y" ]]; then echo "操作已取消。"; return; fi

    case "$os_id" in
        ubuntu)
            sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
            sudo sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list
            sudo sed -i 's/security.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list
            sudo apt-get update
            echo "Ubuntu 源已更换为阿里云。"
            ;;
        debian)
            sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
            sudo sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list
            sudo sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list
            sudo apt-get update
            echo "Debian 源已更换为阿里云。"
            ;;
        centos)
            # 以CentOS 7为例
            if [ -f /etc/yum.repos.d/CentOS-Base.repo ]; then
                sudo cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
                sudo wget -O /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
                sudo yum clean all && sudo yum makecache
                echo "CentOS 7 源已更换为阿里云。"
            else
                echo "未找到 CentOS-Base.repo 文件。此功能可能不适用于您的 CentOS 版本。"
            fi
            ;;
        *)
            echo "此功能暂不支持您的操作系统: $os_id"
            ;;
    esac
}

create_user_func() {
    read -p "请输入要创建的用户名: " username < /dev/tty
    if id "$username" &>/dev/null; then
        echo "用户 '$username' 已存在。"
        return
    fi
    sudo useradd -m -s /bin/bash "$username"
    echo "请为新用户 '$username' 设置密码:"
    sudo passwd "$username"
    read -p "是否将用户 '$username' 添加到 sudo/wheel 组 (设为管理员)? (y/n): " add_sudo < /dev/tty
    if [[ "$add_sudo" == "y" ]]; then
        if command -v usermod &> /dev/null; then
            # Debian/Ubuntu 使用 'sudo' 组, CentOS/RHEL 使用 'wheel' 组
            local sudo_group="sudo"
            if ! getent group sudo >/dev/null; then
                sudo_group="wheel"
            fi
            sudo usermod -aG "$sudo_group" "$username"
            echo "用户 '$username' 已成功创建并设为管理员。"
        fi
    else
        echo "普通用户 '$username' 创建成功。"
    fi
}

show_system_info() {
    echo "--- 系统综合信息 ---"
    echo "主机名: $(hostname)"
    if [ -f /etc/os-release ]; then
        echo "操作系统: $(grep PRETTY_NAME /etc/os-release | cut -d'=' -f2 | tr -d '"')"
    fi
    echo "内核版本: $(uname -r)"
    echo "CPU信息:"
    lscpu | grep -E "^CPU\(s\):|Model name:|Architecture:|Vendor ID:" | sed 's/Model name:/型号名称:/;s/Architecture:/架构:/;s/Vendor ID:/厂商ID:/'
    echo "内存信息:"
    free -h
    echo "磁盘使用情况:"
    df -hT
}

view_system_load() {
    echo "--- 系统平均负载与进程信息 (按 q 退出) ---"
    if ! check_and_install_pkg "htop"; then
        echo "htop 安装失败，将使用 top 命令。"
        top
    else
        htop
    fi
}

find_large_files() {
    read -p "请输入要扫描的起始目录 (默认: /): " scan_dir < /dev/tty
    scan_dir=${scan_dir:-/}
    read -p "请输入要查找的文件数量 (默认: 20): " file_count < /dev/tty
    file_count=${file_count:-20}
    echo "正在扫描目录 '$scan_dir'，这可能需要一些时间..."
    sudo du -ah "$scan_dir" 2>/dev/null | sort -rh | head -n "$file_count"
}

# 2. 网络与连接管理
restart_network_service() {
    echo "正在尝试重启网络服务..."
    if command -v systemctl &> /dev/null; then
        if systemctl list-units --type=service | grep -q 'NetworkManager'; then
            sudo systemctl restart NetworkManager
        elif systemctl list-units --type=service | grep -q 'networking'; then
            sudo systemctl restart networking
        elif systemctl list-units --type=service | grep -q 'network'; then
             sudo systemctl restart network
        else
            echo "未找到标准的网络管理服务。"
            return
        fi
    elif command -v service &> /dev/null; then
        sudo service network restart || sudo service networking restart
    else
        echo "无法确定如何重启网络服务。"
        return
    fi
    echo "网络服务重启命令已发送。"
}

set_dns_func() {
    read -p "请输入首选DNS服务器 (例如 8.8.8.8): " dns1 < /dev/tty
    read -p "请输入备用DNS服务器 (例如 8.8.4.4, 可留空): " dns2 < /dev/tty
    if [[ -z "$dns1" ]]; then
        echo "首选DNS不能为空。"
        return
    fi
    sudo cp /etc/resolv.conf /etc/resolv.conf.bak
    echo "# 由Linux工具箱生成" | sudo tee /etc/resolv.conf > /dev/null
    echo "nameserver $dns1" | sudo tee -a /etc/resolv.conf > /dev/null
    if [[ -n "$dns2" ]]; then
        echo "nameserver $dns2" | sudo tee -a /etc/resolv.conf > /dev/null
    fi
    echo "DNS已成功设置为: "
    cat /etc/resolv.conf
}

toggle_ping_func() {
    local status=$(sysctl -n net.ipv4.icmp_echo_ignore_all)
    if [[ "$status" == "1" ]]; then
        sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0 && echo "Ping (ICMP Echo) 已启用。"
    else
        sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1 && echo "Ping (ICMP Echo) 已禁用。"
    fi
}

add_ip_func() {
    echo "注意: 此功能为临时添加IP，重启后会失效。永久配置需修改网卡文件。"
    read -p "请输入要添加的IP地址和子网掩码 (例如 192.168.1.100/24): " ip_cidr < /dev/tty
    read -p "请输入网络接口名称 (例如 eth0): " interface < /dev/tty
    if [[ -z "$ip_cidr" || -z "$interface" ]]; then
        echo "IP地址和接口名称不能为空。"
        return
    fi
    sudo ip addr add "$ip_cidr" dev "$interface"
    echo "IP地址 '$ip_cidr' 已临时添加到接口 '$interface'。"
    ip addr show "$interface"
}

query_ip_geo() {
    if ! check_and_install_pkg "curl"; then return; fi
    echo "--- 查询本机公网IP地理位置 (数据来源: ipinfo.io) ---"
    curl ipinfo.io
    echo ""
    read -p "是否要查询其他IP地址? (y/n): " query_other < /dev/tty
    if [[ "$query_other" == "y" ]]; then
        read -p "请输入要查询的IP地址: " other_ip < /dev/tty
        if [[ -n "$other_ip" ]]; then
            curl ipinfo.io/"$other_ip"
        fi
    fi
}

list_network_connections() {
    echo "--- 当前网络连接与监听端口 ---"
    if ! check_and_install_pkg "net-tools"; then
        echo "net-tools 安装失败，请手动安装。"
        return
    fi
    sudo netstat -tulnp
}

monitor_traffic_iftop() {
    if ! check_and_install_pkg "iftop"; then return; fi
    echo "正在启动 iftop 实时流量监控... (按 'q' 退出)"
    sudo iftop
}

test_udp_connectivity() {
    if ! check_and_install_pkg "dnsutils" "dig"; then return; fi
    echo "正在测试到 Google DNS (8.8.8.8) 的UDP 53端口连通性..."
    if dig @8.8.8.8 google.com +time=2 +tries=1 | grep -q "status: NOERROR"; then
        echo "UDP 53 端口连通性正常。"
    else
        echo "UDP 53 端口连通性异常，可能被防火墙或运营商屏蔽。"
    fi
}

test_mail_ports() {
    if ! check_and_install_pkg "nmap" "ncat"; then return; fi
    echo "正在测试常用邮件端口 (25, 465, 587) 的连通性..."
    for port in 25 465 587; do
        if ncat -zv -w 2 localhost "$port" &>/dev/null; then
            echo "端口 $port (localhost): 开放"
        else
            echo "端口 $port (localhost): 关闭或无响应"
        fi
    done
}

configure_port_forwarding() {
    echo "警告：此功能将修改iptables规则。"
    read -p "请输入源端口 (本机监听的端口): " src_port < /dev/tty
    read -p "请输入目标IP地址: " dst_ip < /dev/tty
    read -p "请输入目标端口: " dst_port < /dev/tty
    if [[ -z "$src_port" || -z "$dst_ip" || -z "$dst_port" ]]; then
        echo "所有字段均为必填项。"
        return
    fi
    # 启用IP转发
    sudo sysctl -w net.ipv4.ip_forward=1
    # 添加转发规则
    sudo iptables -t nat -A PREROUTING -p tcp --dport "$src_port" -j DNAT --to-destination "${dst_ip}:${dst_port}"
    sudo iptables -t nat -A PREROUTING -p udp --dport "$src_port" -j DNAT --to-destination "${dst_ip}:${dst_port}"
    sudo iptables -t nat -A POSTROUTING -j MASQUERADE
    echo "端口转发规则已添加: 本机端口 $src_port -> ${dst_ip}:${dst_port}"
}

clear_forwarding_rules() {
    read -p "警告：这将清除所有NAT表中的iptables规则，确定吗? (y/n): " confirm < /dev/tty
    if [[ "$confirm" == "y" ]]; then
        sudo iptables -t nat -F
        sudo iptables -t nat -X
        echo "所有NAT转发规则已清除。"
    else
        echo "操作已取消。"
    fi
}

run_mtr() {
    if ! check_and_install_pkg "mtr"; then return; fi
    read -p "请输入要诊断的目标IP或域名: " target < /dev/tty
    if [[ -n "$target" ]]; then
        echo "正在执行MTR网络链路诊断... (按 'q' 退出)"
        sudo mtr "$target"
    else
        echo "目标地址不能为空。"
    fi
}


# 3. 磁盘与文件系统
list_disk_partitions() {
    echo "--- 当前磁盘分区信息 ---"
    sudo fdisk -l
}

format_disk_partition() {
    echo "--- 可用块设备 ---"
    lsblk
    echo "--------------------"
    read -p "请输入要格式化的磁盘分区 (例如 /dev/sdb1): " partition < /dev/tty
    if [[ ! -b "$partition" ]]; then
        echo "错误: '$partition' 不是一个有效的块设备。"
        return
    fi
    read -p "请输入要格式化的文件系统类型 (默认: ext4): " fs_type < /dev/tty
    fs_type=${fs_type:-ext4}
    read -p "警告：格式化将清除 '$partition' 上的所有数据！您确定吗？ (y/n): " confirm < /dev/tty
    if [[ "$confirm" == "y" ]]; then
        sudo mkfs."$fs_type" "$partition"
        echo "分区 '$partition' 格式化为 '$fs_type' 完成。"
    else
        echo "操作已取消。"
    fi
}

mount_disk_partition() {
    echo "--- 可用块设备 ---"
    lsblk
    echo "--------------------"
    read -p "请输入要挂载的磁盘分区 (例如 /dev/sdb1): " partition < /dev/tty
    if [[ ! -b "$partition" ]]; then
        echo "错误: '$partition' 不是一个有效的块设备。"
        return
    fi
    read -p "请输入挂载点目录 (例如 /data): " mount_point < /dev/tty
    if [[ ! -d "$mount_point" ]]; then
        echo "目录 '$mount_point' 不存在，正在创建..."
        sudo mkdir -p "$mount_point"
    fi
    sudo mount "$partition" "$mount_point"
    echo "分区 '$partition' 已成功挂载到 '$mount_point'。"
    
    read -p "是否要设置开机自动挂载? (y/n): " auto_mount < /dev/tty
    if [[ "$auto_mount" == "y" ]]; then
        local uuid=$(sudo blkid -s UUID -o value "$partition")
        if [[ -n "$uuid" ]];then
            echo "UUID=$uuid $mount_point auto defaults 0 0" | sudo tee -a /etc/fstab
            echo "已将自动挂载条目添加到 /etc/fstab。"
        else
            echo "无法获取分区的UUID，自动挂载设置失败。"
        fi
    fi
}

unmount_disk_partition() {
    df -h
    echo "--------------------"
    read -p "请输入要卸载的挂载点或设备 (例如 /data 或 /dev/sdb1): " target < /dev/tty
    if [[ -z "$target" ]]; then
        echo "目标不能为空。"
        return
    fi
    # 移除fstab中的条目
    if grep -q "$target" /etc/fstab; then
        read -p "在 /etc/fstab 中找到了相关条目，是否要移除它? (y/n): " remove_fstab < /dev/tty
        if [[ "$remove_fstab" == "y" ]]; then
            sudo sed -i.bak "\|$target|d" /etc/fstab
            echo "已从 /etc/fstab 中移除条目。"
        fi
    fi
    sudo umount "$target"
    echo "目标 '$target' 卸载完成。"
}

repair_xfs_superblock() {
    read -p "请输入要修复的XFS分区 (例如 /dev/sdb1): " partition < /dev/tty
    if [[ ! -b "$partition" ]]; then
        echo "错误: '$partition' 不是一个有效的块设备。"
        return
    fi
    echo "警告：此操作有风险，请确保分区已卸载。"
    read -p "确定要继续吗? (y/n): " confirm < /dev/tty
    if [[ "$confirm" == "y" ]]; then
        sudo xfs_repair -L "$partition"
    else
        echo "操作已取消。"
    fi
}

configure_startup_script() {
    local script_path="/etc/rc.local"
    if [[ ! -f "$script_path" ]]; then
        echo "#!/bin/bash" | sudo tee "$script_path" > /dev/null
        echo "exit 0" | sudo tee -a "$script_path" > /dev/null
        sudo chmod +x "$script_path"
        echo "已创建 '$script_path' 文件。"
    fi
    echo "您可以编辑 '$script_path' 文件来添加开机自启命令。"
    echo "请将您的命令添加到 'exit 0' 这一行之前。"
    read -p "是否现在使用 nano 编辑该文件? (y/n): " edit_now < /dev/tty
    if [[ "$edit_now" == "y" ]]; then
        sudo nano "$script_path"
    fi
}

search_keyword_in_files() {
    read -p "请输入要搜索的关键字: " keyword < /dev/tty
    read -p "请输入要搜索的目录 (默认: /): " search_dir < /dev/tty
    search_dir=${search_dir:-/}
    echo "正在目录 '$search_dir' 中搜索包含 '$keyword' 的文件..."
    sudo grep -rli "$keyword" "$search_dir" 2>/dev/null
}

scp_file_transfer() {
    echo "请选择操作模式:"
    echo "1. 上传文件到远程服务器"
    echo "2. 从远程服务器下载文件"
    read -p "请选择 [1-2]: " mode < /dev/tty
    
    read -p "请输入远程服务器用户名: " user < /dev/tty
    read -p "请输入远程服务器IP或域名: " host < /dev/tty
    
    if [[ "$mode" == "1" ]]; then
        read -p "请输入本地文件路径: " local_path < /dev/tty
        read -p "请输入远程服务器目标路径: " remote_path < /dev/tty
        scp "$local_path" "${user}@${host}:${remote_path}"
    elif [[ "$mode" == "2" ]]; then
        read -p "请输入远程服务器文件路径: " remote_path < /dev/tty
        read -p "请输入本地保存路径: " local_path < /dev/tty
        scp "${user}@${host}:${remote_path}" "$local_path"
    else
        echo "无效选择。"
    fi
}

# 4. 虚拟化与资源优化
enable_nested_virtualization() {
    if grep -q -E "Y|1" /sys/module/kvm_intel/parameters/nested 2>/dev/null || grep -q -E "Y|1" /sys/module/kvm_amd/parameters/nested 2>/dev/null; then
        echo "嵌套虚拟化已经启用。"
        return
    fi
    if [ -d /sys/module/kvm_intel ]; then
        echo "options kvm_intel nested=1" | sudo tee /etc/modprobe.d/kvm_intel.conf
        sudo modprobe -r kvm_intel
        sudo modprobe kvm_intel
        echo "Intel KVM 嵌套虚拟化已启用。"
    elif [ -d /sys/module/kvm_amd ]; then
        echo "options kvm_amd nested=1" | sudo tee /etc/modprobe.d/kvm_amd.conf
        sudo modprobe -r kvm_amd
        sudo modprobe kvm_amd
        echo "AMD KVM 嵌套虚拟化已启用。"
    else
        echo "未找到KVM模块，无法启用嵌套虚拟化。"
    fi
}

configure_swap_space() {
    read -p "请输入要创建的SWAP大小 (例如 2G, 1024M): " swap_size < /dev/tty
    if [[ -z "$swap_size" ]]; then
        echo "SWAP大小不能为空。"
        return
    fi
    sudo swapoff -a
    sudo rm -f /swapfile
    sudo fallocate -l "$swap_size" /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    # 添加到 fstab
    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab
    fi
    echo "SWAP空间已成功配置。"
    free -h
}

disable_swap_space() {
    sudo swapoff /swapfile
    sudo rm -f /swapfile
    if grep -q "/swapfile" /etc/fstab; then
        sudo sed -i.bak '\|/swapfile|d' /etc/fstab
    fi
    echo "SWAP已禁用并移除。"
    free -h
}

toggle_ksm_deduplication() {
    if ! check_and_install_pkg "ksmtuned"; then return; fi
    if systemctl is-active --quiet ksmtuned; then
        sudo systemctl stop ksmtuned
        sudo systemctl stop ksm
        echo "KSM内存合并已关闭。"
    else
        sudo systemctl start ksm
        sudo systemctl start ksmtuned
        echo "KSM内存合并已开启。"
    fi
}

# 5. 软件与服务部署
install_bt_panel() {
    read -p "这将执行宝塔官方安装脚本，确定吗？(y/n): " confirm < /dev/tty
    if [[ "$confirm" == "y" ]]; then
        os_id=$(get_os_id)
        case "$os_id" in
            ubuntu)
                wget -O install.sh https://download.bt.cn/install/install-ubuntu_6.0.sh && sudo bash install.sh
                ;;
            debian)
                wget -O install.sh https://download.bt.cn/install/install-ubuntu_6.0.sh && bash install.sh
                ;;
            centos)
                yum install -y wget && wget -O install.sh https://download.bt.cn/install/install_6.0.sh && sh install.sh
                ;;
            *)
                echo "宝塔面板可能不支持您的操作系统: $os_id"
                ;;
        esac
    else
        echo "操作已取消。"
    fi
}

install_docker() {
    if command -v docker &> /dev/null; then
        echo "Docker 已经安装。"
        return
    fi
    echo "正在从官方源安装 Docker..."
    if ! check_and_install_pkg "curl"; then return; fi
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo systemctl start docker
    sudo systemctl enable docker
    echo "Docker 安装并启动成功。"
    rm get-docker.sh
}

manage_docker() {
    if ! command -v docker &> /dev/null; then
        echo "Docker 未安装。"
        return
    fi
    clear
    echo "--- Docker 容器管理 ---"
    echo "1. 列出运行中的容器"
    echo "2. 列出所有容器"
    echo "3. 启动容器"
    echo "4. 停止容器"
    echo "5. 查看容器日志 (按 Ctrl+C 退出)"
    echo "6. 删除容器"
    echo "q. 返回"
    read -p "请选择操作: " choice < /dev/tty
    case $choice in
        1) sudo docker ps ;;
        2) sudo docker ps -a ;;
        3) read -p "请输入容器ID或名称: " id < /dev/tty; sudo docker start "$id" ;;
        4) read -p "请输入容器ID或名称: " id < /dev/tty; sudo docker stop "$id" ;;
        5) read -p "请输入容器ID或名称: " id < /dev/tty; sudo docker logs -f "$id" ;;
        6) read -p "请输入容器ID或名称: " id < /dev/tty; sudo docker rm "$id" ;;
        q) return ;;
        *) echo "无效选择" ;;
    esac
}

install_dev_tools() {
    echo "即将安装基础开发工具 (git, gcc, make 等)..."
    read -p "确定要继续吗? (y/n): " confirm < /dev/tty
    if [[ "$confirm" != "y" ]]; then
        echo "操作已取消。"
        return
    fi
    os_id=$(get_os_id)
    case "$os_id" in
        ubuntu|debian)
            sudo apt-get update && sudo apt-get install -y build-essential git
            ;;
        centos|rhel|almalinux|rocky)
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y git
            ;;
        *)
            echo "无法为您的操作系统 '$os_id' 自动安装开发工具。"
            return
            ;;
    esac
    echo "开发工具包安装完成。"
}

install_kangle() {
    read -p "这将执行彩虹Kangle一键安装脚本，确定吗? (y/n): " confirm < /dev/tty
    if [[ "$confirm" == "y" ]]; then
        yum -y install wget; wget http://kangle.cccyun.cn/start; sh start
    else
        echo "操作已取消。"
    fi
}

install_bt_waf() {
    read -p "这将执行宝塔云WAF安装脚本，确定吗? (y/n): " confirm < /dev/tty
    if [[ "$confirm" == "y" ]]; then
        URL=https://download.bt.cn/cloudwaf/scripts/install_cloudwaf.sh && if [ -f /usr/bin/curl ];then curl -sSO "$URL" ;else wget -O install_cloudwaf.sh "$URL";fi;bash install_cloudwaf.sh
    else
        echo "操作已取消。"
    fi
}

# 6. 主机性能与超售风险评估
check_cpu_steal() {
    echo -e "\n--- 1. CPU Steal Time 评估 ---"
    if ! check_and_install_pkg "sysstat" "sar"; then return; fi
    echo "正在收集CPU数据（5秒）..."
    local steal_time=$(sar -u 1 5 | tail -n 1 | awk '{print $6}')
    echo "CPU Steal Time: ${steal_time}%"
    if (( $(echo "$steal_time > 10.0" | bc -l) )); then
        echo "风险评估: 高风险。CPU Steal Time 显著偏高，表示主机CPU资源严重拥塞，是超售的强烈信号。"
    elif (( $(echo "$steal_time > 5.0" | bc -l) )); then
        echo "风险评估: 中等风险。CPU Steal Time 有些偏高，可能存在资源争抢。"
    else
        echo "风险评估: 低风险。CPU Steal Time 处于正常水平。"
    fi
}

check_disk_io() {
    echo -e "\n--- 2. 磁盘 I/O 性能评估 ---"
    echo "正在执行基础磁盘写入测试 (dd, 256MB)..."
    local io_speed=$(dd if=/dev/zero of=test_io_file bs=1M count=256 oflag=direct 2>&1 | tail -n 1 | awk '{print $8 " " $9}')
    rm -f test_io_file
    echo "磁盘写入速度: ${io_speed}"
    local speed_val=$(echo "$io_speed" | awk '{print $1}')
    if (( $(echo "$speed_val < 50" | bc -l) )); then
        echo "性能评估: 较差。磁盘性能可能受限，可能是HDD或I/O限制严格的虚拟化平台。"
    elif (( $(echo "$speed_val < 200" | bc -l) )); then
        echo "性能评估: 普通。性能尚可，类似于普通SATA SSD或性能一般的云盘。"
    else
        echo "性能评估: 良好。磁盘性能表现出色，接近现代NVMe SSD标准。"
    fi
}

check_network_quality() {
    echo -e "\n--- 3. 网络质量评估 ---"
    echo "正在使用 Speedtest.net 测试网络带宽和延迟..."
    if ! check_and_install_pkg "speedtest-cli" "speedtest"; then
        # 备用方案
        if ! check_and_install_pkg "speedtest"; then return; fi
    fi
    speedtest --simple
}

check_cpu_benchmark() {
    echo -e "\n--- 4. CPU 性能基准测试 ---"
    if ! check_and_install_pkg "sysbench"; then return; fi
    echo "正在执行 sysbench CPU 基准测试 (单线程, 10秒)..."
    local cpu_events=$(sysbench cpu --threads=1 --time=10 run | grep "events per second:" | awk '{print $4}')
    echo "单核CPU性能 (events per second): ${cpu_events}"
    if (( $(echo "$cpu_events < 500" | bc -l) )); then
        echo "性能评估: 较低。CPU单核性能较弱，可能为低主频或受限制的vCPU。"
    elif (( $(echo "$cpu_events < 1500" | bc -l) )); then
        echo "性能评估: 中等。性能水平一般，适用于中低负载应用。"
    else
        echo "性能评估: 良好。CPU单核性能强劲。"
    fi
}

run_comprehensive_assessment() {
    clear
    echo "===================================================="
    echo "        开始执行主机性能与超售风险综合评估        "
    echo "===================================================="
    check_cpu_steal
    check_disk_io
    check_network_quality
    check_cpu_benchmark
    echo -e "\n--- 评估总结 ---"
    echo "评估完成。请综合以上各项指标判断主机性能与健康状况。"
    echo "核心关注 CPU Steal Time，该值是判断CPU超售最直接的参考。"
}

# 7. 系统安全与日志审计
run_security_audit() {
    clear
    echo "--- 基础安全审计 ---"
    # 检查root登录
    if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
        echo "[高风险] SSH允许root用户直接密码登录。建议修改为 'PermitRootLogin prohibit-password'。"
    else
        echo "[OK] SSH不允许root用户密码登录。"
    fi

    # 检查开放端口
    echo -e "\n正在监听的TCP/UDP端口:"
    if command -v ss &> /dev/null; then
        sudo ss -tuln
    elif command -v netstat &> /dev/null; then
        check_and_install_pkg "net-tools" "netstat" && sudo netstat -tuln
    else
        echo "无法找到 ss 或 netstat 命令。"
    fi

    # 检查SELinux状态
    if command -v sestatus &> /dev/null; then
        local selinux_status=$(sestatus | awk '{print $3}')
        if [[ $selinux_status == "enabled" ]]; then
             echo -e "\n[注意] SELinux 当前状态为: $selinux_status。某些应用可能需要特定策略。"
        else
             echo -e "\n[OK] SELinux 当前状态为: $selinux_status。"
        fi
    fi
}

manage_ssh_service() {
    if systemctl is-active --quiet sshd || systemctl is-active --quiet ssh; then
        read -p "SSH服务当前正在运行，是否要停止并禁用它? (y/n): " confirm < /dev/tty
        if [[ "$confirm" == "y" ]]; then
            sudo systemctl stop sshd 2>/dev/null || sudo systemctl stop ssh 2>/dev/null
            sudo systemctl disable sshd 2>/dev/null || sudo systemctl disable ssh 2>/dev/null
            echo "SSH服务已停止并禁用。"
        fi
    else
        read -p "SSH服务当前已停止，是否要启动并启用它? (y/n): " confirm < /dev/tty
        if [[ "$confirm" == "y" ]]; then
            sudo systemctl start sshd 2>/dev/null || sudo systemctl start ssh 2>/dev/null
            sudo systemctl enable sshd 2>/dev/null || sudo systemctl enable ssh 2>/dev/null
            echo "SSH服务已启动并启用。"
        fi
    fi
}

change_ssh_port() {
    local ssh_config="/etc/ssh/sshd_config"
    read -p "请输入新的SSH端口 (1024-65535): " new_port < /dev/tty
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1024 ] || [ "$new_port" -gt 65535 ]; then
        echo "无效的端口号。"
        return
    fi
    sudo cp "$ssh_config" "${ssh_config}.bak"
    sudo sed -i "s/^#*Port [0-9]*/Port $new_port/" "$ssh_config"
    echo "SSH端口已在配置文件中修改为 $new_port。"
    echo "请注意：如果启用了防火墙，您需要手动放行新端口 $new_port。"
    read -p "是否现在重启SSH服务以应用更改? (y/n): " restart_ssh < /dev/tty
    if [[ "$restart_ssh" == "y" ]]; then
        sudo systemctl restart sshd 2>/dev/null || sudo systemctl restart ssh 2>/dev/null
        echo "SSH服务已重启。"
    fi
}

disable_selinux_permissive() {
    if ! command -v sestatus &> /dev/null; then
        echo "SELinux 未安装或不可用。"
        return
    fi
    if [[ "$(sestatus | awk '{print $3}')" == "disabled" ]]; then
        echo "SELinux 已经是 disabled 状态。"
        return
    fi
    read -p "警告：这将把SELinux设为 permissive (宽容) 模式，确定吗? (y/n): " confirm < /dev/tty
    if [[ "$confirm" == "y" ]]; then
        sudo setenforce 0
        sudo sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
        echo "SELinux 已临时并永久设置为 permissive 模式。"
    fi
}

view_ssh_logins() {
    echo "--- 最近的SSH成功登录记录 ---"
    local log_file=""
    if [ -f /var/log/auth.log ]; then # Debian/Ubuntu
        log_file="/var/log/auth.log"
    elif [ -f /var/log/secure ]; then # CentOS/RHEL
        log_file="/var/log/secure"
    fi

    if [ -n "$log_file" ]; then
        grep -i "Accepted" "$log_file" | tail -n 20
    else
        echo "未找到SSH日志文件。"
    fi
}

view_current_session_ips() {
    echo "--- 当前连接到本机的远程IP地址 ---"
    sudo who
}

manage_shell_history() {
    echo "1. 查看历史命令"
    echo "2. 清空历史命令"
    read -p "请选择 [1-2]: " choice < /dev/tty
    if [[ "$choice" == "1" ]]; then
        history
    elif [[ "$choice" == "2" ]]; then
        read -p "警告：这将清空您当前会话的历史命令，确定吗? (y/n): " confirm < /dev/tty
        if [[ "$confirm" == "y" ]]; then
            history -c
            echo "" > ~/.bash_history
            echo "历史命令已清空。"
        fi
    fi
}

check_listening_lsof() {
    if ! check_and_install_pkg "lsof"; then return; fi
    echo "--- 使用 lsof 列出所有监听中的服务 ---"
    sudo lsof -i -P -n | grep LISTEN
}

view_sudo_logs() {
    echo "--- 最近的 sudo 命令执行记录 ---"
    local log_file=""
    if [ -f /var/log/auth.log ]; then # Debian/Ubuntu
        log_file="/var/log/auth.log"
    elif [ -f /var/log/secure ]; then # CentOS/RHEL
        log_file="/var/log/secure"
    fi

    if [ -n "$log_file" ]; then
        grep -i 'sudo:' "$log_file" | tail -n 20
    else
        echo "未找到 sudo 日志文件。"
    fi
}


# --- 主循环和逻辑控制 ---
main() {
    while true; do
        show_main_menu
        # 修复：强制从终端读取输入
        read -p "请输入选项 [1-7, q]: " main_choice < /dev/tty
        case $main_choice in
            1) # 系统管理
                while true; do system_menu; read -p "请输入选项: " c < /dev/tty; case $c in
                    1) system_reboot; press_any_key ;; 2) change_current_user_password; press_any_key ;;
                    3) change_hostname_func; press_any_key ;; 4) sync_time_func; press_any_key ;;
                    5) update_system; press_any_key ;; 6) change_repo_source; press_any_key ;;
                    7) create_user_func; press_any_key ;; 8) show_system_info; press_any_key ;;
                    9) view_system_load; press_any_key ;; 10) find_large_files; press_any_key ;;
                    q) break ;; *) echo "无效选项!"; sleep 1 ;; esac; done ;;
            2) # 网络管理
                while true; do network_menu; read -p "请输入选项: " c < /dev/tty; case $c in
                    1) restart_network_service; press_any_key ;; 2) set_dns_func; press_any_key ;;
                    3) toggle_ping_func; press_any_key ;; 4) add_ip_func; press_any_key ;;
                    5) query_ip_geo; press_any_key ;; 6) list_network_connections; press_any_key ;;
                    7) monitor_traffic_iftop; press_any_key ;; 8) test_udp_connectivity; press_any_key ;;
                    9) test_mail_ports; press_any_key ;; 10) configure_port_forwarding; press_any_key ;;
                    11) clear_forwarding_rules; press_any_key ;; 12) run_mtr; press_any_key ;;
                    q) break ;; *) echo "无效选项!"; sleep 1 ;; esac; done ;;
            3) # 磁盘管理
                while true; do disk_menu; read -p "请输入选项: " c < /dev/tty; case $c in
                    1) list_disk_partitions; press_any_key ;; 2) format_disk_partition; press_any_key ;;
                    3) mount_disk_partition; press_any_key ;; 4) unmount_disk_partition; press_any_key ;;
                    5) repair_xfs_superblock; press_any_key ;; 6) configure_startup_script; press_any_key ;;
                    7) search_keyword_in_files; press_any_key ;; 8) scp_file_transfer; press_any_key ;;
                    q) break ;; *) echo "无效选项!"; sleep 1 ;; esac; done ;;
            4) # 虚拟化管理
                while true; do virtualization_menu; read -p "请输入选项: " c < /dev/tty; case $c in
                    1) enable_nested_virtualization; press_any_key ;; 2) configure_swap_space; press_any_key ;;
                    3) disable_swap_space; press_any_key ;; 4) toggle_ksm_deduplication; press_any_key ;;
                    q) break ;; *) echo "无效选项!"; sleep 1 ;; esac; done ;;
            5) # 软件部署
                 while true; do software_menu; read -p "请输入选项: " c < /dev/tty; case $c in
                    1) install_bt_panel; press_any_key ;; 2) install_docker; press_any_key ;;
                    3) manage_docker; press_any_key ;; 4) install_dev_tools; press_any_key ;;
                    5) install_kangle; press_any_key ;; 6) install_bt_waf; press_any_key ;;
                    q) break ;; *) echo "无效选项!"; sleep 1 ;; esac; done ;;
            6) # 性能评估
                while true; do oversubscription_check_menu; read -p "请输入选项: " c < /dev/tty; case $c in
                    1) run_comprehensive_assessment; press_any_key ;; 2) check_cpu_steal; press_any_key ;;
                    3) check_disk_io; press_any_key ;; 4) check_network_quality; press_any_key ;;
                    5) check_cpu_benchmark; press_any_key ;;
                    q) break ;; *) echo "无效选项!"; sleep 1 ;; esac; done ;;
            7) # 安全审计
                 while true; do security_menu; read -p "请输入选项: " c < /dev/tty; case $c in
                    1) run_security_audit; press_any_key ;; 2) manage_ssh_service; press_any_key ;;
                    3) change_ssh_port; press_any_key ;; 4) disable_selinux_permissive; press_any_key ;;
                    5) view_ssh_logins; press_any_key ;; 6) view_current_session_ips; press_any_key ;;
                    7) manage_shell_history; press_any_key ;; 8) check_listening_lsof; press_any_key ;;
                    9) view_sudo_logs; press_any_key ;;
                    q) break ;; *) echo "无效选项!"; sleep 1 ;; esac; done ;;
            q)
                echo "感谢使用，再见！"
                exit 0
                ;;
            *)
                echo "无效的选项，请重新输入。"
                sleep 1
                ;;
        esac
    done
}

# --- 脚本执行入口 ---
main
