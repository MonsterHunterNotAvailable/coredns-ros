#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 GitHub releases 下载最新的 geoip.dat，并提取特定服务的 IPv4 地址（CIDR 格式）
支持的服务：cloudflare, google, facebook, telegram, netflix, twitter, github

可以从外部 API 下载 IP 的服务：
- github 的 IP 可以从 https://api.github.com/meta 获取
"""

import requests
import sys
import os
import ipaddress
from collections import defaultdict
import struct
import re
from requests.auth import HTTPBasicAuth
import time
from ftplib import FTP

def get_latest_release():
    """获取最新的 release 信息"""
    api_url = "https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/latest"
    
    try:
        print("正在获取最新 release 信息...")
        response = requests.get(api_url, timeout=30)
        response.raise_for_status()
        release_info = response.json()
        print(f"最新 release: {release_info['tag_name']}")
        print(f"发布时间: {release_info['published_at']}")
        return release_info
    except requests.exceptions.RequestException as e:
        print(f"获取 release 信息失败: {e}", file=sys.stderr)
        sys.exit(1)

def download_geoip_dat(release_info, output_dir="geo_ips", output_file="geoip.dat"):
    """下载 geoip.dat 文件"""
    # 创建下载目录
    os.makedirs(output_dir, exist_ok=True)
    
    # 查找 geoip.dat 文件
    geoip_asset = None
    for asset in release_info.get("assets", []):
        if asset["name"] == "geoip.dat":
            geoip_asset = asset
            break
    
    if not geoip_asset:
        print("错误: 未找到 geoip.dat 文件", file=sys.stderr)
        sys.exit(1)
    
    download_url = geoip_asset["browser_download_url"]
    file_size = geoip_asset["size"]
    
    # 完整的文件路径
    full_path = os.path.join(output_dir, output_file)
    
    print(f"\n找到 geoip.dat 文件")
    print(f"文件大小: {file_size / (1024*1024):.2f} MB")
    print(f"下载地址: {download_url}")
    
    # 检查文件是否已存在且大小相同
    if os.path.exists(full_path) and os.path.getsize(full_path) == file_size:
        print(f"文件已存在且大小相同，跳过下载")
        return full_path
    
    print(f"正在下载...")
    
    try:
        response = requests.get(download_url, timeout=120, stream=True)
        response.raise_for_status()
        
        total_size = 0
        with open(full_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    total_size += len(chunk)
                    if total_size % (1024 * 1024) == 0:  # 每 MB 显示一次
                        print(f"已下载: {total_size / (1024*1024):.2f} MB / {file_size / (1024*1024):.2f} MB", end='\r')
        
        print(f"\n下载完成!")
        print(f"保存为: {full_path}")
        return full_path
        
    except requests.exceptions.RequestException as e:
        print(f"下载失败: {e}", file=sys.stderr)
        sys.exit(1)

def parse_protobuf_geoip(data):
    """解析 Protobuf 格式的 geoip.dat"""
    # geoip.dat 使用 V2Ray 的 Protobuf 格式
    # 结构大致是: GeoIPList { entries: [GeoIP { country_code, cidr: [CIDR] }] }
    
    services = ['cloudflare', 'google', 'facebook', 'telegram', 'netflix', 'twitter', 'github']
    service_ips = defaultdict(set)
    
    print("\n正在解析 geoip.dat 文件...")
    print("使用改进的解析方法提取 IP 地址...")
    print()
    
    # 在文件中查找服务名称，然后解析相关的 IP 地址范围
    for service in services:
        # 对于 GitHub，查找多种可能的变体（包括部分匹配）
        if service == 'github':
            patterns = [
                b'github',
                b'GITHUB',
                b'GitHub',
                b'GITHUB1S',
                b'github.com',
                b'github.io',
                b'githubassets',
                b'githubapp',
            ]
        else:
            service_bytes = service.encode('utf-8')
            service_lower = service.lower()
            service_upper = service.upper()
            patterns = [service_bytes, service_lower.encode('utf-8'), service_upper.encode('utf-8')]
        
        # 查找所有可能的服务名称位置
        positions = []
        for pattern in patterns:
            pos = 0
            while True:
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                positions.append(pos)
                pos += 1
        
        # 去重位置（避免重复处理）
        positions = sorted(set(positions))
        
        print(f"  找到 '{service}' 相关关键字出现 {len(positions)} 次")
        
        # 在找到的位置附近查找 IP 地址
        found_ips = set()
        
        # 扩大搜索范围，查找更多 IP 地址
        for pos in positions:
            # 在服务名称前后更大范围内查找
            start = max(0, pos - 500)
            end = min(len(data), pos + 2000)
            
            # 方法1: 查找可能的 IPv4 地址（4字节）+ 前缀长度（1字节）
            for i in range(start, end - 5):
                try:
                    # 读取 4 字节作为 IP 地址
                    ip_bytes = data[i:i+4]
                    ip = ipaddress.IPv4Address(ip_bytes)
                    
                    # 排除无效地址
                    if str(ip) in ["0.0.0.0", "255.255.255.255"]:
                        continue
                    
                    # 检查是否是私有地址（这些服务通常不使用私有地址）
                    if ip.is_private or ip.is_multicast or ip.is_reserved:
                        continue
                    
                    # 尝试读取前缀长度
                    prefix_byte = data[i+4]
                    if 0 <= prefix_byte <= 32:
                        cidr = f"{ip}/{prefix_byte}"
                        found_ips.add(cidr)
                        continue
                    
                    # 如果没有有效的前缀，尝试其他可能的格式
                    # 可能是起始 IP + 结束 IP 的格式
                    if i + 8 <= len(data):
                        ip2_bytes = data[i+4:i+8]
                        try:
                            ip2 = ipaddress.IPv4Address(ip2_bytes)
                            # 如果第二个 IP 大于第一个，可能是 IP 范围
                            if ip2 > ip:
                                # 计算 CIDR
                                # 简化处理：使用起始 IP 和合理的前缀
                                # 这里使用 /24 作为默认值
                                cidr = f"{ip}/24"
                                found_ips.add(cidr)
                        except:
                            pass
                    
                    # 默认使用 /32（单个 IP）
                    found_ips.add(f"{ip}/32")
                except:
                    pass
            
            # 方法2: 查找可能的 CIDR 格式（IP + 前缀长度在不同位置）
            # 在 Protobuf 中，字段可能不是连续存储的
            for i in range(start, end - 4):
                try:
                    ip_bytes = data[i:i+4]
                    ip = ipaddress.IPv4Address(ip_bytes)
                    
                    if str(ip) in ["0.0.0.0", "255.255.255.255"]:
                        continue
                    if ip.is_private or ip.is_multicast or ip.is_reserved:
                        continue
                    
                    # 在附近查找可能的前缀长度
                    for j in range(max(start, i-10), min(end, i+20)):
                        if j != i and j + 1 <= len(data):
                            prefix_byte = data[j]
                            if 8 <= prefix_byte <= 32:  # 合理的前缀范围
                                # 检查这个前缀是否在 IP 附近
                                if abs(j - i) < 50:
                                    cidr = f"{ip}/{prefix_byte}"
                                    found_ips.add(cidr)
                except:
                    pass
        
        service_ips[service] = found_ips
        print(f"    提取到 {len(found_ips)} 个 IP 地址/CIDR")
    
    # 转换为列表格式
    return {k: list(v) for k, v in service_ips.items()}


def get_github_ips_from_api():
    """从 GitHub Meta API 获取 GitHub IP 地址范围"""
    print("\n从 GitHub Meta API 获取 IP 地址...")
    
    github_ips = []
    
    try:
        response = requests.get("https://api.github.com/meta", timeout=10)
        if response.status_code == 200:
            data = response.json()
            
            # GitHub Meta API 返回的字段包括：
            # - git: Git 操作相关的 IP
            # - hooks: Webhooks 相关的 IP
            # - web: Web 服务相关的 IP
            # - api: API 服务相关的 IP
            # - packages: Packages 相关的 IP
            # - pages: GitHub Pages 相关的 IP
            # - importer: 导入服务相关的 IP
            # - actions: GitHub Actions 相关的 IP
            # - dependabot: Dependabot 相关的 IP
            # - verifiable_password_authentication: 验证密码认证相关的 IP
            
            ip_fields = ['git', 'hooks', 'web', 'api', 'packages', 'pages', 
                        'importer', 'actions', 'dependabot', 'verifiable_password_authentication']
            
            for field in ip_fields:
                if field in data:
                    field_data = data[field]
                    # 确保 field_data 是列表
                    if isinstance(field_data, list):
                        for ip_range in field_data:
                            # 只处理 IPv4 地址
                            if isinstance(ip_range, str) and ':' not in ip_range:  # 排除 IPv6
                                try:
                                    # 验证 CIDR 格式
                                    ipaddress.ip_network(ip_range, strict=False)
                                    github_ips.append(ip_range)
                                except:
                                    pass
            
            print(f"  从 GitHub Meta API 获取到 {len(github_ips)} 个 IPv4 CIDR 段")
        else:
            print(f"  获取失败: HTTP {response.status_code}")
    except Exception as e:
        print(f"  获取失败: {e}")
    
    return github_ips


def merge_and_optimize_cidr(ip_list):
    """合并和优化 CIDR 列表"""
    if not ip_list:
        return []
    
    networks = []
    for cidr in ip_list:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            # 过滤无效的地址
            # 排除 0.0.0.0/0 和过大的网络
            if str(net) == "0.0.0.0/0":
                continue
            if net.prefixlen < 16:  # 排除前缀长度小于 16 的网络（太大，不够精确）
                continue
            # 排除私有地址（这些服务通常不使用）
            if net.is_private:
                continue
            # 排除多播和保留地址
            if net.is_multicast or net.is_reserved:
                continue
            networks.append(net)
        except:
            pass
    
    if not networks:
        return []
    
    # 去重
    unique_networks = list(set(networks))
    
    # 尝试合并相邻的网络（简化版）
    # 先按网络地址和前缀长度排序
    sorted_networks = sorted(unique_networks, key=lambda x: (x.network_address, x.prefixlen))
    
    # 转换为字符串
    return [str(net) for net in sorted_networks]

def save_results(service_ips, output_dir="."):
    """保存结果到文件"""
    print("\n" + "=" * 60)
    print("保存结果")
    print("=" * 60)
    
    for service, ip_list in service_ips.items():
        if not ip_list:
            print(f"\n{service}: 未找到 IP 地址")
            continue
        
        # 优化 CIDR 列表
        optimized = merge_and_optimize_cidr(ip_list)
        
        if not optimized:
            print(f"\n{service}: 没有有效的 IP 地址")
            continue
        
        filename = f"{output_dir}/{service}_ips.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            for cidr in optimized:
                f.write(f"{cidr}\n")
        
        print(f"\n{service}:")
        print(f"  原始数量: {len(ip_list)} 个")
        print(f"  优化后: {len(optimized)} 个 CIDR 段")
        print(f"  保存到: {filename}")
        print(f"  示例 (前10个):")
        for cidr in optimized[:10]:
            print(f"    {cidr}")
        if len(optimized) > 10:
            print(f"    ... 还有 {len(optimized) - 10} 个")

def parse_routeros_config(config_file="Corefile.routeros"):
    """从 Corefile.routeros 解析 RouterOS 登录和 FTP 信息"""
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        config = {
            'enabled': False,
            'ftp_enabled': False
        }
        
        # 解析配置行
        for line in content.split('\n'):
            line = line.strip()
            
            # 查找 routeros_login 配置行
            # 格式: routeros_login true 192.168.50.137:80 admin password
            if line.startswith('routeros_login'):
                parts = line.split()
                if len(parts) >= 5:
                    enabled = parts[1].lower() == 'true'
                    host = parts[2]
                    username = parts[3]
                    password = parts[4]
                    
                    if enabled:
                        # 确保 host 包含 http:// 或 https://
                        if not host.startswith('http://') and not host.startswith('https://'):
                            host = f'http://{host}'
                        
                        config['enabled'] = True
                        config['host'] = host
                        config['username'] = username
                        config['password'] = password
            
            # 查找 routeros_ftp 配置行
            # 格式: routeros_ftp true 192.168.50.137:21 admin password
            elif line.startswith('routeros_ftp'):
                parts = line.split()
                if len(parts) >= 5:
                    ftp_enabled = parts[1].lower() == 'true'
                    ftp_host = parts[2]
                    ftp_username = parts[3]
                    ftp_password = parts[4]
                    
                    if ftp_enabled:
                        config['ftp_enabled'] = True
                        config['ftp_host'] = ftp_host
                        config['ftp_username'] = ftp_username
                        config['ftp_password'] = ftp_password
        
        if not config['enabled'] and not config['ftp_enabled']:
            print("⚠️  Warning: RouterOS configuration not found or disabled in Corefile.routeros")
            return {'enabled': False, 'ftp_enabled': False}
        
        return config
    
    except FileNotFoundError:
        print(f"✗ Config file {config_file} not found")
        return {'enabled': False, 'ftp_enabled': False}
    except Exception as e:
        print(f"✗ Error parsing RouterOS config: {e}")
        return {'enabled': False, 'ftp_enabled': False}

def generate_routeros_script(service_files_map, download_dir="geo_ips", output_file="geoip_import.rsc"):
    """生成 RouterOS 脚本文件（自动去重）"""
    script_lines = []
    
    # 添加脚本头部注释
    script_lines.append("# Auto-generated GeoIP import script")
    script_lines.append("# Generated by fetch_geoip.py")
    script_lines.append("")
    
    # 清空地址列表
    script_lines.append("# Step 1: Clear existing address lists")
    script_lines.append('/ip firewall address-list remove [find list="gfw_geo_nf"]')
    script_lines.append('/ip firewall address-list remove [find list="gfw_geo_ips"]')
    script_lines.append("")
    
    # 添加地址列表条目
    script_lines.append("# Step 2: Import IP addresses")
    script_lines.append("")
    
    # 按 list_name 分组并去重
    list_ips = {}  # {list_name: set(ip)}
    file_counts = {}  # {filename: count}
    
    for filename, list_name in service_files_map.items():
        filepath = os.path.join(download_dir, filename)
        
        if not os.path.exists(filepath):
            continue
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                cidr_list = [line.strip() for line in f if line.strip()]
            
            if not cidr_list:
                continue
            
            file_counts[filename] = len(cidr_list)
            
            # 添加到对应的 list 中（自动去重）
            if list_name not in list_ips:
                list_ips[list_name] = set()
            
            list_ips[list_name].update(cidr_list)
            
        except Exception as e:
            print(f"  Error processing {filename}: {e}")
    
    # 生成脚本
    total_entries = 0
    total_before_dedup = sum(file_counts.values())
    
    for list_name, ip_set in sorted(list_ips.items()):
        ip_list = sorted(ip_set)  # 排序以保持一致性
        script_lines.append(f"# List '{list_name}' ({len(ip_list)} unique IPs)")
        
        for cidr in ip_list:
            script_lines.append(f'/ip firewall address-list add list={list_name} address={cidr} comment="Auto-imported from geoip"')
            total_entries += 1
        
        script_lines.append("")
    
    # 写入脚本文件
    script_path = os.path.join(download_dir, output_file)
    with open(script_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(script_lines))
    
    # 打印统计信息
    print(f"  Files processed: {len(file_counts)}")
    for filename, count in file_counts.items():
        print(f"    {filename}: {count} entries")
    print(f"  Total before deduplication: {total_before_dedup}")
    print(f"  Total after deduplication: {total_entries}")
    print(f"  Duplicates removed: {total_before_dedup - total_entries}")
    
    return script_path, total_entries

def upload_file_to_routeros(config, local_file, remote_filename):
    """通过 FTP 上传文件到 RouterOS"""
    # 检查是否启用了 FTP
    if not config.get('ftp_enabled'):
        print(f"  ⚠️  Warning: routeros_ftp is not configured or disabled")
        print(f"  → Trying to extract FTP host from routeros_login (REST API) configuration...")
        
        # 回退到从 REST API host 提取
        if not config.get('enabled'):
            print(f"  ✗ Neither routeros_ftp nor routeros_login is enabled")
            print(f"  → Please configure routeros_ftp in Corefile.routeros:")
            print(f"     routeros_ftp true <host>:<port> <username> <password>")
            return False
        
        host = config['host'].replace('http://', '').replace('https://', '')
        if ':' in host:
            host = host.split(':')[0]
        username = config.get('username')
        password = config.get('password')
        ftp_port = 21
        print(f"  → Using REST API host: {host}, default FTP port: {ftp_port}")
    else:
        # 使用 FTP 配置
        ftp_host = config.get('ftp_host', '')
        username = config.get('ftp_username')
        password = config.get('ftp_password')
        
        # 解析 FTP host 和端口
        if ':' in ftp_host:
            host, port_str = ftp_host.split(':')
            ftp_port = int(port_str)
            print(f"  → Using routeros_ftp configuration: {host}:{ftp_port}")
        else:
            host = ftp_host
            ftp_port = 21
            print(f"  → Using routeros_ftp configuration: {host} (default port 21)")
    
    try:
        print(f"  Connecting to FTP server {host}:{ftp_port}...")
        
        # 连接到 RouterOS FTP
        ftp = FTP()
        ftp.connect(host, ftp_port, timeout=30)
        ftp.login(username, password)
        
        print(f"  Uploading {local_file} as {remote_filename}...")
        
        # 上传文件
        with open(local_file, 'rb') as f:
            ftp.storbinary(f'STOR {remote_filename}', f)
        
        ftp.quit()
        print(f"  ✓ File uploaded successfully")
        return True
        
    except ConnectionRefusedError as e:
        print(f"  ✗ Connection refused: {e}")
        print(f"  → Please check:")
        print(f"     1. FTP service is running on {host}:{ftp_port}")
        print(f"     2. Firewall allows FTP connections")
        print(f"     3. Host address {host} is correct")
        print(f"     4. routeros_ftp configuration in Corefile.routeros:")
        print(f"        routeros_ftp true {host}:{ftp_port} <username> <password>")
        return False
    except Exception as e:
        print(f"  ✗ Error uploading file: {e}")
        print(f"  → Please verify:")
        print(f"     1. FTP host: {host}:{ftp_port}")
        print(f"     2. Username/Password are correct")
        print(f"     3. FTP service is accessible")
        return False

def execute_routeros_script(config, script_filename):
    """通过 REST API 执行 RouterOS 脚本"""
    try:
        # RouterOS REST API 执行脚本命令
        url = f"{config['host']}/rest/system/script/run"
        auth = HTTPBasicAuth(config['username'], config['password'])
        
        # 方法1: 尝试通过 REST API 直接执行 import 命令
        import_url = f"{config['host']}/rest/import"
        
        print(f"  Executing script: import {script_filename}")
        
        # 尝试使用系统命令执行
        exec_url = f"{config['host']}/rest/system/script"
        
        # 创建一个临时脚本来执行 import
        script_data = {
            'name': 'temp_geoip_import',
            'source': f'/import {script_filename}'
        }
        
        # 先删除可能存在的旧脚本
        try:
            response = requests.get(exec_url, auth=auth, timeout=10)
            if response.status_code == 200:
                scripts = response.json()
                for script in scripts:
                    if script.get('name') == 'temp_geoip_import':
                        script_id = script.get('.id')
                        requests.delete(f"{exec_url}/{script_id}", auth=auth, timeout=10)
        except:
            pass
        
        # 创建新脚本
        response = requests.put(exec_url, json=script_data, auth=auth, timeout=10)
        
        if response.status_code not in [200, 201]:
            print(f"  Warning: Could not create script: {response.status_code}")
            print(f"  Please manually run: /import {script_filename}")
            return False
        
        # 获取脚本 ID
        script_id = response.json().get('.id')
        
        # 执行脚本
        run_url = f"{exec_url}/run"
        run_data = {'.id': script_id}
        
        print(f"  Running import script...")
        response = requests.post(run_url, json=run_data, auth=auth, timeout=300)
        
        if response.status_code in [200, 201]:
            print(f"  ✓ Script executed successfully")
            
            # 清理临时脚本
            try:
                requests.delete(f"{exec_url}/{script_id}", auth=auth, timeout=10)
            except:
                pass
            
            return True
        else:
            print(f"  Warning: Script execution returned: {response.status_code}")
            print(f"  Response: {response.text[:200]}")
            print(f"  Please manually run: /import {script_filename}")
            return False
        
    except Exception as e:
        print(f"  Error executing script: {e}")
        print(f"  Please manually run: /import {script_filename}")
        return False

def sync_to_routeros(download_dir="geo_ips", config_file="Corefile.routeros"):
    """将下载的 IP 地址同步到 RouterOS"""
    print("\n" + "=" * 60)
    print("Syncing to RouterOS")
    print("=" * 60)
    
    # 解析 RouterOS 配置
    config = parse_routeros_config(config_file)
    
    if not config.get('enabled') and not config.get('ftp_enabled'):
        print("RouterOS sync is disabled or configuration not found")
        print()
        print("Please configure in Corefile.routeros:")
        print("  routeros_login true <host>:<port> <user> <password>  # For REST API")
        print("  routeros_ftp   true <host>:<port> <user> <password>  # For FTP upload")
        return
    
    # 显示配置信息
    print("Configuration loaded:")
    if config.get('enabled'):
        print(f"  ✓ REST API: {config['host']} (user: {config['username']})")
    else:
        print(f"  ✗ REST API: Not configured")
    
    if config.get('ftp_enabled'):
        print(f"  ✓ FTP: {config['ftp_host']} (user: {config['ftp_username']})")
    else:
        print(f"  ⚠️  FTP: Not configured (will try to use REST API host)")
    
    print()
    
    # 定义服务到地址列表的映射
    service_files = {
        'netflix_ips.txt': 'gfw_geo_nf',
        'cloudflare_ips.txt': 'gfw_geo_ips',
        'google_ips.txt': 'gfw_geo_ips',
        'facebook_ips.txt': 'gfw_geo_ips',
        'telegram_ips.txt': 'gfw_geo_ips',
        'twitter_ips.txt': 'gfw_geo_ips',
        'github_ips.txt': 'gfw_geo_ips'
    }
    
    # Step 1: 生成 RouterOS 脚本
    print("Step 1: Generating RouterOS script...")
    script_file = "geoip_import.rsc"
    script_path, total_entries = generate_routeros_script(service_files, download_dir, script_file)
    print(f"  ✓ Generated script with {total_entries} entries")
    print(f"  ✓ Script saved to: {script_path}")
    print()
    
    # Step 2: 上传脚本到 RouterOS
    print("Step 2: Uploading script to RouterOS via FTP...")
    if not upload_file_to_routeros(config, script_path, script_file):
        print("\n✗ Failed to upload script")
        print(f"Please manually upload {script_path} to RouterOS and run: /import {script_file}")
        return
    print()
    
    # Step 3: 执行脚本
    print("Step 3: Executing script on RouterOS...")
    print("  Note: This may take several minutes depending on the number of entries...")
    if not execute_routeros_script(config, script_file):
        print("\n✗ Script execution may have failed or needs manual intervention")
        print(f"Please manually run on RouterOS: /import {script_file}")
    
    print("\n" + "=" * 60)
    print("RouterOS sync completed!")
    print("=" * 60)
    print(f"\nScript file generated: {script_path}")
    print(f"Total entries: {total_entries}")
    print(f"\nIf automatic import failed, you can manually:")
    print(f"1. Upload {script_path} to RouterOS via FTP")
    print(f"2. Run on RouterOS: /import {script_file}")

def main():
    """主函数"""
    services = ['cloudflare', 'google', 'facebook', 'telegram', 'netflix', 'twitter', 'github']
    download_dir = "geo_ips"
    
    print("=" * 60)
    print("从 GitHub releases 下载 geoip.dat 并提取服务 IP")
    print("=" * 60)
    print()
    
    # 创建下载目录
    os.makedirs(download_dir, exist_ok=True)
    
    # 获取最新 release
    release_info = get_latest_release()
    
    # 下载 geoip.dat
    geoip_file = download_geoip_dat(release_info, output_dir=download_dir)
    
    # 读取文件
    print(f"\n正在读取文件: {geoip_file}")
    with open(geoip_file, 'rb') as f:
        geoip_data = f.read()
    
    print(f"文件大小: {len(geoip_data) / (1024*1024):.2f} MB")
    
    # 从 geoip.dat 解析提取 IP 地址
    print("\n" + "=" * 60)
    print("从 geoip.dat 解析提取 IP 地址")
    print("=" * 60)
    service_ips = parse_protobuf_geoip(geoip_data)
    
    # 保存结果到 geo_ips 目录
    save_results(service_ips, output_dir=download_dir)
    
    # 对于 GitHub，从外部 API 获取 IP（作为补充或替代）
    if 'github' in services:
        if not service_ips.get('github') or len(service_ips.get('github', [])) == 0:
            print("\n" + "=" * 60)
            print("GitHub IP 从外部 API 获取")
            print("=" * 60)
            github_ips = get_github_ips_from_api()
            if github_ips:
                service_ips['github'] = github_ips
                # 重新保存 GitHub IP
                optimized = merge_and_optimize_cidr(github_ips)
                if optimized:
                    filename = f"{download_dir}/github_ips.txt"
                    with open(filename, 'w', encoding='utf-8') as f:
                        for cidr in optimized:
                            f.write(f"{cidr}\n")
                    print(f"\ngithub:")
                    print(f"  原始数量: {len(github_ips)} 个")
                    print(f"  优化后: {len(optimized)} 个 CIDR 段")
                    print(f"  保存到: {filename}")
    
    # 同步到 RouterOS
    sync_to_routeros(download_dir=download_dir, config_file="Corefile.routeros")
    
    print("\n" + "=" * 60)
    print("完成!")
    print("=" * 60)

if __name__ == '__main__':
    main()

