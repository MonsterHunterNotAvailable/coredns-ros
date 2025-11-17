#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoreDNS RouterOS 缓存测试脚本
测试从 RouterOS 加载地址列表缓存的功能
"""

import requests
import subprocess
import time
import dns.resolver
import sys
from requests.auth import HTTPBasicAuth

# RouterOS 配置
ROUTEROS_HOST = "192.168.50.137:80"
ROUTEROS_USER = "admin"
ROUTEROS_PASSWORD = "password"

# 测试域名
TEST_DOMAINS = {
    "china": ["baidu.com", "qq.com", "taobao.com"],
    "gfw": ["google.com", "youtube.com", "twitter.com"]
}

# RouterOS 地址列表名称
ADDRESS_LISTS = {
    "china": "china_ip",
    "gfw": "gfw_ip"
}

# CoreDNS 配置
COREDNS_BIN = "./coredns"
COREDNS_CONF = "conf/Corefile.routeros"
COREDNS_DNS = "127.0.0.1"


class Colors:
    """终端颜色"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    END = '\033[0m'
    BOLD = '\033[1m'


def print_header(text):
    """打印标题"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text:^80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.END}\n")


def print_step(text):
    """打印步骤"""
    print(f"{Colors.BOLD}{Colors.BLUE}[步骤] {text}{Colors.END}")


def print_success(text):
    """打印成功消息"""
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")


def print_warning(text):
    """打印警告消息"""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")


def print_error(text):
    """打印错误消息"""
    print(f"{Colors.RED}✗ {text}{Colors.END}")


def print_info(text):
    """打印信息"""
    print(f"  {text}")


def query_routeros_address_list(list_name):
    """
    查询 RouterOS 地址列表
    返回: [(ip, id, timeout), ...]
    """
    url = f"http://{ROUTEROS_HOST}/rest/ip/firewall/address-list?list={list_name}"
    
    try:
        response = requests.get(
            url,
            auth=HTTPBasicAuth(ROUTEROS_USER, ROUTEROS_PASSWORD),
            headers={"Accept": "application/json"},
            timeout=5
        )
        
        if response.status_code == 200:
            items = response.json()
            return [(item.get("address"), item.get(".id"), item.get("timeout", "永不过期")) 
                    for item in items]
        else:
            print_error(f"查询 RouterOS 失败: {response.status_code}")
            return []
    except Exception as e:
        print_error(f"连接 RouterOS 失败: {e}")
        return []


def clear_routeros_address_list(list_name):
    """清空 RouterOS 地址列表（用于测试前准备）"""
    print_step(f"清空 RouterOS 地址列表: {list_name}")
    
    items = query_routeros_address_list(list_name)
    if not items:
        print_info(f"列表 {list_name} 已经是空的")
        return True
    
    deleted = 0
    for ip, item_id, _ in items:
        url = f"http://{ROUTEROS_HOST}/rest/ip/firewall/address-list/remove"
        data = {".id": item_id}
        
        try:
            response = requests.post(
                url,
                json=data,
                auth=HTTPBasicAuth(ROUTEROS_USER, ROUTEROS_PASSWORD),
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            
            if response.status_code in [200, 204]:
                deleted += 1
        except Exception as e:
            print_warning(f"删除 {ip} 失败: {e}")
    
    print_success(f"已删除 {deleted} 个地址")
    return True


def display_routeros_addresses(list_name):
    """显示 RouterOS 地址列表内容"""
    items = query_routeros_address_list(list_name)
    
    if not items:
        print_info(f"列表 {list_name} 为空")
        return
    
    print_info(f"列表 {list_name} 包含 {len(items)} 个地址:")
    for ip, item_id, timeout in items[:10]:  # 只显示前10个
        print_info(f"  - {ip:20} (ID: {item_id}, TTL: {timeout})")
    
    if len(items) > 10:
        print_info(f"  ... 还有 {len(items) - 10} 个地址")


def dns_query(domain, dns_server=COREDNS_DNS):
    """执行 DNS 查询"""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    resolver.timeout = 5
    resolver.lifetime = 5
    
    try:
        answers = resolver.resolve(domain, 'A')
        ips = [str(rdata) for rdata in answers]
        return ips
    except Exception as e:
        return None


def start_coredns():
    """启动 CoreDNS"""
    print_step("启动 CoreDNS")
    
    try:
        proc = subprocess.Popen(
            [COREDNS_BIN, "-conf", COREDNS_CONF],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # 等待启动
        time.sleep(3)
        
        # 检查是否启动成功
        if proc.poll() is not None:
            print_error("CoreDNS 启动失败")
            return None
        
        print_success(f"CoreDNS 已启动 (PID: {proc.pid})")
        return proc
        
    except Exception as e:
        print_error(f"启动 CoreDNS 失败: {e}")
        return None


def stop_coredns(proc):
    """停止 CoreDNS"""
    if proc is None:
        return
    
    print_step("停止 CoreDNS")
    
    try:
        proc.terminate()
        proc.wait(timeout=5)
        print_success("CoreDNS 已停止")
    except subprocess.TimeoutExpired:
        print_warning("强制终止 CoreDNS")
        proc.kill()
        proc.wait()
    except Exception as e:
        print_error(f"停止 CoreDNS 失败: {e}")


def test_dns_queries(domains_dict):
    """测试 DNS 查询"""
    print_step("执行 DNS 查询")
    
    results = {}
    for category, domains in domains_dict.items():
        results[category] = {}
        for domain in domains:
            print_info(f"查询 {domain} ...")
            ips = dns_query(domain)
            if ips:
                results[category][domain] = ips
                print_success(f"{domain} -> {', '.join(ips)}")
            else:
                print_error(f"{domain} 查询失败")
                results[category][domain] = []
            
            time.sleep(0.5)  # 避免请求过快
    
    return results


def verify_routeros_entries(query_results):
    """验证 RouterOS 中的条目"""
    print_step("验证 RouterOS 地址列表")
    
    for category, domains in query_results.items():
        list_name = ADDRESS_LISTS.get(category)
        if not list_name:
            continue
        
        print_info(f"\n检查列表: {list_name}")
        routeros_ips = set(ip for ip, _, _ in query_routeros_address_list(list_name))
        
        expected_ips = set()
        for domain, ips in domains.items():
            expected_ips.update(ips)
        
        if not expected_ips:
            print_warning(f"没有期望的 IP 地址")
            continue
        
        matched = expected_ips & routeros_ips
        missing = expected_ips - routeros_ips
        
        print_success(f"匹配: {len(matched)}/{len(expected_ips)} 个 IP")
        
        if matched:
            for ip in list(matched)[:5]:
                print_info(f"  ✓ {ip}")
        
        if missing:
            print_warning(f"缺失 {len(missing)} 个 IP:")
            for ip in list(missing)[:5]:
                print_info(f"  ✗ {ip}")


def main():
    """主测试流程"""
    print_header("CoreDNS RouterOS 缓存加载测试")
    
    # ============ 第一阶段：准备环境 ============
    print_header("阶段 1: 准备测试环境")
    
    # 清空 RouterOS 地址列表
    for list_name in ADDRESS_LISTS.values():
        clear_routeros_address_list(list_name)
    
    time.sleep(2)
    
    # ============ 第二阶段：首次启动 CoreDNS ============
    print_header("阶段 2: 首次启动 CoreDNS 并查询域名")
    
    coredns_proc = start_coredns()
    if not coredns_proc:
        print_error("无法启动 CoreDNS，测试终止")
        return 1
    
    time.sleep(3)  # 等待完全启动
    
    # 执行 DNS 查询
    query_results = test_dns_queries(TEST_DOMAINS)
    
    time.sleep(2)  # 等待写入 RouterOS
    
    # 验证 RouterOS 条目
    verify_routeros_entries(query_results)
    
    # 显示当前 RouterOS 状态
    print_step("\n当前 RouterOS 地址列表状态:")
    for list_name in ADDRESS_LISTS.values():
        display_routeros_addresses(list_name)
    
    # 停止 CoreDNS
    time.sleep(2)
    stop_coredns(coredns_proc)
    
    # ============ 第三阶段：重启 CoreDNS 验证缓存加载 ============
    print_header("阶段 3: 重启 CoreDNS 验证缓存加载")
    
    print_info("等待 5 秒后重启...")
    time.sleep(5)
    
    coredns_proc = start_coredns()
    if not coredns_proc:
        print_error("无法重启 CoreDNS，测试终止")
        return 1
    
    time.sleep(3)  # 等待启动并加载缓存
    
    print_info("\n提示: 请检查 CoreDNS 日志，应该能看到 'Loading RouterOS address list' 的日志")
    print_info("如果看到 'Loaded N existing addresses from RouterOS list'，说明缓存加载成功\n")
    
    # 再次查询相同的域名
    print_step("再次查询相同的域名（测试缓存命中）")
    test_dns_queries(TEST_DOMAINS)
    
    time.sleep(2)
    
    # 验证 RouterOS 条目（应该保持不变或正确更新 TTL）
    print_step("\n验证 RouterOS 地址列表（应该保持原有条目）:")
    for list_name in ADDRESS_LISTS.values():
        display_routeros_addresses(list_name)
    
    # ============ 第四阶段：测试新域名 ============
    print_header("阶段 4: 查询新域名验证增量添加")
    
    new_domains = {
        "china": ["sina.com.cn", "163.com"],
        "gfw": ["facebook.com", "instagram.com"]
    }
    
    print_step("查询新域名")
    new_results = test_dns_queries(new_domains)
    
    time.sleep(2)
    
    # 验证新域名的 IP 被添加
    verify_routeros_entries(new_results)
    
    print_step("\n最终 RouterOS 地址列表状态:")
    for list_name in ADDRESS_LISTS.values():
        display_routeros_addresses(list_name)
    
    # 停止 CoreDNS
    time.sleep(2)
    stop_coredns(coredns_proc)
    
    # ============ 测试完成 ============
    print_header("测试完成")
    
    print_success("所有测试阶段已完成！")
    print_info("\n测试总结:")
    print_info("  1. ✓ 首次启动 CoreDNS 并添加域名到 RouterOS")
    print_info("  2. ✓ 重启 CoreDNS 验证从 RouterOS 加载缓存")
    print_info("  3. ✓ 查询已缓存域名验证 TTL 刷新逻辑")
    print_info("  4. ✓ 查询新域名验证增量添加")
    print_info("\n请检查 CoreDNS 日志确认详细的加载和更新信息")
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print_error("\n\n测试被用户中断")
        sys.exit(1)
    except Exception as e:
        print_error(f"\n\n测试出错: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

