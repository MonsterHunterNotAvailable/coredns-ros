#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoreDNS 与 RouterOS 缓存对比测试脚本
多轮测试，详细比对 CoreDNS 内存缓存和 RouterOS 地址表的内容
"""

import requests
import subprocess
import time
import dns.resolver
import sys
from requests.auth import HTTPBasicAuth
from collections import defaultdict

# RouterOS 配置
ROUTEROS_HOST = "192.168.50.137:80"
ROUTEROS_USER = "admin"
ROUTEROS_PASSWORD = "password"

# CoreDNS 配置
COREDNS_BIN = "./coredns"
COREDNS_CONF = "conf/Corefile.routeros"
COREDNS_DNS = "127.0.0.1"
COREDNS_API = "http://127.0.0.1:8182"

# RouterOS 地址列表名称
ADDRESS_LISTS = {
    "china": "china_ip",
    "gfw": "gfw_ip"
}

# 测试域名（多轮）
TEST_ROUNDS = [
    {
        "name": "第1轮：初始域名集合",
        "domains": {
            "china": ["baidu.com", "qq.com"],
            "gfw": ["google.com", "youtube.com"]
        }
    },
    {
        "name": "第2轮：部分重复 + 新域名",
        "domains": {
            "china": ["baidu.com", "taobao.com", "sina.com.cn"],  # baidu.com 重复
            "gfw": ["google.com", "twitter.com", "facebook.com"]  # google.com 重复
        }
    },
    {
        "name": "第3轮：全新域名集合",
        "domains": {
            "china": ["163.com", "sohu.com", "jd.com"],
            "gfw": ["instagram.com", "reddit.com"]
        }
    },
    {
        "name": "第4轮：再次查询旧域名（验证缓存）",
        "domains": {
            "china": ["baidu.com", "qq.com", "taobao.com"],  # 全部重复
            "gfw": ["google.com", "youtube.com", "twitter.com"]  # 全部重复
        }
    }
]


class Colors:
    """终端颜色"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    END = '\033[0m'
    BOLD = '\033[1m'


def print_header(text):
    """打印标题"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text:^80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.END}\n")


def print_section(text):
    """打印章节"""
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'─' * 80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}▶ {text}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}{'─' * 80}{Colors.END}")


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
    返回: {ip: {"id": id, "timeout": timeout}, ...}
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
            result = {}
            for item in items:
                result[item.get("address")] = {
                    "id": item.get(".id"),
                    "timeout": item.get("timeout", "永不过期"),
                    "comment": item.get("comment", "")
                }
            return result
        else:
            print_error(f"查询 RouterOS 失败: {response.status_code}")
            return {}
    except Exception as e:
        print_error(f"连接 RouterOS 失败: {e}")
        return {}


def query_coredns_cache():
    """
    查询 CoreDNS 内存缓存
    返回: {list_name: {ip: {"id": id, "expires_at": ..., "remaining": ...}, ...}, ...}
    """
    url = f"{COREDNS_API}/cache"
    
    try:
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            cache = data.get("cache", {})
            
            result = {}
            for list_name, list_data in cache.items():
                result[list_name] = {}
                for entry in list_data.get("entries", []):
                    ip = entry.get("ip")
                    result[list_name][ip] = {
                        "id": entry.get("id"),
                        "expires_at": entry.get("expires_at"),
                        "remaining": entry.get("remaining"),
                        "status": entry.get("status")
                    }
            
            return result
        else:
            print_error(f"查询 CoreDNS 缓存失败: {response.status_code}")
            return {}
    except Exception as e:
        print_error(f"连接 CoreDNS API 失败: {e}")
        return {}


def clear_routeros_address_list(list_name):
    """清空 RouterOS 地址列表"""
    items = query_routeros_address_list(list_name)
    if not items:
        return True
    
    deleted = 0
    for ip, info in items.items():
        url = f"http://{ROUTEROS_HOST}/rest/ip/firewall/address-list/remove"
        data = {".id": info["id"]}
        
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
    
    return deleted


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
        return []


def start_coredns():
    """启动 CoreDNS"""
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
            return None
        
        return proc
        
    except Exception as e:
        print_error(f"启动 CoreDNS 失败: {e}")
        return None


def stop_coredns(proc):
    """停止 CoreDNS"""
    if proc is None:
        return
    
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    except Exception as e:
        print_error(f"停止 CoreDNS 失败: {e}")


def execute_dns_queries(domains_dict):
    """执行 DNS 查询并返回结果"""
    results = {}
    for category, domains in domains_dict.items():
        results[category] = {}
        for domain in domains:
            ips = dns_query(domain)
            results[category][domain] = ips
            if ips:
                print_info(f"{domain:20} -> {', '.join(ips[:3])}{'...' if len(ips) > 3 else ''}")
            time.sleep(0.3)
    
    return results


def compare_cache_and_routeros():
    """比对 CoreDNS 缓存和 RouterOS 地址表"""
    print_section("数据比对：CoreDNS 缓存 vs RouterOS 地址表")
    
    # 查询 CoreDNS 缓存
    print_info("正在查询 CoreDNS 缓存...")
    coredns_cache = query_coredns_cache()
    print_info(f"✓ CoreDNS 缓存查询完成")
    
    # 查询 RouterOS 地址表
    print_info("正在查询 RouterOS 地址表...")
    routeros_data = {}
    for category, list_name in ADDRESS_LISTS.items():
        routeros_data[list_name] = query_routeros_address_list(list_name)
    print_info(f"✓ RouterOS 地址表查询完成")
    
    # 比对每个地址列表
    total_match = 0
    total_only_coredns = 0
    total_only_routeros = 0
    
    for list_name in ADDRESS_LISTS.values():
        print(f"\n{Colors.BOLD}地址列表: {list_name}{Colors.END}")
        
        coredns_ips = set(coredns_cache.get(list_name, {}).keys())
        routeros_ips = set(routeros_data.get(list_name, {}).keys())
        
        match = coredns_ips & routeros_ips
        only_coredns = coredns_ips - routeros_ips
        only_routeros = routeros_ips - coredns_ips
        
        total_match += len(match)
        total_only_coredns += len(only_coredns)
        total_only_routeros += len(only_routeros)
        
        print_info(f"CoreDNS 缓存: {len(coredns_ips)} 个IP")
        print_info(f"RouterOS 表: {len(routeros_ips)} 个IP")
        
        if len(match) > 0:
            print_success(f"匹配: {len(match)} 个IP")
            # 显示前5个匹配的 IP 及其详细信息
            for ip in list(match)[:5]:
                coredns_info = coredns_cache[list_name][ip]
                routeros_info = routeros_data[list_name][ip]
                print_info(f"  ✓ {ip:18} | CoreDNS: {coredns_info['remaining']:15} | RouterOS: {routeros_info['timeout']}")
            
            if len(match) > 5:
                print_info(f"  ... 还有 {len(match) - 5} 个匹配")
        
        if len(only_coredns) > 0:
            print_warning(f"仅在 CoreDNS: {len(only_coredns)} 个IP")
            for ip in list(only_coredns)[:3]:
                print_info(f"  ! {ip}")
        
        if len(only_routeros) > 0:
            print_warning(f"仅在 RouterOS: {len(only_routeros)} 个IP")
            for ip in list(only_routeros)[:3]:
                print_info(f"  ! {ip}")
    
    # 总体统计
    print(f"\n{Colors.BOLD}总体统计:{Colors.END}")
    print_success(f"匹配: {total_match} 个IP")
    if total_only_coredns > 0:
        print_warning(f"仅在 CoreDNS: {total_only_coredns} 个IP")
    if total_only_routeros > 0:
        print_warning(f"仅在 RouterOS: {total_only_routeros} 个IP")
    
    # 判断是否一致
    if total_only_coredns == 0 and total_only_routeros == 0:
        print_success("✓✓✓ 数据完全一致！")
        return True
    else:
        print_warning("⚠⚠⚠ 数据存在差异")
        return False


def main():
    """主测试流程"""
    print_header("CoreDNS 与 RouterOS 缓存对比测试（3次大循环）")
    
    # ============ 初始化：仅清空一次 ============
    print_header("初始化: 准备测试环境（仅执行一次）")
    
    print_step("清空 RouterOS 地址列表")
    for list_name in ADDRESS_LISTS.values():
        deleted = clear_routeros_address_list(list_name)
        if deleted:
            print_success(f"清空 {list_name}: 删除 {deleted} 个地址")
        else:
            print_info(f"{list_name} 已经是空的")
    
    print_success("✓ 初始化完成，RouterOS 地址列表已清空")
    time.sleep(2)
    
    # ============ 大循环：重复 3 次完整测试 ============
    BIG_LOOP_COUNT = 3
    
    for big_loop in range(1, BIG_LOOP_COUNT + 1):
        print_header(f"═══════════════ 大循环 {big_loop}/{BIG_LOOP_COUNT} 开始 ═══════════════")
        print_info(f"本次测试将在现有 RouterOS 数据基础上继续添加/刷新")
        time.sleep(1)
        
        # ============ 启动 CoreDNS ============
        print_header(f"[循环{big_loop}] 阶段 1: 启动 CoreDNS")
        
        coredns_proc = start_coredns()
        if not coredns_proc:
            print_error("无法启动 CoreDNS，测试终止")
            return 1
        
        print_success(f"CoreDNS 已启动 (PID: {coredns_proc.pid})")
        time.sleep(3)
        
        # ============ 4轮 DNS 查询测试 ============
        for round_idx, test_round in enumerate(TEST_ROUNDS, 1):
            print_header(f"[循环{big_loop}] 阶段 {round_idx + 1}: {test_round['name']}")
            print_info(f"进度: 大循环 {big_loop}/{BIG_LOOP_COUNT} - DNS查询 {round_idx}/{len(TEST_ROUNDS)}")
            
            print_step("执行 DNS 查询")
            query_results = execute_dns_queries(test_round['domains'])
            
            # 统计查询到的 IP 数量
            total_ips = sum(len(ips) for domains in query_results.values() for ips in domains.values())
            print_success(f"本轮查询到 {total_ips} 个IP")
            
            print_info("等待 2 秒让 RouterOS 完成写入...")
            time.sleep(2)
            
            # 比对数据
            print_step("开始数据比对...")
            compare_cache_and_routeros()
            
            # 如果不是最后一轮，等待一下
            if round_idx < len(TEST_ROUNDS):
                print_info("\n等待 3 秒进入下一轮...")
                time.sleep(3)
        
        # ============ 重启测试 ============
        print_header(f"[循环{big_loop}] 阶段 6: 重启 CoreDNS 验证缓存持久化")
        print_info(f"进度: 大循环 {big_loop}/{BIG_LOOP_COUNT} - 准备重启测试")
        
        print_step("停止 CoreDNS")
        stop_coredns(coredns_proc)
        print_success("CoreDNS 已停止")
        
        print_info("等待 5 秒后重启...")
        for i in range(5, 0, -1):
            print_info(f"  倒计时: {i} 秒...")
            time.sleep(1)
        
        print_step("重新启动 CoreDNS")
        coredns_proc = start_coredns()
        if not coredns_proc:
            print_error("无法重启 CoreDNS，测试终止")
            return 1
        
        print_success(f"CoreDNS 已重启 (PID: {coredns_proc.pid})")
        print_info("提示: 查看日志确认从 RouterOS 加载了地址列表")
        print_info("等待 CoreDNS 完成缓存加载...")
        time.sleep(3)
        
        # 重启后立即比对
        print_step("重启后立即比对数据（验证缓存加载）")
        compare_cache_and_routeros()
        
        # ============ 再次查询测试 ============
        print_header(f"[循环{big_loop}] 阶段 7: 重启后查询相同域名（验证缓存加载）")
        print_info(f"进度: 大循环 {big_loop}/{BIG_LOOP_COUNT} - 重启后查询验证")
        
        print_step("查询之前测试过的域名")
        test_domains = {
            "china": ["baidu.com", "taobao.com"],
            "gfw": ["google.com", "twitter.com"]
        }
        execute_dns_queries(test_domains)
        
        print_info("等待 2 秒...")
        time.sleep(2)
        
        # 最终比对
        print_step("最终数据比对")
        compare_cache_and_routeros()
        
        # ============ 清理 ============
        print_step("\n停止 CoreDNS")
        stop_coredns(coredns_proc)
        print_success("CoreDNS 已停止")
        
        # ============ 本次大循环完成 ============
        print_header(f"═══════════════ 大循环 {big_loop}/{BIG_LOOP_COUNT} 完成 ═══════════════")
        print_success(f"✓ 第 {big_loop} 次大循环测试完成")
        print_info(f"已完成: {big_loop}/{BIG_LOOP_COUNT} 次大循环")
        
        # 如果不是最后一次大循环，等待后继续
        if big_loop < BIG_LOOP_COUNT:
            print_info(f"\n准备开始第 {big_loop + 1} 次大循环...")
            print_info(f"注意: RouterOS 数据不会清空，将在现有基础上继续测试")
            print_info("等待 10 秒...")
            for i in range(10, 0, -1):
                print_info(f"  倒计时: {i} 秒...")
                time.sleep(1)
    
    # ============ 所有测试完成 ============
    print_header("🎉🎉🎉 全部测试完成 🎉🎉🎉")
    
    print_success(f"完成了 {BIG_LOOP_COUNT} 次完整的大循环测试！")
    print_info("\n测试摘要:")
    print_info(f"  - 大循环次数: {BIG_LOOP_COUNT} 次")
    print_info(f"  - 每次大循环包含: {len(TEST_ROUNDS)} 轮 DNS 查询 + 1 轮重启验证")
    print_info(f"  - 总共执行 DNS 查询: {BIG_LOOP_COUNT * len(TEST_ROUNDS)} 轮")
    print_info(f"  - 总共重启 CoreDNS: {BIG_LOOP_COUNT} 次")
    print_info(f"  - 验证了缓存加载、TTL 刷新、增量添加、重启恢复等功能")
    print_info("\n请查看上述比对结果确认数据一致性")
    
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

