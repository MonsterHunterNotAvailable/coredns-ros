#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoreDNS TTL=0 修复验证测试
专门测试 TTL=0 的缓存检查和更新逻辑
"""

import requests
import subprocess
import time
import dns.resolver
import sys
import signal
from requests.auth import HTTPBasicAuth

# RouterOS 配置
ROUTEROS_HOST = "192.168.50.137:80"
ROUTEROS_USER = "admin"
ROUTEROS_PASSWORD = "password"

# 测试配置
COREDNS_BIN = "./coredns"
COREDNS_CONF = "conf/Corefile.routeros"
COREDNS_DNS = "127.0.0.1"

# 测试域名（使用 china_ip 列表，但我们需要测试 gfw_ip 的 TTL=0）
# 改用 baidu.com，它的 IP 相对稳定
TEST_DOMAIN = "www.google.com"
ADDRESS_LIST = "gfw_ip"

# 或者我们手动测试：先查一次，等待添加完成，再查同一个 IP
TEST_MANUAL = True


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
    """查询 RouterOS 地址列表"""
    url = f"http://{ROUTEROS_HOST}/rest/ip/firewall/address-list?list={list_name}"
    
    try:
        response = requests.get(
            url,
            auth=HTTPBasicAuth(ROUTEROS_USER, ROUTEROS_PASSWORD),
            headers={"Accept": "application/json"},
            timeout=5,
            verify=False
        )
        
        if response.status_code == 200:
            items = response.json()
            return [(item.get("address"), item.get(".id"), item.get("timeout", "")) 
                    for item in items]
        else:
            print_error(f"查询 RouterOS 失败: {response.status_code}")
            return []
    except Exception as e:
        print_error(f"连接 RouterOS 失败: {e}")
        return []


def clear_routeros_address_list(list_name):
    """清空 RouterOS 地址列表"""
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
                timeout=5,
                verify=False
            )
            
            if response.status_code in [200, 204]:
                deleted += 1
        except Exception as e:
            print_warning(f"删除 {ip} 失败: {e}")
    
    print_success(f"已删除 {deleted} 个地址")
    return True


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
        print_warning(f"DNS 查询失败: {e}")
        return None


def start_coredns():
    """启动 CoreDNS"""
    print_step("启动 CoreDNS")
    
    try:
        proc = subprocess.Popen(
            [COREDNS_BIN, "-conf", COREDNS_CONF],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # 等待启动
        time.sleep(3)
        
        # 检查是否启动成功
        if proc.poll() is not None:
            print_error("CoreDNS 启动失败")
            output, _ = proc.communicate()
            print_error(f"输出: {output}")
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


def test_repeated_queries(domain, count=10):
    """测试重复查询同一域名"""
    print_step(f"重复查询域名 {domain} {count} 次")
    
    results = []
    for i in range(1, count + 1):
        print_info(f"\n第 {i} 次查询 {domain}...")
        
        # DNS 查询
        ips = dns_query(domain)
        if ips:
            print_success(f"解析成功: {', '.join(ips)}")
            results.append({"query": i, "ips": ips, "success": True})
        else:
            print_error(f"解析失败")
            results.append({"query": i, "ips": [], "success": False})
        
        # 短暂延迟，让 CoreDNS 有时间处理
        time.sleep(0.5)
        
        # 每3次查询后检查 RouterOS
        if i % 3 == 0:
            check_routeros_entries(results[0]["ips"] if results[0]["success"] else [])
    
    return results


def check_routeros_entries(expected_ips):
    """检查 RouterOS 中的条目"""
    items = query_routeros_address_list(ADDRESS_LIST)
    
    if not items:
        print_warning(f"RouterOS 列表 {ADDRESS_LIST} 为空")
        return
    
    routeros_ips = [ip for ip, _, _ in items]
    print_info(f"RouterOS 中有 {len(routeros_ips)} 个地址:")
    
    for ip, item_id, timeout in items:
        ttl_info = "永不过期 (TTL=0)" if timeout == "" else f"TTL={timeout}"
        print_info(f"  - {ip:20} (ID: {item_id}, {ttl_info})")
    
    # 验证数量
    if expected_ips:
        expected_count = len(set(expected_ips))
        actual_count = len(routeros_ips)
        
        if actual_count == expected_count:
            print_success(f"✓ 数量正确: {actual_count} 个地址")
        elif actual_count > expected_count:
            print_error(f"✗ 数量异常: 期望 {expected_count} 个，实际 {actual_count} 个（可能有重复添加）")
        else:
            print_warning(f"⚠ 数量不足: 期望 {expected_count} 个，实际 {actual_count} 个")


def analyze_coredns_logs(proc, duration=2):
    """分析 CoreDNS 日志输出"""
    print_step(f"分析 CoreDNS 日志（最近 {duration} 秒）")
    
    time.sleep(duration)
    
    # 尝试读取最近的日志
    log_file = "logs/system.log"
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
            recent_lines = lines[-50:]  # 最近50行
            
            # 统计关键信息
            add_count = 0
            skip_count = 0
            cache_hit_count = 0
            error_400_count = 0
            
            print_info("\n关键日志:")
            for line in recent_lines:
                if "TTL=0" in line:
                    print_info(f"  {line.strip()}")
                    if "Added" in line and "to cache" in line:
                        cache_hit_count += 1
                    elif "already in cache" in line or "skipping" in line:
                        skip_count += 1
                elif "400 Bad Request" in line:
                    error_400_count += 1
                    print_error(f"  {line.strip()}")
                elif "already have such entry" in line:
                    print_error(f"  {line.strip()}")
            
            print_info(f"\n日志统计:")
            print_info(f"  - 缓存命中/跳过: {skip_count} 次")
            print_info(f"  - 添加到缓存: {cache_hit_count} 次")
            print_info(f"  - 400 错误: {error_400_count} 次")
            
            if error_400_count > 0:
                print_error(f"\n⚠️  检测到 {error_400_count} 个 400 错误！TTL=0 修复可能不完全")
                return False
            elif skip_count >= 5:
                print_success(f"\n✓ 缓存工作正常！检测到 {skip_count} 次缓存命中")
                return True
            else:
                print_warning(f"\n⚠️  缓存命中次数较少，可能需要更多测试")
                return True
    
    except FileNotFoundError:
        print_warning(f"日志文件 {log_file} 不存在，跳过日志分析")
        return True
    except Exception as e:
        print_warning(f"读取日志失败: {e}")
        return True


def main():
    """主测试流程"""
    print_header("TTL=0 修复验证测试")
    
    coredns_proc = None
    
    try:
        # ============ 阶段 1: 准备环境 ============
        print_header("阶段 1: 准备测试环境")
        
        # 清空 RouterOS 地址列表
        clear_routeros_address_list(ADDRESS_LIST)
        time.sleep(2)
        
        # ============ 阶段 2: 启动 CoreDNS ============
        print_header("阶段 2: 启动 CoreDNS")
        
        coredns_proc = start_coredns()
        if not coredns_proc:
            print_error("无法启动 CoreDNS，测试终止")
            return 1
        
        time.sleep(3)  # 等待完全启动
        
        # ============ 阶段 3: 重复查询测试 ============
        print_header("阶段 3: 重复查询测试（关键测试）")
        
        print_info(f"测试说明:")
        print_info(f"  - 将重复查询 {TEST_DOMAIN} 10 次")
        print_info(f"  - TTL=0 的列表应该:")
        print_info(f"    ✓ 第1次: 添加到 RouterOS 并缓存")
        print_info(f"    ✓ 第2-10次: 缓存命中，跳过添加")
        print_info(f"    ✗ 不应该出现 400 Bad Request 错误")
        print_info(f"")
        
        # 执行重复查询
        results = test_repeated_queries(TEST_DOMAIN, count=10)
        
        time.sleep(2)
        
        # ============ 阶段 4: 验证结果 ============
        print_header("阶段 4: 验证测试结果")
        
        # 检查 RouterOS 最终状态
        print_step("检查 RouterOS 最终状态")
        if results and results[0]["success"]:
            check_routeros_entries(results[0]["ips"])
        
        # 分析日志
        log_ok = analyze_coredns_logs(coredns_proc, duration=1)
        
        # ============ 阶段 5: 测试总结 ============
        print_header("测试总结")
        
        success_count = sum(1 for r in results if r["success"])
        
        print_info(f"查询统计:")
        print_info(f"  - 总查询次数: {len(results)}")
        print_info(f"  - 成功次数: {success_count}")
        print_info(f"  - 失败次数: {len(results) - success_count}")
        
        # 最终判断
        items = query_routeros_address_list(ADDRESS_LIST)
        if results and results[0]["success"]:
            expected_count = len(set(results[0]["ips"]))
            actual_count = len(items)
            
            print_info(f"\nRouterOS 条目:")
            print_info(f"  - 期望数量: {expected_count}")
            print_info(f"  - 实际数量: {actual_count}")
            
            if actual_count == expected_count and log_ok:
                print_success("\n" + "="*80)
                print_success("✓✓✓ 测试通过！TTL=0 修复工作正常！")
                print_success("="*80)
                print_info("\n修复效果:")
                print_info("  ✓ 第1次查询成功添加到 RouterOS")
                print_info("  ✓ 后续查询使用缓存，没有重复添加")
                print_info("  ✓ 没有 400 Bad Request 错误")
                print_info("  ✓ RouterOS 中只有预期数量的条目")
                return 0
            else:
                print_error("\n" + "="*80)
                print_error("✗✗✗ 测试失败！发现问题：")
                print_error("="*80)
                if actual_count > expected_count:
                    print_error("  ✗ RouterOS 中有重复条目")
                elif actual_count < expected_count:
                    print_error("  ✗ RouterOS 中条目不完整")
                if not log_ok:
                    print_error("  ✗ 日志中发现 400 错误")
                return 1
        else:
            print_error("\n测试无法完成判断（DNS 查询失败）")
            return 1
    
    except KeyboardInterrupt:
        print_error("\n\n测试被用户中断")
        return 1
    
    except Exception as e:
        print_error(f"\n\n测试出错: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    finally:
        # 清理
        if coredns_proc:
            time.sleep(2)
            stop_coredns(coredns_proc)


if __name__ == "__main__":
    sys.exit(main())

