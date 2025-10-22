#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoreDNS High-Performance Benchmark Tool
支持从 dnsmasq-china-list 和 gfwlist 获取域名进行并发 DNS 测试
"""

import asyncio
import argparse
import base64
import random
import time
import sys
import statistics
from urllib.request import urlopen
from typing import List, Dict, Tuple
from collections import defaultdict
import dns.resolver
import dns.asyncresolver
import dns.exception


class Colors:
    """终端颜色"""
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color


class DNSBenchmark:
    """DNS 压测工具"""
    
    # 域名列表 URL
    CHINA_LIST_URL = "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"
    GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
    
    def __init__(self, dns_server: str, port: int = 53, timeout: float = 5.0):
        """
        初始化
        
        Args:
            dns_server: DNS 服务器地址
            port: DNS 端口
            timeout: 查询超时时间（秒）
        """
        self.dns_server = dns_server
        self.port = port
        self.timeout = timeout
        
        # 统计数据
        self.stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'timeout': 0,
            'china_domains': 0,
            'foreign_domains': 0,
            'latencies': [],
            'errors': defaultdict(int)
        }
        
        # 域名列表
        self.china_domains = []
        self.foreign_domains = []
        
    def print_info(self, msg: str):
        """打印信息"""
        print(f"{Colors.GREEN}[INFO]{Colors.NC} {msg}")
        
    def print_warn(self, msg: str):
        """打印警告"""
        print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}")
        
    def print_error(self, msg: str):
        """打印错误"""
        print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}")
        
    def load_china_domains(self) -> List[str]:
        """
        从 dnsmasq-china-list 加载中国域名
        
        Returns:
            域名列表
        """
        self.print_info("Loading China domains from dnsmasq-china-list...")
        
        try:
            response = urlopen(self.CHINA_LIST_URL, timeout=30)
            content = response.read().decode('utf-8')
            
            domains = []
            for line in content.splitlines():
                line = line.strip()
                # 解析 server=/example.com/114.114.114.114 格式
                if line.startswith('server=/') and not line.startswith('#'):
                    parts = line.split('/')
                    if len(parts) >= 3:
                        domain = parts[1]
                        if domain and domain != '':
                            domains.append(domain)
            
            self.print_info(f"Loaded {len(domains)} China domains")
            return domains
            
        except Exception as e:
            self.print_error(f"Failed to load China domains: {e}")
            return []
    
    def load_gfw_domains(self) -> List[str]:
        """
        从 gfwlist 加载国外域名
        
        Returns:
            域名列表
        """
        self.print_info("Loading foreign domains from gfwlist...")
        
        try:
            response = urlopen(self.GFWLIST_URL, timeout=30)
            content = response.read()
            
            # Base64 解码
            decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
            
            domains = []
            for line in decoded.splitlines():
                line = line.strip()
                
                # 跳过注释和特殊规则
                if not line or line.startswith('!') or line.startswith('['):
                    continue
                
                # 跳过正则表达式规则
                if line.startswith('/') and line.endswith('/'):
                    continue
                
                # 移除规则前缀
                line = line.lstrip('|@.')
                
                # 移除通配符和路径
                if '||' in line:
                    line = line.split('||')[1]
                if '*' in line:
                    continue
                if '/' in line:
                    line = line.split('/')[0]
                
                # 提取域名
                if '.' in line:
                    # 移除端口号
                    if ':' in line:
                        line = line.split(':')[0]
                    
                    # 简单的域名验证
                    if len(line) > 3 and len(line) < 100:
                        # 确保是有效域名格式
                        parts = line.split('.')
                        if len(parts) >= 2 and all(p for p in parts):
                            domains.append(line)
            
            # 去重
            domains = list(set(domains))
            
            self.print_info(f"Loaded {len(domains)} foreign domains")
            return domains
            
        except Exception as e:
            self.print_error(f"Failed to load GFW domains: {e}")
            return []
    
    async def query_dns_async(self, domain: str, is_china: bool) -> Tuple[bool, float, str]:
        """
        异步 DNS 查询
        
        Args:
            domain: 域名
            is_china: 是否为中国域名
            
        Returns:
            (成功, 延迟ms, 错误信息)
        """
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = [self.dns_server]
        resolver.port = self.port
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        
        start_time = time.time()
        
        try:
            # 查询 A 记录
            await resolver.resolve(domain, 'A')
            
            latency = (time.time() - start_time) * 1000  # 转换为毫秒
            
            return True, latency, ""
            
        except dns.exception.Timeout:
            return False, 0, "timeout"
            
        except dns.resolver.NXDOMAIN:
            # NXDOMAIN 也算查询成功（域名不存在是正常响应）
            latency = (time.time() - start_time) * 1000
            return True, latency, ""
            
        except dns.resolver.NoAnswer:
            latency = (time.time() - start_time) * 1000
            return True, latency, ""
            
        except Exception as e:
            return False, 0, str(type(e).__name__)
    
    async def run_benchmark_async(self, domains: List[Tuple[str, bool]], concurrency: int = 100):
        """
        异步运行压测
        
        Args:
            domains: (域名, 是否中国域名) 列表
            concurrency: 并发数
        """
        total = len(domains)
        semaphore = asyncio.Semaphore(concurrency)
        
        async def query_with_semaphore(domain: str, is_china: bool, index: int):
            async with semaphore:
                success, latency, error = await self.query_dns_async(domain, is_china)
                
                # 更新统计
                self.stats['total'] += 1
                if success:
                    self.stats['success'] += 1
                    self.stats['latencies'].append(latency)
                else:
                    self.stats['failed'] += 1
                    if error == 'timeout':
                        self.stats['timeout'] += 1
                    self.stats['errors'][error] += 1
                
                if is_china:
                    self.stats['china_domains'] += 1
                else:
                    self.stats['foreign_domains'] += 1
                
                # 进度显示
                if (index + 1) % 50 == 0 or index + 1 == total:
                    progress = (index + 1) / total * 100
                    print(f"\r{Colors.CYAN}Progress: {index + 1}/{total} ({progress:.1f}%) "
                          f"Success: {self.stats['success']} Failed: {self.stats['failed']}{Colors.NC}", 
                          end='', flush=True)
        
        # 创建所有任务
        tasks = [
            query_with_semaphore(domain, is_china, i) 
            for i, (domain, is_china) in enumerate(domains)
        ]
        
        # 并发执行
        await asyncio.gather(*tasks)
        print()  # 换行
    
    def print_report(self, duration: float):
        """
        打印测试报告
        
        Args:
            duration: 测试持续时间（秒）
        """
        print(f"\n{Colors.BLUE}{'='*70}{Colors.NC}")
        print(f"{Colors.BLUE}DNS Benchmark Report{Colors.NC}")
        print(f"{Colors.BLUE}{'='*70}{Colors.NC}\n")
        
        # 基本信息
        print(f"{Colors.GREEN}Test Configuration:{Colors.NC}")
        print(f"  DNS Server:     {self.dns_server}:{self.port}")
        print(f"  Timeout:        {self.timeout}s")
        print(f"  Duration:       {duration:.2f}s")
        print()
        
        # 查询统计
        print(f"{Colors.GREEN}Query Statistics:{Colors.NC}")
        print(f"  Total Queries:  {self.stats['total']}")
        print(f"  Successful:     {Colors.GREEN}{self.stats['success']}{Colors.NC} "
              f"({self.stats['success']/self.stats['total']*100:.2f}%)")
        print(f"  Failed:         {Colors.RED}{self.stats['failed']}{Colors.NC} "
              f"({self.stats['failed']/self.stats['total']*100:.2f}%)")
        print(f"  Timeout:        {self.stats['timeout']}")
        print()
        
        # 域名类型统计
        print(f"{Colors.GREEN}Domain Types:{Colors.NC}")
        print(f"  China Domains:   {self.stats['china_domains']}")
        print(f"  Foreign Domains: {self.stats['foreign_domains']}")
        print()
        
        # 性能统计
        if self.stats['latencies']:
            latencies = self.stats['latencies']
            print(f"{Colors.GREEN}Performance:{Colors.NC}")
            print(f"  QPS:            {self.stats['total']/duration:.2f} queries/sec")
            print(f"  Min Latency:    {min(latencies):.2f}ms")
            print(f"  Max Latency:    {max(latencies):.2f}ms")
            print(f"  Avg Latency:    {statistics.mean(latencies):.2f}ms")
            print(f"  Median Latency: {statistics.median(latencies):.2f}ms")
            
            # 百分位延迟
            sorted_latencies = sorted(latencies)
            p95 = sorted_latencies[int(len(sorted_latencies) * 0.95)]
            p99 = sorted_latencies[int(len(sorted_latencies) * 0.99)]
            print(f"  P95 Latency:    {p95:.2f}ms")
            print(f"  P99 Latency:    {p99:.2f}ms")
            print()
        
        # 错误统计
        if self.stats['errors']:
            print(f"{Colors.YELLOW}Error Distribution:{Colors.NC}")
            for error, count in sorted(self.stats['errors'].items(), key=lambda x: x[1], reverse=True):
                if error:
                    print(f"  {error}: {count}")
            print()
        
        print(f"{Colors.BLUE}{'='*70}{Colors.NC}\n")
    
    def run(self, num_queries: int = 1000, concurrency: int = 100, 
            china_ratio: float = 0.5, load_lists: bool = True):
        """
        运行压测
        
        Args:
            num_queries: 查询总数
            concurrency: 并发数
            china_ratio: 中国域名比例 (0-1)
            load_lists: 是否从网络加载域名列表
        """
        self.print_info("Starting DNS Benchmark...")
        self.print_info(f"Target: {self.dns_server}:{self.port}")
        self.print_info(f"Queries: {num_queries}, Concurrency: {concurrency}")
        print()
        
        # 加载域名列表
        if load_lists:
            self.china_domains = self.load_china_domains()
            self.foreign_domains = self.load_gfw_domains()
        
        # 如果没有域名，使用默认测试域名
        if not self.china_domains:
            self.print_warn("Using default China domains")
            self.china_domains = [
                'baidu.com', 'qq.com', 'taobao.com', 'sina.com.cn', 'weibo.com',
                'alipay.com', 'jd.com', '163.com', 'tmall.com', 'sohu.com'
            ]
        
        if not self.foreign_domains:
            self.print_warn("Using default foreign domains")
            self.foreign_domains = [
                'google.com', 'facebook.com', 'youtube.com', 'twitter.com', 'instagram.com',
                'amazon.com', 'wikipedia.org', 'reddit.com', 'netflix.com', 'github.com'
            ]
        
        # 生成测试域名列表
        num_china = int(num_queries * china_ratio)
        num_foreign = num_queries - num_china
        
        test_domains = []
        
        # 随机选择中国域名
        for _ in range(num_china):
            domain = random.choice(self.china_domains)
            test_domains.append((domain, True))
        
        # 随机选择国外域名
        for _ in range(num_foreign):
            domain = random.choice(self.foreign_domains)
            test_domains.append((domain, False))
        
        # 打乱顺序
        random.shuffle(test_domains)
        
        self.print_info(f"Generated {len(test_domains)} test queries")
        self.print_info(f"China: {num_china}, Foreign: {num_foreign}")
        print()
        
        # 运行测试
        start_time = time.time()
        
        try:
            asyncio.run(self.run_benchmark_async(test_domains, concurrency))
        except KeyboardInterrupt:
            self.print_warn("Benchmark interrupted by user")
        
        duration = time.time() - start_time
        
        # 打印报告
        self.print_report(duration)


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='CoreDNS High-Performance Benchmark Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage (test local CoreDNS)
  python3 dns_benchmark.py -s 127.0.0.1 -p 53 -n 1000

  # High concurrency test
  python3 dns_benchmark.py -s 127.0.0.1 -p 53 -n 5000 -c 500

  # Test with custom ratio (70% China domains)
  python3 dns_benchmark.py -s 127.0.0.1 -p 53 -n 1000 -r 0.7

  # Quick test with default domains
  python3 dns_benchmark.py -s 127.0.0.1 -p 53 -n 100 --no-load

  # Test production DNS
  python3 dns_benchmark.py -s 223.5.5.5 -n 2000 -c 200
        """
    )
    
    parser.add_argument('-s', '--server', type=str, default='127.0.0.1',
                        help='DNS server address (default: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=53,
                        help='DNS server port (default: 53)')
    parser.add_argument('-n', '--num', type=int, default=1000,
                        help='Number of queries (default: 1000)')
    parser.add_argument('-c', '--concurrency', type=int, default=100,
                        help='Concurrency level (default: 100)')
    parser.add_argument('-r', '--ratio', type=float, default=0.5,
                        help='China domains ratio 0-1 (default: 0.5)')
    parser.add_argument('-t', '--timeout', type=float, default=5.0,
                        help='Query timeout in seconds (default: 5.0)')
    parser.add_argument('--no-load', action='store_true', dest='no_load',
                        help='Use default domains instead of loading from internet')
    
    args = parser.parse_args()
    
    # 验证参数
    if not 0 <= args.ratio <= 1:
        print(f"{Colors.RED}Error: ratio must be between 0 and 1{Colors.NC}")
        sys.exit(1)
    
    if args.num <= 0 or args.concurrency <= 0:
        print(f"{Colors.RED}Error: num and concurrency must be positive{Colors.NC}")
        sys.exit(1)
    
    # 运行测试
    benchmark = DNSBenchmark(args.server, args.port, args.timeout)
    benchmark.run(
        num_queries=args.num,
        concurrency=args.concurrency,
        china_ratio=args.ratio,
        load_lists=not args.no_load
    )


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[WARN]{Colors.NC} Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[ERROR]{Colors.NC} {e}")
        sys.exit(1)

