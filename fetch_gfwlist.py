#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GFWList 域名提取脚本

从 https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt 
获取 GFWList 数据，解析并生成纯域名列表文件。

GFWList 使用 Base64 编码的 AdBlock Plus 格式，包含被 GFW 屏蔽的网站列表。
"""

import base64
import re
import urllib.request
import urllib.error
import sys
from typing import Set, List

class GFWListParser:
    def __init__(self):
        self.gfwlist_url = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
        self.domains: Set[str] = set()
        
    def fetch_gfwlist(self) -> str:
        """从 GitHub 获取 GFWList 原始数据"""
        print(f"正在从 {self.gfwlist_url} 获取 GFWList...")
        
        try:
            with urllib.request.urlopen(self.gfwlist_url, timeout=30) as response:
                data = response.read().decode('utf-8')
                print(f"✅ 成功获取数据，大小: {len(data)} 字节")
                return data
        except urllib.error.URLError as e:
            print(f"❌ 网络错误: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ 获取失败: {e}")
            sys.exit(1)
    
    def decode_gfwlist(self, encoded_data: str) -> str:
        """解码 Base64 编码的 GFWList 数据"""
        print("正在解码 Base64 数据...")
        
        try:
            # 移除可能的空白字符
            encoded_data = encoded_data.strip()
            
            # Base64 解码
            decoded_bytes = base64.b64decode(encoded_data)
            decoded_text = decoded_bytes.decode('utf-8')
            
            print(f"✅ 解码成功，解码后大小: {len(decoded_text)} 字节")
            return decoded_text
        except Exception as e:
            print(f"❌ Base64 解码失败: {e}")
            sys.exit(1)
    
    def extract_domains(self, gfwlist_content: str) -> Set[str]:
        """从 GFWList 内容中提取域名"""
        print("正在解析域名...")
        
        domains = set()
        lines = gfwlist_content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # 跳过注释行和空行
            if not line or line.startswith('!') or line.startswith('['):
                continue
            
            # 跳过白名单规则（@@开头）
            if line.startswith('@@'):
                continue
            
            # 提取域名的正则表达式模式
            domain = self._extract_domain_from_rule(line)
            if domain:
                domains.add(domain)
        
        print(f"✅ 提取到 {len(domains)} 个唯一域名")
        return domains
    
    def _extract_domain_from_rule(self, rule: str) -> str:
        """从单个规则中提取域名"""
        # 移除常见的 AdBlock Plus 规则前缀
        rule = rule.lstrip('|')
        
        # 处理 ||domain.com 格式
        if rule.startswith('||'):
            rule = rule[2:]
        
        # 处理 http:// 和 https:// 前缀
        if rule.startswith('http://'):
            rule = rule[7:]
        elif rule.startswith('https://'):
            rule = rule[8:]
        
        # 移除路径部分，只保留域名
        if '/' in rule:
            rule = rule.split('/')[0]
        
        # 移除端口号
        if ':' in rule and not rule.count(':') > 1:  # 排除 IPv6
            rule = rule.split(':')[0]
        
        # 移除通配符和其他特殊字符
        rule = rule.replace('*', '').replace('^', '')
        
        # 验证是否为有效域名
        if self._is_valid_domain(rule):
            return rule.lower()
        
        return None
    
    def _is_valid_domain(self, domain: str) -> bool:
        """验证域名格式是否有效"""
        if not domain:
            return False
        
        # 基本格式检查
        if len(domain) > 253:  # 域名最大长度
            return False
        
        # 检查是否包含有效字符
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return False
        
        # 检查是否包含至少一个点（顶级域名）
        if '.' not in domain:
            return False
        
        # 检查是否以点开头或结尾
        if domain.startswith('.') or domain.endswith('.'):
            return False
        
        # 检查是否包含连续的点
        if '..' in domain:
            return False
        
        # 检查各个部分是否有效
        parts = domain.split('.')
        for part in parts:
            if not part:  # 空部分
                return False
            if len(part) > 63:  # 单个标签最大长度
                return False
            if part.startswith('-') or part.endswith('-'):  # 不能以连字符开头或结尾
                return False
        
        return True
    
    def save_domains(self, domains: Set[str], output_file: str) -> None:
        """保存域名列表到文件"""
        print(f"正在保存域名列表到 {output_file}...")
        
        # 排序域名列表
        sorted_domains = sorted(domains)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                # 写入文件头注释
                f.write("# GFWList 域名列表\n")
                f.write("# 数据来源: https://github.com/gfwlist/gfwlist\n")
                f.write(f"# 生成时间: {self._get_current_time()}\n")
                f.write(f"# 域名数量: {len(sorted_domains)}\n")
                f.write("#\n")
                f.write("# 这些域名在中国大陆可能无法正常访问\n")
                f.write("# 建议使用海外 DNS 服务器解析\n")
                f.write("\n")
                
                # 写入域名列表
                for domain in sorted_domains:
                    f.write(f"{domain}\n")
            
            print(f"✅ 成功保存 {len(sorted_domains)} 个域名到 {output_file}")
            
        except Exception as e:
            print(f"❌ 保存文件失败: {e}")
            sys.exit(1)
    
    def _get_current_time(self) -> str:
        """获取当前时间字符串"""
        import datetime
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def generate_statistics(self, domains: Set[str]) -> None:
        """生成统计信息"""
        print("\n=== 统计信息 ===")
        print(f"总域名数量: {len(domains)}")
        
        # 按顶级域名分类统计
        tld_count = {}
        for domain in domains:
            parts = domain.split('.')
            if len(parts) >= 2:
                tld = parts[-1]
                tld_count[tld] = tld_count.get(tld, 0) + 1
        
        # 显示前 10 个最常见的顶级域名
        print("\n前 10 个最常见的顶级域名:")
        sorted_tlds = sorted(tld_count.items(), key=lambda x: x[1], reverse=True)[:10]
        for tld, count in sorted_tlds:
            print(f"  .{tld}: {count} 个域名")
        
        # 显示一些示例域名
        print(f"\n示例域名（前 10 个）:")
        sorted_domains = sorted(domains)[:10]
        for domain in sorted_domains:
            print(f"  {domain}")
    
    def run(self, output_file: str = "gfwlist_domains.txt") -> None:
        """运行完整的处理流程"""
        print("=== GFWList 域名提取工具 ===\n")
        
        # 1. 获取 GFWList 数据
        encoded_data = self.fetch_gfwlist()
        
        # 2. 解码数据
        decoded_data = self.decode_gfwlist(encoded_data)
        
        # 3. 提取域名
        domains = self.extract_domains(decoded_data)
        
        # 4. 生成统计信息
        self.generate_statistics(domains)
        
        # 5. 保存到文件
        self.save_domains(domains, output_file)
        
        print(f"\n✅ 处理完成！域名列表已保存到 {output_file}")
        print(f"📊 共提取 {len(domains)} 个唯一域名")

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="从 GFWList 提取域名列表",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python3 fetch_gfwlist.py                          # 生成 gfwlist_domains.txt
  python3 fetch_gfwlist.py -o my_gfwlist.txt       # 自定义输出文件名
  python3 fetch_gfwlist.py --help                  # 显示帮助信息

输出文件格式:
  每行一个域名，按字母顺序排序
  包含文件头注释说明数据来源和统计信息
        """
    )
    
    parser.add_argument(
        '-o', '--output',
        default='gfwlist_domains.txt',
        help='输出文件名 (默认: gfwlist_domains.txt)'
    )
    
    args = parser.parse_args()
    
    try:
        parser_instance = GFWListParser()
        parser_instance.run(args.output)
    except KeyboardInterrupt:
        print("\n\n❌ 用户中断操作")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 发生错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
