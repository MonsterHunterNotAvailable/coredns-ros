#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
中国域名列表提取脚本

从 https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/refs/heads/master/accelerated-domains.china.conf
获取 dnsmasq-china-list 数据，解析并生成纯域名列表文件。

dnsmasq-china-list 包含中国大陆常用网站域名，适合加速访问。
"""

import re
import urllib.request
import urllib.error
import sys
from typing import Set, List

class ChinaDomainsParser:
    def __init__(self):
        self.china_list_url = "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/refs/heads/master/accelerated-domains.china.conf"
        self.domains: Set[str] = set()
        
    def fetch_china_list(self) -> str:
        """从 GitHub 获取中国域名列表原始数据"""
        print(f"正在从 {self.china_list_url} 获取中国域名列表...")
        
        try:
            with urllib.request.urlopen(self.china_list_url, timeout=30) as response:
                data = response.read().decode('utf-8')
                print(f"✅ 成功获取数据，大小: {len(data)} 字节")
                return data
        except urllib.error.URLError as e:
            print(f"❌ 网络错误: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ 获取失败: {e}")
            sys.exit(1)
    
    def extract_domains(self, dnsmasq_content: str) -> Set[str]:
        """从 dnsmasq 配置内容中提取域名"""
        print("正在解析域名...")
        
        domains = set()
        lines = dnsmasq_content.split('\n')
        
        # dnsmasq 格式正则表达式: server=/domain.com/dns_server
        pattern = re.compile(r'^server=/([^/]+)/[^/]+$')
        
        for line in lines:
            line = line.strip()
            
            # 跳过注释行和空行
            if not line or line.startswith('#'):
                continue
            
            # 匹配 dnsmasq 格式
            match = pattern.match(line)
            if match:
                domain = match.group(1)
                
                # 验证域名格式
                if self._is_valid_domain(domain):
                    domains.add(domain.lower())
        
        print(f"✅ 提取到 {len(domains)} 个唯一域名")
        return domains
    
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
                f.write("# 中国域名列表\n")
                f.write("# 数据来源: https://github.com/felixonmars/dnsmasq-china-list\n")
                f.write(f"# 生成时间: {self._get_current_time()}\n")
                f.write(f"# 域名数量: {len(sorted_domains)}\n")
                f.write("#\n")
                f.write("# 这些域名是中国大陆常用网站，建议使用国内 DNS 服务器解析\n")
                f.write("# 可以获得更好的访问速度和稳定性\n")
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
            percentage = (count / len(domains)) * 100
            print(f"  .{tld}: {count} 个域名 ({percentage:.1f}%)")
        
        # 分析域名类型
        print(f"\n域名类型分析:")
        
        # 统计常见的中国域名后缀
        china_tlds = {'.cn', '.com.cn', '.net.cn', '.org.cn', '.gov.cn', '.edu.cn'}
        china_count = sum(1 for domain in domains if any(domain.endswith(tld) for tld in china_tlds))
        print(f"  中国域名后缀: {china_count} 个 ({(china_count/len(domains)*100):.1f}%)")
        
        # 统计 .com 域名
        com_count = sum(1 for domain in domains if domain.endswith('.com'))
        print(f"  .com 域名: {com_count} 个 ({(com_count/len(domains)*100):.1f}%)")
        
        # 显示一些示例域名
        print(f"\n示例域名（前 10 个）:")
        sorted_domains = sorted(domains)[:10]
        for domain in sorted_domains:
            print(f"  {domain}")
        
        # 显示一些知名网站
        famous_sites = []
        well_known = ['baidu.com', 'qq.com', 'taobao.com', 'tmall.com', 'jd.com', 
                     'weibo.com', 'sina.com.cn', '163.com', 'sohu.com', 'youku.com']
        for site in well_known:
            if site in domains:
                famous_sites.append(site)
        
        if famous_sites:
            print(f"\n包含的知名网站:")
            for site in famous_sites[:10]:
                print(f"  {site}")
    
    def run(self, output_file: str = "china_domains.txt") -> None:
        """运行完整的处理流程"""
        print("=== 中国域名列表提取工具 ===\n")
        
        # 1. 获取中国域名列表数据
        dnsmasq_data = self.fetch_china_list()
        
        # 2. 提取域名
        domains = self.extract_domains(dnsmasq_data)
        
        # 3. 生成统计信息
        self.generate_statistics(domains)
        
        # 4. 保存到文件
        self.save_domains(domains, output_file)
        
        print(f"\n✅ 处理完成！域名列表已保存到 {output_file}")
        print(f"📊 共提取 {len(domains)} 个唯一域名")

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="从 dnsmasq-china-list 提取中国域名列表",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python3 fetch_china_domains.py                        # 生成 china_domains.txt
  python3 fetch_china_domains.py -o my_china_list.txt   # 自定义输出文件名
  python3 fetch_china_domains.py --help                 # 显示帮助信息

输出文件格式:
  每行一个域名，按字母顺序排序
  包含文件头注释说明数据来源和统计信息
  
数据来源:
  felixonmars/dnsmasq-china-list - 中国大陆加速域名列表
  包含常用的中国网站域名，适合使用国内 DNS 服务器解析
        """
    )
    
    parser.add_argument(
        '-o', '--output',
        default='china_domains.txt',
        help='输出文件名 (默认: china_domains.txt)'
    )
    
    args = parser.parse_args()
    
    try:
        parser_instance = ChinaDomainsParser()
        parser_instance.run(args.output)
    except KeyboardInterrupt:
        print("\n\n❌ 用户中断操作")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 发生错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
