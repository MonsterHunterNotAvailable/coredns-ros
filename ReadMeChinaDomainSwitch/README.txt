CoreDNS 智能 DNS 分流系统
=============================

## 项目结构

coredns/
├── coredns                      # 二进制文件（包含 domainswitch 插件）
├── Corefile                     # 主配置文件
├── china-domains.txt            # 中国域名列表（116,254 个域名）
├── plugin/domainswitch/         # 自定义插件源码
│   ├── domainswitch.go         # 插件主逻辑
│   ├── setup.go                # 配置解析
│   └── README.md               # 插件文档
└── plugin.cfg                   # 插件注册配置

## 快速启动

1. 启动 CoreDNS:
   ./coredns -conf Corefile.routeros

2. 测试查询:
   # 中国域名（走阿里云 DNS 223.5.5.5）
   dig @127.0.0.1 -p 1053 www.baidu.com
   
   # 国外域名（走 Google DNS 8.8.8.8）
   dig @127.0.0.1 -p 1053 www.google.com

## 性能指标

- 加载域名: 116,254 个
- 启动时间: 3-5 秒
- 内存占用: ~57MB
- 查询延迟: < 1ms

## 配置说明

编辑 Corefile 修改配置:

domainswitch {
    list /path/to/domain-list.txt  # 域名列表文件
    special 223.5.5.5              # 列表中域名的上游 DNS
    default 8.8.8.8                # 其他域名的上游 DNS
}

## 重新编译

如果修改了插件代码:

1. go generate
2. make

## 更新域名列表

curl -o china-domains.txt \
  https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/refs/heads/master/accelerated-domains.china.conf

## 插件特性

- ✅ 高性能 HashMap 查找
- ✅ 支持 10 万+ 域名
- ✅ 自动匹配子域名
- ✅ 支持 dnsmasq 格式
- ✅ 低内存占用
- ✅ 毫秒级查询

