# domainswitch

## Name

*domainswitch* - 基于域名列表的智能 DNS 分流插件

## Description

domainswitch 插件根据域名列表将 DNS 查询分流到不同的上游 DNS 服务器。特别适合需要区分国内外域名的场景。

## Syntax

**新版本配置格式（支持多域名列表）**：

```
domainswitch {
    default DNS_SERVER
    list FILENAME DNS_SERVER ROUTEROS_LIST
    list FILENAME DNS_SERVER ROUTEROS_LIST
    ...
    block_ip FILE
    routeros_enable BOOL
    routeros_host IP
    routeros_user USER
    routeros_password PASSWORD
}
```

* **default** - 默认上游 DNS 服务器（默认：8.8.8.8）
* **list** - 域名列表配置，格式：`list 文件名 DNS服务器 RouterOS地址列表`
  - 可以配置多个 `list` 行，每个使用不同的 DNS 服务器和 RouterOS 地址列表
* **block_ip** - IP 黑名单文件路径（CIDR 格式，可选）
* **routeros_enable** - 是否启用 RouterOS 集成（默认：false）
* **routeros_host** - RouterOS 设备 IP 地址
* **routeros_user** - RouterOS 用户名（默认：admin）
* **routeros_password** - RouterOS 密码

## Examples

### 多域名列表配置（推荐）

```
.:1053 {
    domainswitch {
        default 8.8.8.8
        
        # 中国域名使用阿里云 DNS，添加到 china_ip 地址列表
        list china-domains.txt 223.5.5.5 china_ip
        
        # GFW 域名使用 Level3 DNS，添加到 gfw_ip 地址列表  
        list gfw_list.txt 4.4.4.4 gfw_ip
        
        # IP 黑名单过滤
        block_ip block_ip.txt
        
        # RouterOS 集成
        routeros_enable true
        routeros_host 172.16.40.248
        routeros_user admin
        routeros_password your_password
    }
    cache 30
    log
    errors
}
```

### 基本用法（单域名列表）

```
.:1053 {
    domainswitch {
        default 8.8.8.8
        list china-domains.txt 223.5.5.5 china_sites
    }
    log
    errors
}
```

### 复杂分流配置

```
.:1053 {
    domainswitch {
        default 8.8.8.8
        
        # 中国域名 -> 阿里云 DNS
        list china-domains.txt 223.5.5.5 china_ip
        
        # 被墙网站 -> Level3 DNS  
        list gfw_list.txt 4.4.4.4 gfw_ip
        
        # 广告域名 -> AdGuard DNS
        list ad_list.txt 94.140.14.14 ad_block
        
        # 开发相关 -> Cloudflare DNS
        list dev_list.txt 1.1.1.1 dev_sites
        
        block_ip block_ip.txt
        routeros_enable true
        routeros_host 192.168.1.1
        routeros_user admin
        routeros_password your_password
    }
    cache 30
    log
}
```

## 域名列表格式

支持简单的纯域名格式（每行一个域名）：

```
# 中国域名列表示例
# 注释行以 # 开头

baidu.com
qq.com
taobao.com
tmall.com
jd.com
weibo.com
sina.com.cn
163.com
sohu.com
youku.com
```

**格式要求**：
- 每行一个域名
- 支持注释行（以 `#` 开头）
- 自动跳过空行
- 域名会自动转换为小写
- 无效域名会记录警告日志并跳过

## IP 黑名单格式

支持 CIDR 格式的 IP 地址和网段：

```
# IP 黑名单文件示例
# 注释行以 # 开头

# 单个 IPv4 地址
192.168.1.100
10.0.0.1

# IPv4 网段（CIDR）
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12

# IPv6 地址
::1
2001:db8::1

# IPv6 网段
2001:db8::/32
```

**功能说明**：
- 如果 DNS 解析结果中的任何 IP 地址匹配黑名单，则返回空响应（NODATA）
- 被阻止的域名不会添加到 RouterOS 地址列表中
- 支持 IPv4 和 IPv6 地址过滤
- 单个 IP 会自动转换为 /32（IPv4）或 /128（IPv6）CIDR

## 功能特点

### 多域名列表支持
- **灵活配置**：支持配置多个域名列表，每个列表使用不同的 DNS 服务器
- **独立 RouterOS 地址列表**：每个域名列表可以对应不同的 RouterOS 防火墙地址列表
- **优先级匹配**：按配置顺序检查域名列表，第一个匹配的生效

### 性能特点
- **高效查询**：使用 HashMap 存储域名，查询时间复杂度 O(1)
- **大容量支持**：支持加载 10 万+ 域名，内存占用约 20-50MB
- **快速启动**：2-3 秒加载完成所有域名列表
- **低延迟**：< 1ms 判断时间

### 高级功能
- **IP 黑名单**：支持 CIDR 格式的 IP 过滤，阻止特定 IP 段的解析结果
- **RouterOS 集成**：自动将解析的 IP 添加到 RouterOS 防火墙地址列表
- **IPv6 过滤**：内置 IPv6 查询过滤功能
- **子域名匹配**：支持子域名自动匹配父域名规则

## See Also

- [CoreDNS forward plugin](https://coredns.io/plugins/forward/)
- [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)

