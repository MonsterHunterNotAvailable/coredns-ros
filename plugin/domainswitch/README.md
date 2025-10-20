# domainswitch

## Name

*domainswitch* - 基于域名列表的智能 DNS 分流插件

## Description

domainswitch 插件根据域名列表将 DNS 查询分流到不同的上游 DNS 服务器。特别适合需要区分国内外域名的场景。

## Syntax

```
domainswitch {
    list FILE
    special IP
    default IP
    block_ip FILE
    routeros_enable BOOL
    routeros_host IP
    routeros_user USER
    routeros_password PASSWORD
    routeros_list LISTNAME
}
```

* **list** - 域名列表文件路径（每行一个域名，支持 dnsmasq 格式）
* **special** - 列表中域名使用的上游 DNS（默认：223.5.5.5）
* **default** - 其他域名使用的上游 DNS（默认：8.8.8.8）
* **block_ip** - IP 黑名单文件路径（CIDR 格式，可选）
* **routeros_enable** - 是否启用 RouterOS 集成（默认：false）
* **routeros_host** - RouterOS 设备 IP 地址
* **routeros_user** - RouterOS 用户名（默认：admin）
* **routeros_password** - RouterOS 密码
* **routeros_list** - RouterOS 地址列表名称（默认：china_site）

## Examples

### 基本用法

```
.:1053 {
    domainswitch {
        list /path/to/china-domains.txt
        special 223.5.5.5
        default 8.8.8.8
    }
    log
    errors
}
```

### 使用 dnsmasq-china-list

```
.:1053 {
    domainswitch {
        list /path/to/accelerated-domains.china.conf
        special 223.5.5.5
        default 8.8.8.8
    }
    cache 30
    log
}
```

### 带 IP 黑名单功能

```
.:1053 {
    domainswitch {
        list china-domains.txt
        special 223.5.5.5
        default 8.8.8.8
        block_ip block_ip.txt
    }
    cache 30
    log
    errors
}
```

### RouterOS 集成（自动添加 IP 到防火墙地址列表）

```
.:1053 {
    domainswitch {
        list china-domains.txt
        special 223.5.5.5
        default 8.8.8.8
        routeros_enable true
        routeros_host 192.168.1.1
        routeros_user admin
        routeros_password your_password
        routeros_list china_sites
    }
    cache 30
    log
}
```

## 域名列表格式

支持两种格式：

1. **纯域名格式**（每行一个域名）:
```
baidu.com
qq.com
taobao.com
```

2. **dnsmasq 格式**:
```
server=/baidu.com/114.114.114.114
server=/qq.com/114.114.114.114
```

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

## 性能特点

- 使用 HashMap 存储域名，查询时间复杂度 O(1)
- 支持加载 10 万+ 域名，内存占用约 20-50MB
- 启动速度快（2-3 秒加载完成）
- 查询延迟低（< 1ms 判断时间）

## See Also

- [CoreDNS forward plugin](https://coredns.io/plugins/forward/)
- [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)

