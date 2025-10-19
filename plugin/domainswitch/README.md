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
}
```

* **list** - 域名列表文件路径（每行一个域名，支持 dnsmasq 格式）
* **special** - 列表中域名使用的上游 DNS（默认：223.5.5.5）
* **default** - 其他域名使用的上游 DNS（默认：8.8.8.8）

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

## 性能特点

- 使用 HashMap 存储域名，查询时间复杂度 O(1)
- 支持加载 10 万+ 域名，内存占用约 20-50MB
- 启动速度快（2-3 秒加载完成）
- 查询延迟低（< 1ms 判断时间）

## See Also

- [CoreDNS forward plugin](https://coredns.io/plugins/forward/)
- [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)

