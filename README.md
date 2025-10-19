# CoreDNS 智能 DNS 分流系统

基于 CoreDNS 1.13.1 的智能 DNS 分流解决方案，支持根据域名列表自动将 DNS 查询分流到不同的上游服务器。

## 项目特点

- ✅ **高性能**: 使用 HashMap 存储 116,254 个中国域名，O(1) 查询复杂度
- ✅ **智能分流**: 中国域名走国内 DNS，其他域名走国外 DNS
- ✅ **RouterOS 集成**: 自动将中国域名 IP 添加到 RouterOS 防火墙地址列表 ⭐新功能
- ✅ **低内存占用**: 启动后仅占用 ~57MB 内存
- ✅ **快速启动**: 3-5 秒加载完成
- ✅ **实时日志**: 清晰显示每个域名的分流路由和 RouterOS 操作
- ✅ **易于维护**: 支持 dnsmasq 格式的域名列表

## 快速开始

### 1. 启动服务

```bash
# 进入 coredns 目录
cd coredns
./coredns
```

服务将在端口 **1053** 启动。

### 2. 测试查询

```bash
# 测试中国域名（走 223.5.5.5）
dig @127.0.0.1 -p 1053 www.baidu.com

# 测试国外域名（走 8.8.8.8）
dig @127.0.0.1 -p 1053 www.google.com
```

### 3. 查看分流日志

日志会实时显示每个查询的路由信息：
```
[INFO] plugin/domainswitch: [CHINA] www.baidu.com -> 223.5.5.5
[INFO] plugin/domainswitch: [DEFAULT] www.google.com -> 8.8.8.8
```

### 4. RouterOS 集成（可选）⭐

如果需要将中国域名 IP 自动添加到 RouterOS 防火墙地址列表：

👉 **查看 [RouterOS 集成快速开始指南](ReadMeChinaDomainSwitch/QUICKSTART_ROUTEROS.md)**

功能特点：
- 自动将解析的中国域名 IP 添加到 RouterOS address-list
- 支持基于地址列表的智能路由策略
- 异步处理，不影响 DNS 性能
- 5 分钟快速配置

## 项目结构

```
coredns/
├── coredns                      # 可执行文件（包含 domainswitch 插件）
├── Corefile                     # 主配置文件
├── china-domains.txt            # 中国域名列表（116,254 个）
├── plugin.cfg                   # 插件注册配置
├── plugin/
│   └── domainswitch/           # 自定义插件源码
│       ├── domainswitch.go     # 插件核心逻辑
│       ├── setup.go            # 配置解析
│       └── README.md           # 插件文档
├── ReadMeChinaDomainSwitch/    # 本项目相关文档
│   ├── README.txt              # 详细使用说明
│   ├── README.md               # 插件文档（副本）
│   └── test_routing.sh         # 分流测试脚本
└── ReadMeOrigin/               # CoreDNS 原始文档
    ├── README.md               # CoreDNS 原始说明
    ├── GOVERNANCE.md           # 治理说明
    └── ...                     # 其他原始文档
```

## 配置说明

当前配置（`Corefile`）：

```
.:1053 {
    # 智能 DNS 分流插件
    domainswitch {
        list china-domains.txt    # 中国域名列表
        special 223.5.5.5         # 列表中域名的上游 DNS（阿里云）
        default 8.8.8.8           # 其他域名的上游 DNS（Google）
    }
    
    cache 30     # 缓存 30 秒
    log          # 启用日志
    errors       # 记录错误
}
```

### 修改配置

编辑 `Corefile` 可以自定义：
- 监听端口
- 上游 DNS 服务器
- 域名列表文件
- 缓存时间

修改后重启 CoreDNS 即可生效。

## 性能指标

| 指标 | 数值 |
|-----|------|
| 域名数量 | 116,254 个 |
| 启动时间 | 3-5 秒 |
| 内存占用 | ~57MB |
| 查询延迟 | < 1ms（域名匹配） |

## 测试工具

使用自动化测试脚本验证分流功能：

```bash
cd ReadMeChinaDomainSwitch
./test_routing.sh
```

脚本会测试多个中国和国外域名，并显示分流日志。

## 更新域名列表

从 dnsmasq-china-list 更新域名列表：

```bash
# 在 coredns 目录下执行
curl -o china-domains.txt \
  https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/refs/heads/master/accelerated-domains.china.conf
```

更新后重启 CoreDNS 即可。

## 编译说明

### 快速编译

```bash
# 在 coredns 目录下执行
go generate
make
```

### 详细说明

完整的编译指南请参考：[编译指南](ReadMeChinaDomainSwitch/BUILD.md)

包含内容：
- 前置要求（Go 版本等）
- 多种编译方法
- 交叉编译
- 常见问题解决
- 开发模式编译

## 文档索引

### 本项目文档
- [详细使用说明](ReadMeChinaDomainSwitch/README.txt) - 包含配置、测试、性能等详细信息
- [插件文档](ReadMeChinaDomainSwitch/README.md) - domainswitch 插件使用指南
- [RouterOS 集成完整文档](ReadMeChinaDomainSwitch/ROUTEROS.md) - RouterOS 防火墙地址列表集成详细说明 ⭐
- [RouterOS 快速开始](ReadMeChinaDomainSwitch/QUICKSTART_ROUTEROS.md) - 5 分钟配置指南 ⭐
- [编译指南](ReadMeChinaDomainSwitch/BUILD.md) - 从源码编译说明
- [路径说明](ReadMeChinaDomainSwitch/PATHS.md) - 相对路径使用说明
- [DNS 分流测试](ReadMeChinaDomainSwitch/test_routing.sh) - DNS 分流自动化测试
- [RouterOS 集成测试](ReadMeChinaDomainSwitch/test_routeros.sh) - RouterOS 集成测试脚本 ⭐

### CoreDNS 原始文档
- [CoreDNS 官方说明](ReadMeOrigin/README.md)
- [插件开发指南](ReadMeOrigin/plugin.md)
- [Corefile 语法](ReadMeOrigin/corefile.5.md)

## 常见问题

### Q: 如何验证分流是否工作？
A: 查看日志中的 `[CHINA]` 和 `[DEFAULT]` 标记，或运行 `test_routing.sh` 脚本。

### Q: 如何修改上游 DNS？
A: 编辑 `Corefile` 中的 `special` 和 `default` 参数。

### Q: 域名列表多久更新一次？
A: 建议每月从 dnsmasq-china-list 更新一次。

### Q: 可以添加自定义域名吗？
A: 可以，直接编辑 `china-domains.txt` 文件，每行一个域名。

## 技术栈

- **CoreDNS**: 1.13.1
- **Go**: 1.25.3
- **插件架构**: 自定义 domainswitch 插件
- **域名列表**: [felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)

## License

继承 CoreDNS 的 Apache 2.0 License。

## 相关链接

- [CoreDNS 官网](https://coredns.io/)
- [CoreDNS GitHub](https://github.com/coredns/coredns)
- [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)

