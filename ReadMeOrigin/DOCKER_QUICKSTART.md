# CoreDNS Docker 快速部署指南

## 概述

本项目已支持 Docker 部署，可在以下平台运行：
- ✅ x86_64 / AMD64 服务器
- ✅ ARM64 设备（如 RouterOS RB5009）
- ✅ Raspberry Pi 4/5
- ✅ 其他支持 Docker 的设备

## 核心功能

1. **智能 DNS 分流**: 116K+ 中国域名自动走阿里云 DNS
2. **IPv6 自动过滤**: 屏蔽所有 AAAA 查询
3. **RouterOS 集成**: 自动添加 IP 到防火墙地址列表
4. **低资源占用**: 内存 <60MB，CPU <5%

## 快速开始

### 1. 构建镜像

```bash
cd coredns
docker build -t coredns-ros:latest .
```

构建时间约 3-5 分钟（首次）。

### 2. 运行容器

#### 基本模式（无 RouterOS 集成）

```bash
docker run -d \
  --name coredns-china \
  --restart unless-stopped \
  -p 53:53/udp \
  -p 53:53/tcp \
  coredns-ros:latest
```

#### 启用 RouterOS 集成

1. 编辑 `Corefile.docker`，修改 RouterOS 配置：
   ```
   routeros_enable true
   routeros_host 172.16.40.248
   routeros_user admin
   routeros_password your_password
   routeros_list china_site
   ```

2. 挂载配置文件运行：
   ```bash
   docker run -d \
     --name coredns-china \
     --restart unless-stopped \
     -p 53:53/udp \
     -p 53:53/tcp \
     -v $(pwd)/Corefile.docker:/etc/coredns/Corefile:ro \
     -v $(pwd)/china-domains.txt:/etc/coredns/china-domains.txt:ro \
     coredns-ros:latest
   ```

### 3. 测试

运行自动化测试脚本：

```bash
./test-docker.sh
```

或手动测试：

```bash
# IPv4 - 中国域名
dig @127.0.0.1 www.baidu.com +short

# IPv4 - 国外域名
dig @127.0.0.1 www.google.com +short

# IPv6 - 应该返回空
dig @127.0.0.1 www.baidu.com AAAA
```

### 4. 查看日志

```bash
# 实时日志
docker logs -f coredns-china

# 最近 50 行
docker logs --tail 50 coredns-china
```

## RouterOS RB5009 部署

### 前提条件

1. RouterOS 7.x 或更高版本
2. 已启用 Container 功能
3. 网络连接正常

### 部署步骤

#### 1. 启用 Container

```routeros
# 在 RouterOS 终端执行
/system/device-mode/update container=yes
/system/reboot
```

#### 2. 配置网络

```routeros
# 创建容器网桥
/interface/bridge/add name=docker

# 配置 IP 地址
/ip/address/add address=172.17.0.1/24 interface=docker

# 配置 NAT（让容器访问外网）
/ip/firewall/nat/add chain=srcnat out-interface=ether1 action=masquerade
```

#### 3. 上传镜像

方式 A - 通过 Registry：
```bash
# 在本机推送到 Registry
docker tag coredns-ros:latest your-registry/coredns-ros:latest
docker push your-registry/coredns-ros:latest

# 在 RouterOS 中拉取
/container/shell
docker pull your-registry/coredns-ros:latest
```

方式 B - 导出导入：
```bash
# 在本机导出
docker save coredns-ros:latest | gzip > coredns-ros.tar.gz

# 上传到 RouterOS
scp coredns-ros.tar.gz admin@172.16.40.248:/

# 在 RouterOS 中导入
/container/shell
gunzip -c /coredns-ros.tar.gz | docker load
```

#### 4. 运行容器

```bash
# 在 RouterOS container shell 中
docker run -d \
  --name coredns \
  --restart always \
  -p 172.17.0.1:53:53/udp \
  -p 172.17.0.1:53:53/tcp \
  --dns 223.5.5.5 \
  --dns 8.8.8.8 \
  --memory="256m" \
  --cpus="1.0" \
  coredns-ros:latest
```

#### 5. 配置 RouterOS DNS

```routeros
# 退出 container shell，回到 RouterOS 终端
# 设置 DNS 指向容器
/ip/dns/set servers=172.17.0.1
/ip/dns/set allow-remote-requests=yes

# 测试
/tool/dig www.baidu.com A
/tool/dig www.baidu.com AAAA
```

#### 6. 启用 RouterOS 集成（可选）

如需自动添加中国域名 IP 到地址列表：

1. 启用 REST API：
   ```routeros
   /ip/service/set www-ssl certificate=auto address=172.17.0.1/32
   ```

2. 创建地址列表：
   ```routeros
   /ip/firewall/address-list/add list=china_site address=0.0.0.0 comment="test"
   ```

3. 在容器中修改配置：
   ```bash
   docker exec -it coredns sh
   vi /etc/coredns/Corefile
   # 修改 routeros_enable 为 true，保存退出
   docker restart coredns
   ```

## 常见问题

### Q: 构建太慢怎么办？

A: 使用 Go 模块代理：
```bash
docker build \
  --build-arg GOPROXY=https://goproxy.cn,direct \
  -t coredns-ros:latest .
```

### Q: ARM64 设备构建报错？

A: 确保 Docker 支持 buildx：
```bash
docker buildx version
docker buildx create --use
```

### Q: 容器无法启动？

A: 检查端口占用和日志：
```bash
# 检查端口
netstat -tunlp | grep :53

# 查看错误日志
docker logs coredns-china
```

### Q: DNS 解析不工作？

A: 检查上游 DNS 和容器网络：
```bash
# 进入容器测试
docker exec -it coredns-china sh
ping -c 3 223.5.5.5
ping -c 3 8.8.8.8
```

### Q: IPv6 没有被过滤？

A: 确认 Corefile 配置正确：
```bash
docker exec -it coredns-china cat /etc/coredns/Corefile | grep template
```

应该看到：
```
template ANY AAAA {
    rcode NOERROR
}
```

### Q: RouterOS 集成不工作？

A: 检查网络连通性和 REST API：
```bash
# 在容器中测试
docker exec -it coredns-china sh
curl -k -u admin:password https://172.16.40.248/rest/system/resource
```

## 性能调优

### 限制资源使用

```bash
docker run -d \
  --name coredns-china \
  --restart unless-stopped \
  --memory="128m" \
  --memory-swap="256m" \
  --cpus="0.5" \
  -p 53:53/udp \
  -p 53:53/tcp \
  coredns-ros:latest
```

### 调整缓存大小

编辑 Corefile，修改 cache 参数：
```
cache 300  # 缓存 5 分钟（默认 30 秒）
```

### 持久化日志

```bash
mkdir -p ./logs
docker run -d \
  --name coredns-china \
  --restart unless-stopped \
  -p 53:53/udp \
  -p 53:53/tcp \
  -v $(pwd)/logs:/var/log/coredns \
  coredns-ros:latest
```

## 多架构构建

如需同时构建 AMD64 和 ARM64 镜像：

```bash
# 创建 builder
docker buildx create --name multiarch-builder --use

# 构建多架构镜像
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag your-registry/coredns-ros:latest \
  --push \
  .
```

## 更新维护

### 更新镜像

```bash
# 停止并删除旧容器
docker stop coredns-china
docker rm coredns-china

# 重新构建
docker build -t coredns-ros:latest .

# 启动新容器
docker run -d \
  --name coredns-china \
  --restart unless-stopped \
  -p 53:53/udp \
  -p 53:53/tcp \
  coredns-ros:latest
```

### 更新域名列表

```bash
# 下载最新列表
curl -o china-domains.txt.new \
  https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf

# 转换格式（去掉 server= 前缀和 /114.114.114.114 后缀）
sed 's/server=\///; s/\/[0-9.]*$//' china-domains.txt.new > china-domains.txt

# 重新构建镜像
docker build -t coredns-ros:latest .
docker restart coredns-china
```

## 卸载

```bash
# 停止容器
docker stop coredns-china

# 删除容器
docker rm coredns-china

# 删除镜像
docker rmi coredns-ros:latest

# 清理构建缓存
docker builder prune
```

## 参考链接

- **完整文档**: ReadMeChinaDomainSwitch/DOCKER.md
- **项目主页**: README.md
- **插件说明**: plugin/domainswitch/README.md

## 技术支持

遇到问题？
1. 查看日志: `docker logs coredns-china`
2. 运行测试: `./test-docker.sh`
3. 查看详细文档: `ReadMeChinaDomainSwitch/DOCKER.md`

