package main

import (
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"

	// 只导入必要的插件
	_ "github.com/coredns/coredns/plugin/cache"    // DNS 缓存
	_ "github.com/coredns/coredns/plugin/errors"   // 错误处理
	_ "github.com/coredns/coredns/plugin/forward"  // DNS 转发（备用）
	_ "github.com/coredns/coredns/plugin/log"      // 日志记录
	_ "github.com/coredns/coredns/plugin/template" // 模板处理（IPv6 过滤）

	// 自定义插件
	_ "github.com/coredns/coredns/plugin/domainswitch"
)

func main() {
	// 设置插件执行顺序（非常重要）
	dnsserver.Directives = []string{
		"errors",       // 错误处理（最先）
		"log",          // 日志记录
		"cache",        // DNS 缓存
		"template",     // 模板处理（IPv6 过滤）
		"domainswitch", // 域名分流（核心功能）
		"forward",      // DNS 转发（备用，最后）
	}

	// 启动 CoreDNS
	coremain.Run()
}
