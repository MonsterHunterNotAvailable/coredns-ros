package domainswitch

import (
	"path/filepath"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() {
	plugin.Register("domainswitch", setup)
}

func setup(c *caddy.Controller) error {
	ds, err := parseDomainSwitch(c)
	if err != nil {
		return plugin.Error("domainswitch", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		ds.Next = next
		return ds
	})

	return nil
}

// parseDomainSwitch 解析 Corefile 配置
// 新配置格式：
//
//	domainswitch {
//	    default 8.8.8.8
//	    list china-domains.txt 223.5.5.5 china_ip
//	    list gfw_list.txt 4.4.4.4 gfw_ip
//	    block_ip block_ip.txt
//	    hot_reload true
//	    reload_port 8182
//	    verbose_log false
//	    routeros_enable true
//	    routeros_host 172.16.40.248
//	    routeros_user admin
//	    routeros_password your_routeros_password
//	}
func parseDomainSwitch(c *caddy.Controller) (*DomainSwitch, error) {
	var (
		defaultUpstream = "8.8.8.8" // 默认：Google DNS
		blockIPFile     = ""        // IP 黑名单文件

		// RouterOS 配置
		rosEnabled  = false
		rosHost     = ""
		rosUser     = "admin"
		rosPassword = ""
	)

	// 获取 Corefile 的目录路径
	corefileDir := filepath.Dir(c.File())

	// 创建插件实例
	ds := NewDomainSwitch(defaultUpstream)

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "default":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				ds.DefaultUpstream = c.Val()
			case "list":
				// 解析格式: list filename dnsserver routeros_list
				args := c.RemainingArgs()
				if len(args) != 3 {
					return nil, c.Errf("list requires 3 arguments: filename dnsserver routeros_list")
				}

				// 处理相对路径：相对于 Corefile 的路径
				filename := args[0]
				if !filepath.IsAbs(filename) {
					filename = filepath.Join(corefileDir, filename)
				}

				listConfig := &DomainListConfig{
					File:         filename,
					DNSServer:    args[1],
					RouterOSList: args[2],
				}

				// 加载域名列表
				if err := listConfig.LoadList(); err != nil {
					return nil, c.Errf("failed to load domain list %s: %v", args[0], err)
				}

				ds.DomainLists = append(ds.DomainLists, listConfig)
			case "block_ip":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				blockIPFile = c.Val()
				// 处理相对路径：相对于 Corefile 的路径
				if blockIPFile != "" && !filepath.IsAbs(blockIPFile) {
					blockIPFile = filepath.Join(corefileDir, blockIPFile)
				}
			case "routeros_enable":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				rosEnabled = c.Val() == "true"
			case "routeros_host":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				rosHost = c.Val()
			case "routeros_user":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				rosUser = c.Val()
			case "routeros_password":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				rosPassword = c.Val()
			case "hot_reload":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				ds.HotReloadEnabled = c.Val() == "true"
			case "reload_port":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				ds.ReloadHTTPPort = c.Val()
			case "verbose_log":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				ds.VerboseLog = c.Val() == "true"
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}

	// 配置 RouterOS
	ds.RouterOSEnabled = rosEnabled
	ds.RouterOSHost = rosHost
	ds.RouterOSUser = rosUser
	ds.RouterOSPassword = rosPassword

	// 配置 IP 黑名单
	ds.BlockIPFile = blockIPFile

	// 加载 IP 黑名单
	if blockIPFile != "" {
		if err := ds.LoadBlockIPList(blockIPFile); err != nil {
			return nil, c.Errf("failed to load IP block list: %v", err)
		}
	}

	// 启动 HTTP 重载服务器
	ds.startHTTPReloadServer()

	return ds, nil
}
