package domainswitch

import (
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
// 配置格式：
// domainswitch {
//     list /path/to/domain-list.txt
//     special 223.5.5.5
//     default 8.8.8.8
//     block_ip /path/to/block_ip.txt
//     routeros_enable true
//     routeros_host 172.16.40.248
//     routeros_user admin
//     routeros_password your_password
//     routeros_list china_site
// }
func parseDomainSwitch(c *caddy.Controller) (*DomainSwitch, error) {
	var (
		listFile        string
		specialUpstream = "223.5.5.5" // 默认：阿里云 DNS
		defaultUpstream = "8.8.8.8"   // 默认：Google DNS
		blockIPFile     = ""           // IP 黑名单文件
		
		// RouterOS 配置
		rosEnabled  = false
		rosHost     = ""
		rosUser     = "admin"
		rosPassword = ""
		rosList     = "china_site"
	)

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "list":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				listFile = c.Val()
			case "special":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				specialUpstream = c.Val()
			case "default":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				defaultUpstream = c.Val()
			case "block_ip":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				blockIPFile = c.Val()
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
			case "routeros_list":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				rosList = c.Val()
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}

	// 创建插件实例
	ds := NewDomainSwitch(specialUpstream, defaultUpstream)
	
	// 配置 RouterOS
	ds.RouterOSEnabled = rosEnabled
	ds.RouterOSHost = rosHost
	ds.RouterOSUser = rosUser
	ds.RouterOSPassword = rosPassword
	ds.RouterOSList = rosList
	
	// 配置 IP 黑名单
	ds.BlockIPFile = blockIPFile

	// 加载域名列表
	if listFile != "" {
		if err := ds.LoadList(listFile); err != nil {
			return nil, c.Errf("failed to load domain list: %v", err)
		}
	}
	
	// 加载 IP 黑名单
	if blockIPFile != "" {
		if err := ds.LoadBlockIPList(blockIPFile); err != nil {
			return nil, c.Errf("failed to load IP block list: %v", err)
		}
	}

	return ds, nil
}

