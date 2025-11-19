package domainswitch

import (
	"path/filepath"
	"strconv"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
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
//	    list china-domains.txt 223.5.5.5 china_ip 86400
//	    list gfw_list.txt 4.4.4.4 gfw_ip 0
//	    block_ip block_ip.txt
//	    routeros_login true 192.168.50.137:80 admin password
//	    hot_reload true 8182
//	    verbose_log false
//	    trace_domain true true logs/coredns.log
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

	// 默认值：如果配置了 log_file，默认同时输出到控制台
	ds.LogStdout = true

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "default":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				ds.DefaultUpstream = c.Val()
			case "list":
				// 解析格式: list filename dnsserver routeros_list routeros_ttl
				args := c.RemainingArgs()
				if len(args) != 4 {
					return nil, c.Errf("list requires 4 arguments: filename dnsserver routeros_list routeros_ttl")
				}

				// 处理相对路径：相对于 Corefile 的路径
				filename := args[0]
				if !filepath.IsAbs(filename) {
					filename = filepath.Join(corefileDir, filename)
				}

				// 解析 TTL
				ttl, err := strconv.Atoi(args[3])
				if err != nil || ttl < 0 {
					return nil, c.Errf("routeros_ttl must be a non-negative integer (seconds), 0 means no timeout")
				}

				listConfig := &DomainListConfig{
					File:         filename,
					DNSServer:    args[1],
					RouterOSList: args[2],
					RouterOSTTL:  ttl,
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
			case "routeros_login":
				// 解析格式: routeros_login enabled host:port user password
				args := c.RemainingArgs()
				if len(args) != 4 {
					return nil, c.Errf("routeros_login requires 4 arguments: enabled host:port user password")
				}
				rosEnabled = args[0] == "true"
				rosHost = args[1]
				rosUser = args[2]
				rosPassword = args[3]
			case "hot_reload":
				// 解析格式: hot_reload enabled port
				args := c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.Errf("hot_reload requires 2 arguments: enabled port")
				}
				ds.HotReloadEnabled = args[0] == "true"
				ds.ReloadHTTPPort = args[1]
			case "verbose_log":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				ds.VerboseLog = c.Val() == "true"
			case "trace_domain":
				// 解析格式: trace_domain trace_enabled stdout_enabled log_file
				args := c.RemainingArgs()
				if len(args) != 3 {
					return nil, c.Errf("trace_domain requires 3 arguments: trace_enabled stdout_enabled log_file")
				}
				ds.TraceDomainLog = args[0] == "true"
				ds.LogStdout = args[1] == "true"
				logPath := args[2]
				// 处理相对路径
				if !filepath.IsAbs(logPath) {
					logPath = filepath.Join(corefileDir, logPath)
				}
				ds.LogFile = logPath
			default:
				// 未知配置项显示警告而不是错误
				log.Warningf("domainswitch: unknown property '%s' in configuration, ignoring", c.Val())
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

	// 初始化日志写入器
	if ds.LogFile != "" {
		// 如果没有显式设置 log_stdout，默认为 true（同时输出到控制台）
		// 这个在解析配置时已经处理了，这里不需要再设置

		logWriter, err := NewLogWriter(ds.LogFile, ds.LogStdout)
		if err != nil {
			return nil, c.Errf("failed to create log writer: %v", err)
		}
		ds.logWriter = logWriter
		ds.pluginLogger = NewPluginLogger("domainswitch", logWriter)

		logger.Infof("[Log] 日志输出配置: 文件=%s, 控制台=%v, 自动按天切分=启用", ds.LogFile, ds.LogStdout)
	} else {
		logger.Infof("[Log] 日志输出配置: 仅控制台输出")
	}

	// 启动 HTTP 重载服务器
	ds.startHTTPReloadServer()

	// 如果启用 RouterOS，初始化 RouterOS 地址缓存（只针对配置了 TTL 的列表）
	if ds.RouterOSEnabled {
		if err := ds.initializeRouterOSCache(); err != nil {
			logger.Warningf("Failed to initialize RouterOS cache: %v", err)
		}
	}

	return ds, nil
}
