// Package domainswitch 实现基于域名列表的智能 DNS 分流
package domainswitch

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

var logger = log.NewWithPlugin("domainswitch")

// DomainListConfig 域名列表配置
type DomainListConfig struct {
	File         string              // 域名列表文件路径
	DNSServer    string              // 该列表使用的 DNS 服务器
	RouterOSList string              // RouterOS 地址列表名称
	domainMap    map[string]struct{} // 域名映射表
	lastModTime  time.Time           // 文件最后修改时间
	mu           sync.RWMutex        // 读写锁
}

// DomainSwitch 实现智能 DNS 分流
type DomainSwitch struct {
	Next            plugin.Handler
	DefaultUpstream string              // 默认上游 DNS
	DomainLists     []*DomainListConfig // 多个域名列表配置
	mu              sync.RWMutex
	client          *dns.Client

	// RouterOS 配置
	RouterOSEnabled  bool
	RouterOSHost     string
	RouterOSUser     string
	RouterOSPassword string
	httpClient       *http.Client

	// IP 黑名单配置
	BlockIPFile string       // IP 黑名单文件路径
	blockIPNets []*net.IPNet // CIDR 格式的 IP 黑名单
	blockMu     sync.RWMutex // 黑名单读写锁

	// 热重载配置
	HotReloadEnabled bool         // 是否启用热重载
	ReloadHTTPPort   string       // HTTP 重载端口
	httpServer       *http.Server // HTTP 服务器
}

// Name 返回插件名称
func (ds *DomainSwitch) Name() string { return "domainswitch" }

// ServeDNS 处理 DNS 查询
func (ds *DomainSwitch) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := strings.ToLower(strings.TrimSuffix(state.Name(), "."))

	// 过滤 IPv6 (AAAA) 查询，直接返回空响应
	if state.QType() == dns.TypeAAAA {
		logger.Infof("[FILTER] Blocked IPv6 query for %s", qname)

		// 构造空响应（NODATA）
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.RecursionAvailable = true

		err := w.WriteMsg(m)
		if err != nil {
			logger.Errorf("Failed to write AAAA block response: %v", err)
			return dns.RcodeServerFailure, err
		}
		return dns.RcodeSuccess, nil
	}

	// 检查域名在哪个列表中
	upstream, listConfig := ds.getUpstream(qname)

	// 记录分流信息
	routeType := "DEFAULT"
	if listConfig != nil {
		routeType = listConfig.RouterOSList
	}
	logger.Infof("[%s] %s -> %s", routeType, qname, upstream)

	// 转发 DNS 请求
	msg, _, err := ds.client.Exchange(r, net.JoinHostPort(upstream, "53"))
	if err != nil {
		logger.Errorf("Failed to query upstream %s: %v", upstream, err)
		return dns.RcodeServerFailure, err
	}

	// 检查解析结果是否包含黑名单 IP
	isBlocked := false
	if ds.BlockIPFile != "" && msg.Rcode == dns.RcodeSuccess {
		if ds.containsBlockedIP(msg) {
			logger.Infof("[BLOCKED] %s contains blocked IP, returning DNS result but not adding to RouterOS", qname)
			isBlocked = true
		}
	}

	// 如果匹配到列表且启用了 RouterOS，且 IP 不在黑名单中，提取 IP 并添加到地址列表
	if listConfig != nil && ds.RouterOSEnabled && msg.Rcode == dns.RcodeSuccess && !isBlocked {
		go ds.addToRouterOS(qname, msg, listConfig.RouterOSList)
	}

	// 写入响应
	err = w.WriteMsg(msg)
	if err != nil {
		logger.Errorf("Failed to write response: %v", err)
		return dns.RcodeServerFailure, err
	}

	return dns.RcodeSuccess, nil
}

// getUpstream 根据域名选择上游 DNS 和对应的列表配置
func (ds *DomainSwitch) getUpstream(domain string) (string, *DomainListConfig) {
	// 逐级检查域名（支持子域名匹配）
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		testDomain := strings.Join(parts[i:], ".")

		ds.mu.RLock()
		// 遍历所有域名列表配置
		for _, listConfig := range ds.DomainLists {
			listConfig.mu.RLock()
			_, inList := listConfig.domainMap[testDomain]
			listConfig.mu.RUnlock()

			if inList {
				ds.mu.RUnlock()
				return listConfig.DNSServer, listConfig
			}
		}
		ds.mu.RUnlock()
	}

	return ds.DefaultUpstream, nil
}

// LoadList 为特定的 DomainListConfig 从文件加载域名列表
func (listConfig *DomainListConfig) LoadList() error {
	logger.Infof("Loading domain list from: %s", listConfig.File)

	// 获取文件信息
	fileInfo, err := os.Stat(listConfig.File)
	if err != nil {
		return fmt.Errorf("failed to stat domain list file: %v", err)
	}

	f, err := os.Open(listConfig.File)
	if err != nil {
		return fmt.Errorf("failed to open domain list file: %v", err)
	}
	defer f.Close()

	// 创建新的域名映射
	newDomainMap := make(map[string]struct{}, 200000)
	scanner := bufio.NewScanner(f)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 直接使用域名（每行一个域名格式）
		domain := strings.ToLower(line)
		if isValidDomain(domain) {
			newDomainMap[domain] = struct{}{}
			count++
		} else {
			logger.Warningf("Invalid domain format: %s", line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading domain list: %v", err)
	}

	// 原子性更新域名映射和修改时间
	listConfig.mu.Lock()
	listConfig.domainMap = newDomainMap
	listConfig.lastModTime = fileInfo.ModTime()
	listConfig.mu.Unlock()

	logger.Infof("Loaded %d domains from %s for DNS %s -> RouterOS %s",
		count, listConfig.File, listConfig.DNSServer, listConfig.RouterOSList)
	return nil
}

// isValidDomain 验证域名格式是否有效
func isValidDomain(domain string) bool {
	if domain == "" {
		return false
	}

	// 基本长度检查
	if len(domain) > 253 {
		return false
	}

	// 检查是否包含至少一个点
	if !strings.Contains(domain, ".") {
		return false
	}

	// 检查是否以点开头或结尾
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}

	// 检查是否包含连续的点
	if strings.Contains(domain, "..") {
		return false
	}

	// 检查字符是否合法（字母、数字、点、连字符）
	for _, char := range domain {
		if !((char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '.' || char == '-') {
			return false
		}
	}

	// 检查各个标签
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" {
			return false
		}
		if len(label) > 63 {
			return false
		}
		// 标签不能以连字符开头或结尾
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}

	return true
}

// startHTTPReloadServer 启动 HTTP 重载服务器
func (ds *DomainSwitch) startHTTPReloadServer() {
	if !ds.HotReloadEnabled || ds.ReloadHTTPPort == "" {
		return
	}

	mux := http.NewServeMux()

	// 重载所有域名列表
	mux.HandleFunc("/reload", ds.handleReload)

	// 重载特定域名列表
	mux.HandleFunc("/reload/", ds.handleReloadSpecific)

	// 重载 IP 黑名单
	mux.HandleFunc("/reload-ip", ds.handleReloadIP)

	// 获取状态信息
	mux.HandleFunc("/status", ds.handleStatus)

	ds.httpServer = &http.Server{
		Addr:    ":" + ds.ReloadHTTPPort,
		Handler: mux,
	}

	logger.Infof("Starting HTTP reload server on port %s", ds.ReloadHTTPPort)

	go func() {
		if err := ds.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("HTTP reload server error: %v", err)
		}
	}()
}

// handleReload 处理重载所有域名列表的请求
func (ds *DomainSwitch) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger.Infof("[HTTP Reload] Reloading all domain lists...")

	results := make(map[string]string)

	ds.mu.RLock()
	lists := make([]*DomainListConfig, len(ds.DomainLists))
	copy(lists, ds.DomainLists)
	ds.mu.RUnlock()

	// 重载所有域名列表
	for _, listConfig := range lists {
		if err := listConfig.LoadList(); err != nil {
			logger.Errorf("[HTTP Reload] Failed to reload %s: %v", listConfig.File, err)
			results[listConfig.File] = fmt.Sprintf("Error: %v", err)
		} else {
			logger.Infof("[HTTP Reload] Successfully reloaded %s", listConfig.File)
			results[listConfig.File] = "Success"
		}
	}

	// 重载 IP 黑名单
	if ds.BlockIPFile != "" {
		if err := ds.LoadBlockIPList(ds.BlockIPFile); err != nil {
			logger.Errorf("[HTTP Reload] Failed to reload IP block list: %v", err)
			results[ds.BlockIPFile] = fmt.Sprintf("Error: %v", err)
		} else {
			logger.Infof("[HTTP Reload] Successfully reloaded IP block list")
			results[ds.BlockIPFile] = "Success"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "completed",
		"results": results,
	})
}

// handleReloadSpecific 处理重载特定域名列表的请求
func (ds *DomainSwitch) handleReloadSpecific(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 从 URL 路径中提取文件名
	filename := strings.TrimPrefix(r.URL.Path, "/reload/")
	if filename == "" {
		http.Error(w, "Filename required", http.StatusBadRequest)
		return
	}

	logger.Infof("[HTTP Reload] Reloading specific file: %s", filename)

	ds.mu.RLock()
	var targetConfig *DomainListConfig
	for _, listConfig := range ds.DomainLists {
		if listConfig.File == filename {
			targetConfig = listConfig
			break
		}
	}
	ds.mu.RUnlock()

	if targetConfig == nil {
		http.Error(w, "File not found in configuration", http.StatusNotFound)
		return
	}

	if err := targetConfig.LoadList(); err != nil {
		logger.Errorf("[HTTP Reload] Failed to reload %s: %v", filename, err)
		http.Error(w, fmt.Sprintf("Reload failed: %v", err), http.StatusInternalServerError)
		return
	}

	logger.Infof("[HTTP Reload] Successfully reloaded %s", filename)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "success",
		"filename": filename,
		"message":  "Reloaded successfully",
	})
}

// handleReloadIP 处理重载 IP 黑名单的请求
func (ds *DomainSwitch) handleReloadIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if ds.BlockIPFile == "" {
		http.Error(w, "IP block list not configured", http.StatusBadRequest)
		return
	}

	logger.Infof("[HTTP Reload] Reloading IP block list: %s", ds.BlockIPFile)

	if err := ds.LoadBlockIPList(ds.BlockIPFile); err != nil {
		logger.Errorf("[HTTP Reload] Failed to reload IP block list: %v", err)
		http.Error(w, fmt.Sprintf("Reload failed: %v", err), http.StatusInternalServerError)
		return
	}

	logger.Infof("[HTTP Reload] Successfully reloaded IP block list")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "IP block list reloaded successfully",
	})
}

// handleStatus 处理状态查询请求
func (ds *DomainSwitch) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ds.mu.RLock()
	lists := make([]map[string]interface{}, len(ds.DomainLists))
	for i, listConfig := range ds.DomainLists {
		listConfig.mu.RLock()
		domainCount := len(listConfig.domainMap)
		lastModTime := listConfig.lastModTime
		listConfig.mu.RUnlock()

		lists[i] = map[string]interface{}{
			"file":          listConfig.File,
			"dns_server":    listConfig.DNSServer,
			"routeros_list": listConfig.RouterOSList,
			"domain_count":  domainCount,
			"last_loaded":   lastModTime.Format("2006-01-02 15:04:05"),
		}
	}
	ds.mu.RUnlock()

	ds.blockMu.RLock()
	blockIPCount := len(ds.blockIPNets)
	ds.blockMu.RUnlock()

	status := map[string]interface{}{
		"hot_reload_enabled": ds.HotReloadEnabled,
		"reload_http_port":   ds.ReloadHTTPPort,
		"default_upstream":   ds.DefaultUpstream,
		"domain_lists":       lists,
		"block_ip_file":      ds.BlockIPFile,
		"block_ip_count":     blockIPCount,
		"routeros_enabled":   ds.RouterOSEnabled,
		"routeros_host":      ds.RouterOSHost,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// stopHTTPReloadServer 停止 HTTP 重载服务器
func (ds *DomainSwitch) stopHTTPReloadServer() {
	if ds.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := ds.httpServer.Shutdown(ctx); err != nil {
			logger.Errorf("HTTP reload server shutdown error: %v", err)
		} else {
			logger.Infof("HTTP reload server stopped")
		}
	}
}

// NewDomainSwitch 创建新的 DomainSwitch 插件实例
func NewDomainSwitch(defaultUpstream string) *DomainSwitch {
	return &DomainSwitch{
		DefaultUpstream: defaultUpstream,
		DomainLists:     make([]*DomainListConfig, 0),
		client: &dns.Client{
			Net:          "udp",
			Timeout:      5 * time.Second,
			DialTimeout:  2 * time.Second,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		// 热重载默认配置
		HotReloadEnabled: false,
		ReloadHTTPPort:   "8182", // 默认端口
	}
}

// addToRouterOS 将解析出的 IP 添加到 RouterOS 地址列表
func (ds *DomainSwitch) addToRouterOS(domain string, msg *dns.Msg, addressList string) {
	if msg == nil || len(msg.Answer) == 0 {
		return
	}

	// 提取所有 A 记录的 IP 地址
	var ips []string
	for _, answer := range msg.Answer {
		if a, ok := answer.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}

	if len(ips) == 0 {
		return
	}

	// 为每个 IP 添加到 RouterOS
	for _, ip := range ips {
		err := ds.addIPToRouterOS(ip, domain, addressList)
		if err != nil {
			logger.Warningf("Failed to add %s (%s) to RouterOS: %v", ip, domain, err)
		} else {
			logger.Infof("[RouterOS] Added %s (%s) to address-list %s", ip, domain, addressList)
		}
	}
}

// addIPToRouterOS 通过 RouterOS REST API 添加 IP 到地址列表
func (ds *DomainSwitch) addIPToRouterOS(ip, comment, addressList string) error {
	// RouterOS REST API URL
	url := fmt.Sprintf("http://%s/rest/ip/firewall/address-list/add", ds.RouterOSHost)

	// 构造请求体
	data := map[string]string{
		"list":    addressList,
		"address": ip,
		"comment": comment,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// 记录 POST 请求信息
	logger.Infof("[RouterOS POST] URL: %s", url)
	logger.Infof("[RouterOS POST] Method: POST")
	logger.Infof("[RouterOS POST] Headers: Content-Type=application/json, Authorization=Basic ***")
	logger.Infof("[RouterOS POST] Body: %s", string(jsonData))
	logger.Infof("[RouterOS POST] Target: %s (User: %s)", ds.RouterOSHost, ds.RouterOSUser)

	// 创建 HTTP 请求
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// 设置 HTTP Basic Auth
	req.SetBasicAuth(ds.RouterOSUser, ds.RouterOSPassword)
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	logger.Infof("[RouterOS POST] Sending request...")
	resp, err := ds.httpClient.Do(req)
	if err != nil {
		logger.Errorf("[RouterOS POST] Request failed: %v", err)
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, _ := io.ReadAll(resp.Body)

	// 记录响应信息
	logger.Infof("[RouterOS POST] Response Status: %d %s", resp.StatusCode, resp.Status)
	logger.Infof("[RouterOS POST] Response Headers: %v", resp.Header)
	logger.Infof("[RouterOS POST] Response Body: %s", string(body))

	// 检查响应状态
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		logger.Errorf("[RouterOS POST] API Error - Status: %d, Body: %s", resp.StatusCode, string(body))
		return fmt.Errorf("RouterOS API returned status %d: %s", resp.StatusCode, string(body))
	}

	logger.Infof("[RouterOS POST] Success - IP %s added to list %s", ip, addressList)
	return nil
}

// LoadBlockIPList 从文件加载 IP 黑名单（CIDR 格式）
func (ds *DomainSwitch) LoadBlockIPList(file string) error {
	logger.Infof("Loading IP block list from: %s", file)

	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open IP block list file: %v", err)
	}
	defer f.Close()

	ds.blockMu.Lock()
	defer ds.blockMu.Unlock()

	ds.blockIPNets = nil // 清空现有列表
	scanner := bufio.NewScanner(f)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析 CIDR
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			// 尝试解析单个 IP，自动添加 /32 或 /128
			ip := net.ParseIP(line)
			if ip != nil {
				var cidr string
				if ip.To4() != nil {
					cidr = line + "/32" // IPv4
				} else {
					cidr = line + "/128" // IPv6
				}
				_, ipNet, err = net.ParseCIDR(cidr)
			}
		}

		if err != nil {
			logger.Warningf("Invalid IP/CIDR format: %s, error: %v", line, err)
			continue
		}

		ds.blockIPNets = append(ds.blockIPNets, ipNet)
		count++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading IP block list: %v", err)
	}

	logger.Infof("Loaded %d IP blocks from %s", count, file)
	return nil
}

// containsBlockedIP 检查 DNS 响应是否包含黑名单中的 IP
func (ds *DomainSwitch) containsBlockedIP(msg *dns.Msg) bool {
	if msg == nil || len(msg.Answer) == 0 {
		return false
	}

	ds.blockMu.RLock()
	defer ds.blockMu.RUnlock()

	// 如果没有加载黑名单，直接返回 false
	if len(ds.blockIPNets) == 0 {
		return false
	}

	// 检查所有 A 记录的 IP 地址
	for _, answer := range msg.Answer {
		if a, ok := answer.(*dns.A); ok {
			ip := a.A
			if ds.isIPBlocked(ip) {
				logger.Infof("[BLOCKED] IP %s is in block list", ip.String())
				return true
			}
		}
		// 也检查 AAAA 记录（IPv6）
		if aaaa, ok := answer.(*dns.AAAA); ok {
			ip := aaaa.AAAA
			if ds.isIPBlocked(ip) {
				logger.Infof("[BLOCKED] IPv6 %s is in block list", ip.String())
				return true
			}
		}
	}

	return false
}

// isIPBlocked 检查单个 IP 是否在黑名单中
func (ds *DomainSwitch) isIPBlocked(ip net.IP) bool {
	for _, ipNet := range ds.blockIPNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}
