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

// DomainSwitch 实现智能 DNS 分流
type DomainSwitch struct {
	Next            plugin.Handler
	SpecialUpstream string // 特殊域名列表使用的上游 DNS
	DefaultUpstream string // 默认上游 DNS
	domainMap       map[string]struct{}
	mu              sync.RWMutex
	client          *dns.Client
	
	// RouterOS 配置
	RouterOSEnabled  bool
	RouterOSHost     string
	RouterOSUser     string
	RouterOSPassword string
	RouterOSList     string
	httpClient       *http.Client
}

// Name 返回插件名称
func (ds *DomainSwitch) Name() string { return "domainswitch" }

// ServeDNS 处理 DNS 查询
func (ds *DomainSwitch) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := strings.ToLower(strings.TrimSuffix(state.Name(), "."))

	// 检查域名是否在特殊列表中
	upstream := ds.getUpstream(qname)

	// 记录分流信息
	routeType := "DEFAULT"
	if upstream == ds.SpecialUpstream {
		routeType = "CHINA"
	}
	logger.Infof("[%s] %s -> %s", routeType, qname, upstream)

	// 转发 DNS 请求
	msg, _, err := ds.client.Exchange(r, net.JoinHostPort(upstream, "53"))
	if err != nil {
		logger.Errorf("Failed to query upstream %s: %v", upstream, err)
		return dns.RcodeServerFailure, err
	}

	// 如果是中国域名且启用了 RouterOS，提取 IP 并添加到地址列表
	if routeType == "CHINA" && ds.RouterOSEnabled && msg.Rcode == dns.RcodeSuccess {
		go ds.addToRouterOS(qname, msg)
	}

	// 写入响应
	err = w.WriteMsg(msg)
	if err != nil {
		logger.Errorf("Failed to write response: %v", err)
		return dns.RcodeServerFailure, err
	}

	return dns.RcodeSuccess, nil
}

// getUpstream 根据域名选择上游 DNS
func (ds *DomainSwitch) getUpstream(domain string) string {
	// 逐级检查域名（支持子域名匹配）
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		testDomain := strings.Join(parts[i:], ".")
		
		ds.mu.RLock()
		_, inList := ds.domainMap[testDomain]
		ds.mu.RUnlock()
		
		if inList {
			return ds.SpecialUpstream
		}
	}
	
	return ds.DefaultUpstream
}

// LoadList 从文件加载域名列表
func (ds *DomainSwitch) LoadList(file string) error {
	logger.Infof("Loading domain list from: %s", file)
	
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open domain list file: %v", err)
	}
	defer f.Close()

	ds.mu.Lock()
	defer ds.mu.Unlock()
	
	ds.domainMap = make(map[string]struct{}, 200000)
	scanner := bufio.NewScanner(f)
	count := 0
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// 提取域名（支持多种格式）
		domain := extractDomain(line)
		if domain != "" {
			ds.domainMap[strings.ToLower(domain)] = struct{}{}
			count++
		}
	}
	
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading domain list: %v", err)
	}
	
	logger.Infof("Loaded %d domains from %s", count, file)
	return nil
}

// extractDomain 从不同格式的行中提取域名
// 支持格式：
// - domain.com
// - server=/domain.com/114.114.114.114 (dnsmasq 格式)
func extractDomain(line string) string {
	// dnsmasq 格式: server=/domain.com/dns
	if strings.HasPrefix(line, "server=/") {
		parts := strings.Split(line, "/")
		if len(parts) >= 3 {
			return parts[1]
		}
	}
	
	// 纯域名格式
	return line
}

// NewDomainSwitch 创建新的 DomainSwitch 插件实例
func NewDomainSwitch(special, defaultUpstream string) *DomainSwitch {
	return &DomainSwitch{
		SpecialUpstream: special,
		DefaultUpstream: defaultUpstream,
		domainMap:       make(map[string]struct{}),
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
	}
}

// addToRouterOS 将解析出的 IP 添加到 RouterOS 地址列表
func (ds *DomainSwitch) addToRouterOS(domain string, msg *dns.Msg) {
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
		err := ds.addIPToRouterOS(ip, domain)
		if err != nil {
			logger.Warningf("Failed to add %s (%s) to RouterOS: %v", ip, domain, err)
		} else {
			logger.Infof("[RouterOS] Added %s (%s) to address-list %s", ip, domain, ds.RouterOSList)
		}
	}
}

// addIPToRouterOS 通过 RouterOS REST API 添加 IP 到地址列表
func (ds *DomainSwitch) addIPToRouterOS(ip, comment string) error {
	// RouterOS REST API URL
	url := fmt.Sprintf("https://%s/rest/ip/firewall/address-list/add", ds.RouterOSHost)

	// 构造请求体
	data := map[string]string{
		"list":    ds.RouterOSList,
		"address": ip,
		"comment": comment,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// 创建 HTTP 请求
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// 设置 HTTP Basic Auth
	req.SetBasicAuth(ds.RouterOSUser, ds.RouterOSPassword)
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := ds.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, _ := io.ReadAll(resp.Body)

	// 检查响应状态
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("RouterOS API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

