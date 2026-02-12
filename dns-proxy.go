package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/websocket"
)

// ============================================================================
// 配置和数据结构
// ============================================================================

// Config 统一配置
type Config struct {
	// DNS 配置
	DNSListen   string `json:"dns_listen"`   // DNS 监听地址
	UpstreamDNS string `json:"upstream_dns"` // 上游 DNS
	RedirectIP  string `json:"redirect_ip"`  // 拦截返回 IP

	// 代理配置
	ProxyListen []string `json:"proxy_listen"` // 代理监听地址
	Socks5Proxy string   `json:"socks5_proxy"` // SOCKS5 代理地址

	// 服务状态
	AutoStart bool `json:"auto_start"` // 启动时自动启动服务

	// 共享配置
	WebAddr string `json:"-"` // 管理界面地址（不保存到配置文件）
}

// SaveConfig 保存配置到文件
func (c *Config) SaveConfig(filename string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// LoadConfig 从文件加载配置
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// GetDefaultConfig 获取默认配置
func GetDefaultConfig() *Config {
	localIP := getLocalIP()
	return &Config{
		DNSListen:   localIP + ":53",
		UpstreamDNS: "119.29.29.29",
		RedirectIP:  localIP,
		ProxyListen: []string{"0.0.0.0:80", "0.0.0.0:443"},
		Socks5Proxy: "",
	}
}

// getLocalIP 获取本机IP地址
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

// normalizeUpstreamDNS 规范化上游DNS地址，如果没有端口则添加:53
func normalizeUpstreamDNS(upstream string) string {
	if upstream == "" {
		return ""
	}
	// 检查是否已经包含端口
	if strings.Contains(upstream, ":") {
		return upstream
	}
	// 没有端口，添加默认端口53
	return upstream + ":53"
}

// ValidateConfig 验证配置
func (c *Config) ValidateConfig() error {
	// 验证 DNS 监听地址
	if _, err := net.ResolveTCPAddr("tcp", c.DNSListen); err != nil {
		return fmt.Errorf("DNS 监听地址格式错误: %v", err)
	}

	// 验证上游 DNS
	upstreamDNS := normalizeUpstreamDNS(c.UpstreamDNS)
	if _, err := net.ResolveUDPAddr("udp", upstreamDNS); err != nil {
		return fmt.Errorf("上游 DNS 地址格式错误: %v", err)
	}

	// 验证拦截 IP
	if net.ParseIP(c.RedirectIP) == nil {
		return fmt.Errorf("拦截返回 IP 格式错误: %s", c.RedirectIP)
	}

	// 验证代理监听地址
	for _, addr := range c.ProxyListen {
		if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
			return fmt.Errorf("代理监听地址格式错误 (%s): %v", addr, err)
		}
	}

	// 验证代理地址（必填）
	if c.Socks5Proxy == "" {
		return fmt.Errorf("代理地址为必填项")
	}
	if _, err := parseProxyURL(c.Socks5Proxy); err != nil {
		return fmt.Errorf("代理地址格式错误: %v", err)
	}

	return nil
}

// getAllLocalIPs 获取所有本机IP地址
func getAllLocalIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return []string{"127.0.0.1"}
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}

	if len(ips) == 0 {
		return []string{"127.0.0.1"}
	}
	return ips
}

// RuleManager 规则管理器（共享）
type RuleManager struct {
	patterns   []string
	patternsMu sync.RWMutex
	filePath   string
}

// Metrics 服务指标统计
type Metrics struct {
	dnsQueries     int64 // DNS 查询总数
	dnsIntercepted int64 // 被拦截的查询
	proxyForwarded int64 // 代理转发次数
	proxySocks5    int64 // SOCKS5 代理转发次数
	proxyConns     int32 // 活跃代理连接数
}

// DNSLog DNS查询日志
type DNSLog struct {
	Time        time.Time `json:"time"`
	Domain      string    `json:"domain"`
	Intercepted bool      `json:"intercepted"`
	ClientIP    string    `json:"client_ip"`
}

// ProxyLog 代理转发日志
type ProxyLog struct {
	Time     time.Time `json:"time"`
	Protocol string    `json:"protocol"` // HTTP/HTTPS
	Host     string    `json:"host"`
	ClientIP string    `json:"client_ip"`
	Method   string    `json:"method"` // 仅HTTP有效
}

// LogManager 日志管理器
type LogManager struct {
	dnsLogs   []DNSLog
	proxyLogs []ProxyLog
	maxLogs   int // 最大保存日志数
	mu        sync.RWMutex
	wsClients map[*websocket.Conn]bool
	wsMu      sync.RWMutex
	metrics   *Metrics // 统计数据引用
	cfg       *Config  // 配置引用
}

// NewLogManager 创建日志管理器
func NewLogManager(maxLogs int, metrics *Metrics, cfg *Config) *LogManager {
	return &LogManager{
		dnsLogs:   make([]DNSLog, 0, maxLogs),
		proxyLogs: make([]ProxyLog, 0, maxLogs),
		maxLogs:   maxLogs,
		wsClients: make(map[*websocket.Conn]bool),
		metrics:   metrics,
		cfg:       cfg,
	}
}

// AddDNSLog 添加DNS查询日志
func (lm *LogManager) AddDNSLog(domain, clientIP string, intercepted bool) {
	lm.mu.Lock()
	log := DNSLog{
		Time:        time.Now(),
		Domain:      domain,
		Intercepted: intercepted,
		ClientIP:    clientIP,
	}

	lm.dnsLogs = append(lm.dnsLogs, log)
	if len(lm.dnsLogs) > lm.maxLogs {
		lm.dnsLogs = lm.dnsLogs[len(lm.dnsLogs)-lm.maxLogs:]
	}
	lm.mu.Unlock()

	// 广播到所有WebSocket客户端
	lm.broadcastDNSLog(log)
}

// AddProxyLog 添加代理转发日志
func (lm *LogManager) AddProxyLog(protocol, host, clientIP, method string) {
	lm.mu.Lock()
	log := ProxyLog{
		Time:     time.Now(),
		Protocol: protocol,
		Host:     host,
		ClientIP: clientIP,
		Method:   method,
	}

	lm.proxyLogs = append(lm.proxyLogs, log)
	if len(lm.proxyLogs) > lm.maxLogs {
		lm.proxyLogs = lm.proxyLogs[len(lm.proxyLogs)-lm.maxLogs:]
	}
	lm.mu.Unlock()

	// 广播到所有WebSocket客户端
	lm.broadcastProxyLog(log)
}

// GetDNSLogs 获取DNS日志（最新的N条）
func (lm *LogManager) GetDNSLogs(limit int) []DNSLog {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	if limit <= 0 || limit > len(lm.dnsLogs) {
		limit = len(lm.dnsLogs)
	}

	result := make([]DNSLog, limit)
	copy(result, lm.dnsLogs[len(lm.dnsLogs)-limit:])

	// 反转顺序，最新的在前面
	for i := 0; i < len(result)/2; i++ {
		result[i], result[len(result)-1-i] = result[len(result)-1-i], result[i]
	}

	return result
}

// GetProxyLogs 获取代理日志（最新的N条）
func (lm *LogManager) GetProxyLogs(limit int) []ProxyLog {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	if limit <= 0 || limit > len(lm.proxyLogs) {
		limit = len(lm.proxyLogs)
	}

	result := make([]ProxyLog, limit)
	copy(result, lm.proxyLogs[len(lm.proxyLogs)-limit:])

	// 反转顺序，最新的在前面
	for i := 0; i < len(result)/2; i++ {
		result[i], result[len(result)-1-i] = result[len(result)-1-i], result[i]
	}

	return result
}

// AddWSClient 添加WebSocket客户端
func (lm *LogManager) AddWSClient(ws *websocket.Conn) {
	lm.wsMu.Lock()
	defer lm.wsMu.Unlock()
	lm.wsClients[ws] = true
}

// RemoveWSClient 移除WebSocket客户端
func (lm *LogManager) RemoveWSClient(ws *websocket.Conn) {
	lm.wsMu.Lock()
	defer lm.wsMu.Unlock()
	delete(lm.wsClients, ws)
	ws.Close()
}

// getProxyConfig 获取代理配置信息
func (lm *LogManager) getProxyConfig() map[string]interface{} {
	proxyStatus := "未配置"
	proxyType := "代理"

	if lm.cfg.Socks5Proxy != "" {
		proxyCfg, err := parseProxyURL(lm.cfg.Socks5Proxy)
		if err == nil {
			if proxyCfg.Type == "socks5" {
				proxyType = "SOCKS5 代理"
			} else {
				proxyType = "HTTP 代理"
			}
		}
		proxyStatus = "已配置: " + lm.cfg.Socks5Proxy
	}

	return map[string]interface{}{
		"proxyType":   proxyType,
		"proxyStatus": proxyStatus,
	}
}

// broadcastDNSLog 广播DNS日志到所有客户端
func (lm *LogManager) broadcastDNSLog(log DNSLog) {
	lm.wsMu.RLock()
	defer lm.wsMu.RUnlock()

	message := map[string]interface{}{
		"type": "dns",
		"data": log,
		"stats": map[string]interface{}{
			"dnsQueries":     atomic.LoadInt64(&lm.metrics.dnsQueries),
			"dnsIntercepted": atomic.LoadInt64(&lm.metrics.dnsIntercepted),
			"proxyConns":     atomic.LoadInt32(&lm.metrics.proxyConns),
			"proxyForwarded": atomic.LoadInt64(&lm.metrics.proxyForwarded),
			"proxySocks5":    atomic.LoadInt64(&lm.metrics.proxySocks5),
		},
		"config": lm.getProxyConfig(),
	}

	data, err := json.Marshal(message)
	if err != nil {
		return
	}

	for ws := range lm.wsClients {
		if err := websocket.Message.Send(ws, string(data)); err != nil {
			// 发送失败，稍后会被清理
		}
	}
}

// broadcastProxyLog 广播代理日志到所有客户端
func (lm *LogManager) broadcastProxyLog(log ProxyLog) {
	lm.wsMu.RLock()
	defer lm.wsMu.RUnlock()

	message := map[string]interface{}{
		"type": "proxy",
		"data": log,
		"stats": map[string]interface{}{
			"dnsQueries":     atomic.LoadInt64(&lm.metrics.dnsQueries),
			"dnsIntercepted": atomic.LoadInt64(&lm.metrics.dnsIntercepted),
			"proxyConns":     atomic.LoadInt32(&lm.metrics.proxyConns),
			"proxyForwarded": atomic.LoadInt64(&lm.metrics.proxyForwarded),
			"proxySocks5":    atomic.LoadInt64(&lm.metrics.proxySocks5),
		},
		"config": lm.getProxyConfig(),
	}

	data, err := json.Marshal(message)
	if err != nil {
		return
	}

	for ws := range lm.wsClients {
		if err := websocket.Message.Send(ws, string(data)); err != nil {
			// 发送失败，稍后会被清理
		}
	}
}

// BroadcastConfigUpdate 广播配置更新到所有客户端
func (lm *LogManager) BroadcastConfigUpdate() {
	lm.wsMu.RLock()
	defer lm.wsMu.RUnlock()

	message := map[string]interface{}{
		"type": "config",
		"stats": map[string]interface{}{
			"dnsQueries":     atomic.LoadInt64(&lm.metrics.dnsQueries),
			"dnsIntercepted": atomic.LoadInt64(&lm.metrics.dnsIntercepted),
			"proxyConns":     atomic.LoadInt32(&lm.metrics.proxyConns),
			"proxyForwarded": atomic.LoadInt64(&lm.metrics.proxyForwarded),
			"proxySocks5":    atomic.LoadInt64(&lm.metrics.proxySocks5),
		},
		"config": lm.getProxyConfig(),
	}

	data, err := json.Marshal(message)
	if err != nil {
		return
	}

	for ws := range lm.wsClients {
		if err := websocket.Message.Send(ws, string(data)); err != nil {
			// 发送失败，稍后会被清理
		}
	}
}

// ServiceManager 服务管理器
type ServiceManager struct {
	cfg            *Config
	ruleMgr        *RuleManager
	metrics        *Metrics
	logMgr         *LogManager
	running        bool
	mu             sync.RWMutex
	stopChan       chan struct{}
	dnsConn        *net.UDPConn
	proxyListeners []net.Listener
}

// NewServiceManager 创建服务管理器
func NewServiceManager(cfg *Config) *ServiceManager {
	metrics := &Metrics{}
	return &ServiceManager{
		cfg:      cfg,
		ruleMgr:  NewRuleManager("gfwlist.txt"),
		metrics:  metrics,
		logMgr:   NewLogManager(1000, metrics, cfg), // 保存最近1000条日志，传入 metrics 和 cfg
		running:  false,
		stopChan: make(chan struct{}),
	}
}

// Start 启动所有服务
func (sm *ServiceManager) Start() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.running {
		return fmt.Errorf("服务已在运行中")
	}

	// 加载规则
	if err := sm.ruleMgr.Load(); err != nil {
		log.Printf("警告: 加载规则失败: %v", err)
	}

	// 启动 DNS 服务
	if err := sm.startDNS(); err != nil {
		return fmt.Errorf("DNS 服务启动失败: %v", err)
	}

	// 启动代理服务
	if err := sm.startProxy(); err != nil {
		sm.stopDNS()
		return fmt.Errorf("代理服务启动失败: %v", err)
	}

	sm.running = true
	log.Println("所有服务已启动")
	return nil
}

// Stop 停止所有服务
func (sm *ServiceManager) Stop() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.running {
		return fmt.Errorf("服务未运行")
	}

	close(sm.stopChan)
	sm.stopDNS()
	sm.stopProxy()

	sm.running = false
	sm.stopChan = make(chan struct{})
	log.Println("所有服务已停止")
	return nil
}

// IsRunning 检查服务是否运行中
func (sm *ServiceManager) IsRunning() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.running
}

// startDNS 启动 DNS 服务
func (sm *ServiceManager) startDNS() error {
	addr, err := net.ResolveUDPAddr("udp", sm.cfg.DNSListen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	sm.dnsConn = conn

	go func() {
		buf := make([]byte, 512)
		for {
			select {
			case <-sm.stopChan:
				return
			default:
				sm.dnsConn.SetReadDeadline(time.Now().Add(1 * time.Second))
				n, clientAddr, err := sm.dnsConn.ReadFromUDP(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					return
				}
				go sm.handleDNSQuery(buf[:n], clientAddr)
			}
		}
	}()

	log.Printf("[DNS] 正在监听 %s", sm.cfg.DNSListen)
	return nil
}

// stopDNS 停止 DNS 服务
func (sm *ServiceManager) stopDNS() {
	if sm.dnsConn != nil {
		sm.dnsConn.Close()
		sm.dnsConn = nil
	}
}

// startProxy 启动代理服务
func (sm *ServiceManager) startProxy() error {
	sm.proxyListeners = make([]net.Listener, 0)
	for _, addr := range sm.cfg.ProxyListen {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			sm.stopProxy()
			return fmt.Errorf("无法监听 %s: %v", addr, err)
		}
		sm.proxyListeners = append(sm.proxyListeners, l)
		log.Printf("[Proxy] 正在监听 %s", addr)

		go func(listener net.Listener) {
			for {
				select {
				case <-sm.stopChan:
					return
				default:
					conn, err := listener.Accept()
					if err != nil {
						select {
						case <-sm.stopChan:
							return
						default:
							continue
						}
					}
					go sm.handleProxyConnection(conn)
				}
			}
		}(l)
	}
	return nil
}

// stopProxy 停止代理服务
func (sm *ServiceManager) stopProxy() {
	for _, l := range sm.proxyListeners {
		if l != nil {
			l.Close()
		}
	}
	sm.proxyListeners = nil
}

// handleDNSQuery 处理 DNS 查询
func (sm *ServiceManager) handleDNSQuery(data []byte, clientAddr *net.UDPAddr) {
	atomic.AddInt64(&sm.metrics.dnsQueries, 1)

	if len(data) < 12 {
		return
	}

	domain := parseDNSDomain(data)
	if domain == "" {
		return
	}

	clientIP := clientAddr.IP.String()

	if sm.ruleMgr.Match(domain) {
		atomic.AddInt64(&sm.metrics.dnsIntercepted, 1)
		sm.logMgr.AddDNSLog(domain, clientIP, true)
		response := buildDNSResponse(data, sm.cfg.RedirectIP)
		sm.dnsConn.WriteToUDP(response, clientAddr)
		return
	}

	sm.logMgr.AddDNSLog(domain, clientIP, false)

	upstreamDNS := normalizeUpstreamDNS(sm.cfg.UpstreamDNS)
	upstreamAddr, _ := net.ResolveUDPAddr("udp", upstreamDNS)
	upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		return
	}
	defer upstreamConn.Close()

	upstreamConn.Write(data)
	upstreamConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := upstreamConn.Read(buf)
	if err == nil {
		sm.dnsConn.WriteToUDP(buf[:n], clientAddr)
	}
}

// handleProxyConnection 处理代理连接
func (sm *ServiceManager) handleProxyConnection(conn net.Conn) {
	atomic.AddInt32(&sm.metrics.proxyConns, 1)
	defer func() {
		atomic.AddInt32(&sm.metrics.proxyConns, -1)
		conn.Close()
	}()

	listenPort, err := getLocalPort(conn)
	if err != nil {
		return
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	if n > 0 && buf[0] == 0x16 {
		sm.handleHTTPS(conn, listenPort, buf[:n])
	} else {
		sm.handleHTTP(conn, listenPort, buf[:n])
	}
}

// handleHTTP 处理 HTTP 连接
func (sm *ServiceManager) handleHTTP(conn net.Conn, listenPort string, initialData []byte) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	host := req.Host
	if host == "" {
		return
	}

	targetHost := host
	if strings.Contains(targetHost, ":") {
		if h, _, err := net.SplitHostPort(targetHost); err == nil {
			targetHost = h
		}
	}

	// 记录客户端IP
	clientIP := conn.RemoteAddr().String()
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = tcpAddr.IP.String()
	}

	var forwardConn net.Conn
	if sm.cfg.Socks5Proxy != "" {
		proxyCfg, err := parseProxyURL(sm.cfg.Socks5Proxy)
		if err != nil {
			return
		}
		if proxyCfg.Type == "socks5" {
			forwardConn, err = dialViaSocks5(proxyCfg, targetHost, listenPort)
		} else {
			forwardConn, err = dialViaHTTP(proxyCfg, targetHost, listenPort)
		}
		if err != nil {
			return
		}
		atomic.AddInt64(&sm.metrics.proxySocks5, 1)
	} else {
		forwardAddr := net.JoinHostPort(targetHost, listenPort)
		forwardConn, err = net.Dial("tcp", forwardAddr)
		if err != nil {
			return
		}
	}
	defer forwardConn.Close()

	// 记录HTTP代理日志
	sm.logMgr.AddProxyLog("HTTP", host, clientIP, req.Method)

	forwardConn.Write(initialData)
	atomic.AddInt64(&sm.metrics.proxyForwarded, 1)
	handleTCPForward(conn, forwardConn)
}

// handleHTTPS 处理 HTTPS 连接
func (sm *ServiceManager) handleHTTPS(conn net.Conn, listenPort string, initialData []byte) {
	clientHello, fullHello, err := readClientHello(conn, initialData)
	if err != nil {
		return
	}

	sni := clientHello.ServerName
	if sni == "" {
		return
	}

	// 记录客户端IP
	clientIP := conn.RemoteAddr().String()
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = tcpAddr.IP.String()
	}

	var forwardConn net.Conn
	if sm.cfg.Socks5Proxy != "" {
		proxyCfg, err := parseProxyURL(sm.cfg.Socks5Proxy)
		if err != nil {
			return
		}
		if proxyCfg.Type == "socks5" {
			forwardConn, err = dialViaSocks5(proxyCfg, sni, listenPort)
		} else {
			forwardConn, err = dialViaHTTP(proxyCfg, sni, listenPort)
		}
		if err != nil {
			return
		}
		atomic.AddInt64(&sm.metrics.proxySocks5, 1)
	} else {
		forwardAddr := net.JoinHostPort(sni, listenPort)
		forwardConn, err = net.Dial("tcp", forwardAddr)
		if err != nil {
			return
		}
	}
	defer forwardConn.Close()

	// 记录HTTPS代理日志
	sm.logMgr.AddProxyLog("HTTPS", sni, clientIP, "")

	forwardConn.Write(fullHello)
	atomic.AddInt64(&sm.metrics.proxyForwarded, 1)
	handleTCPForward(conn, forwardConn)
}

// ProxyConfig 代理配置结构
type ProxyConfig struct {
	Type     string // "socks5" 或 "http"
	Host     string
	Port     string
	Username string
	Password string
}

// DNSHeader 表示 DNS 头（固定 12 字节）
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// parseDNSDomain 解析 DNS 查询中的域名
func parseDNSDomain(data []byte) string {
	if len(data) < 13 {
		return ""
	}
	pos := 12
	var domain []string
	for pos < len(data) {
		length := int(data[pos])
		if length == 0 {
			break
		}
		pos++
		if pos+length > len(data) {
			return ""
		}
		domain = append(domain, string(data[pos:pos+length]))
		pos += length
	}
	return strings.Join(domain, ".")
}

// buildDNSResponse 构建 DNS 响应
func buildDNSResponse(query []byte, ip string) []byte {
	response := make([]byte, len(query)+16)
	copy(response, query)

	// 设置响应标志
	response[2] = 0x81
	response[3] = 0x80

	// 设置回答数量
	response[6] = 0x00
	response[7] = 0x01

	// 添加回答记录
	pos := len(query)
	response[pos] = 0xc0
	response[pos+1] = 0x0c
	response[pos+2] = 0x00
	response[pos+3] = 0x01
	response[pos+4] = 0x00
	response[pos+5] = 0x01
	response[pos+6] = 0x00
	response[pos+7] = 0x00
	response[pos+8] = 0x00
	response[pos+9] = 0x3c
	response[pos+10] = 0x00
	response[pos+11] = 0x04

	// 添加 IP 地址
	parts := strings.Split(ip, ".")
	for i, part := range parts {
		if val, err := strconv.Atoi(part); err == nil {
			response[pos+12+i] = byte(val)
		}
	}

	return response[:pos+16]
}

// ============================================================================
// RuleManager 方法
// ============================================================================

// NewRuleManager 创建规则管理器
func NewRuleManager(filePath string) *RuleManager {
	return &RuleManager{
		filePath: filePath,
		patterns: []string{},
	}
}

// Load 加载规则文件
func (rm *RuleManager) Load() error {
	patterns, err := parseGFWList(rm.filePath)
	if err != nil {
		return err
	}
	rm.patternsMu.Lock()
	rm.patterns = patterns
	rm.patternsMu.Unlock()
	return nil
}

// Reload 重新加载规则
func (rm *RuleManager) Reload() error {
	patterns, err := parseGFWList(rm.filePath)
	if err != nil {
		return err
	}
	rm.patternsMu.Lock()
	rm.patterns = patterns
	rm.patternsMu.Unlock()
	log.Printf("[管理] 已重新载入 %d 条规则", len(patterns))
	return nil
}

// Match 匹配域名
func (rm *RuleManager) Match(domain string) bool {
	rm.patternsMu.RLock()
	defer rm.patternsMu.RUnlock()
	return matchDomain(domain, rm.patterns)
}

// GetPatterns 获取规则列表
func (rm *RuleManager) GetPatterns() []string {
	rm.patternsMu.RLock()
	defer rm.patternsMu.RUnlock()
	result := make([]string, len(rm.patterns))
	copy(result, rm.patterns)
	return result
}

// SavePatterns 保存规则
func (rm *RuleManager) SavePatterns(content string) error {
	// 去重、清理并排序规则
	lines := strings.Split(content, "\n")
	seen := make(map[string]struct{})
	var unique []string
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if _, ok := seen[ln]; ok {
			continue
		}
		seen[ln] = struct{}{}
		unique = append(unique, ln)
	}
	// 按字母顺序排序
	sort.Strings(unique)
	cleaned := strings.Join(unique, "\n")

	if err := os.WriteFile(rm.filePath, []byte(cleaned), 0644); err != nil {
		return err
	}
	return rm.Reload()
}

// MergeAndSavePatterns 合并新规则并保存
func (rm *RuleManager) MergeAndSavePatterns(newPatterns []string) error {
	rm.patternsMu.Lock()
	defer rm.patternsMu.Unlock()

	// 使用 map 去重
	seen := make(map[string]struct{})
	for _, p := range rm.patterns {
		seen[p] = struct{}{}
	}

	var added int
	for _, p := range newPatterns {
		if _, exists := seen[p]; !exists {
			seen[p] = struct{}{}
			rm.patterns = append(rm.patterns, p)
			added++
		}
	}

	// 排序
	sort.Strings(rm.patterns)

	// 保存到文件
	content := strings.Join(rm.patterns, "\n")
	if err := os.WriteFile(rm.filePath, []byte(content), 0644); err != nil {
		return err
	}

	log.Printf("[RuleManager] 合并完成: 新增 %d 条规则，总计 %d 条", added, len(rm.patterns))
	return nil
}

func (rm *RuleManager) UpdateFromURL(rawURL string) error {
	resp, err := http.Get(rawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取失败，状态码: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	patterns, err := parseGFWListBytes(body)
	if err != nil {
		return err
	}
	return rm.MergeAndSavePatterns(patterns)
}

func fetchViaProxy(proxyStr, targetURL string) ([]byte, error) {
	if proxyStr == "" {
		return nil, fmt.Errorf("未配置前置代理")
	}
	proxyCfg, err := parseProxyURL(proxyStr)
	if err != nil {
		return nil, err
	}
	if proxyCfg.Type == "socks5" {
		u, err := url.Parse(targetURL)
		if err != nil {
			return nil, err
		}
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		conn, err := dialViaSocks5(proxyCfg, host, port)
		if err != nil {
			return nil, err
		}
		var rw io.ReadWriteCloser = conn
		if u.Scheme == "https" {
			tlsConn := tls.Client(conn, &tls.Config{ServerName: host})
			rw = tlsConn
		}
		req, _ := http.NewRequest("GET", u.RequestURI(), nil)
		req.Host = host
		req.Header.Set("User-Agent", "dns-proxy")
		req.Header.Set("Connection", "close")
		if err := req.Write(rw); err != nil {
			rw.Close()
			return nil, err
		}
		br := bufio.NewReader(rw)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			rw.Close()
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		rw.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("获取失败，状态码: %d", resp.StatusCode)
		}
		return body, err
	}
	proxyURL := &url.URL{Scheme: "http", Host: net.JoinHostPort(proxyCfg.Host, proxyCfg.Port)}
	if proxyCfg.Username != "" {
		proxyURL.User = url.UserPassword(proxyCfg.Username, proxyCfg.Password)
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	resp, err := client.Get(targetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取失败，状态码: %d", resp.StatusCode)
	}
	return body, err
}

func (rm *RuleManager) UpdateFromURLViaProxy(proxyStr, rawURL string) error {
	body, err := fetchViaProxy(proxyStr, rawURL)
	if err != nil {
		return err
	}
	patterns, err := parseGFWListBytes(body)
	if err != nil {
		return err
	}
	return rm.MergeAndSavePatterns(patterns)
}

// ============================================================================
// DNS 服务相关函数
// ============================================================================

// parseQuestion 解析查询报文中的问题部分
func parseQuestion(msg []byte) (domain string, qtype uint16, qclass uint16, endOffset int, err error) {
	if len(msg) < 12 {
		err = fmt.Errorf("无效的 DNS 报文")
		return
	}
	offset := 12
	var labels []string
	for {
		if offset >= len(msg) {
			err = fmt.Errorf("偏移量超出报文长度")
			return
		}
		l := int(msg[offset])
		offset++
		if l == 0 {
			break
		}
		if offset+l > len(msg) {
			err = fmt.Errorf("域名标签长度非法")
			return
		}
		labels = append(labels, string(msg[offset:offset+l]))
		offset += l
	}
	if offset+4 > len(msg) {
		err = fmt.Errorf("缺少查询类型或类")
		return
	}
	domain = strings.ToLower(strings.Join(labels, "."))
	qtype = binary.BigEndian.Uint16(msg[offset : offset+2])
	qclass = binary.BigEndian.Uint16(msg[offset+2 : offset+4])
	endOffset = offset + 4
	return
}

// buildResponse 构造 DNS 响应
func buildResponse(query []byte, questionEnd int, ip string) ([]byte, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("无效的 IP: %s", ip)
	}
	response := make([]byte, questionEnd)
	copy(response, query[:questionEnd])

	flags := binary.BigEndian.Uint16(response[2:4])
	flags |= 0x8000  // QR=1 (response)
	flags |= 0x0080  // RA=1 (recursion available)
	flags &^= 0x0200 // clear TC
	binary.BigEndian.PutUint16(response[2:4], flags)

	binary.BigEndian.PutUint16(response[6:8], 1) // ANCOUNT = 1

	var ans []byte
	if ipv4 := parsedIP.To4(); ipv4 != nil {
		ans = make([]byte, 16)
		ans[0] = 0xC0
		ans[1] = 0x0C
		binary.BigEndian.PutUint16(ans[2:4], 1)    // TYPE A
		binary.BigEndian.PutUint16(ans[4:6], 1)    // CLASS IN
		binary.BigEndian.PutUint32(ans[6:10], 300) // TTL
		binary.BigEndian.PutUint16(ans[10:12], 4)  // RDLENGTH
		copy(ans[12:16], ipv4)
	} else {
		ans = make([]byte, 28)
		ans[0] = 0xC0
		ans[1] = 0x0C
		binary.BigEndian.PutUint16(ans[2:4], 28)   // TYPE AAAA
		binary.BigEndian.PutUint16(ans[4:6], 1)    // CLASS IN
		binary.BigEndian.PutUint32(ans[6:10], 300) // TTL
		binary.BigEndian.PutUint16(ans[10:12], 16) // RDLENGTH
		copy(ans[12:28], parsedIP.To16())
	}

	response = append(response, ans...)
	return response, nil
}

// buildEmptyResponse 构造空响应
func buildEmptyResponse(query []byte, questionEnd int) []byte {
	resp := make([]byte, questionEnd)
	copy(resp, query[:questionEnd])
	flags := binary.BigEndian.Uint16(resp[2:4])
	flags |= 0x8000  // QR=1
	flags |= 0x0080  // RA=1
	flags &^= 0x0200 // 清 TC
	binary.BigEndian.PutUint16(resp[2:4], flags)
	return resp
}

// parseGFWList 解析 gfwlist 文件
func parseGFWList(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseGFWListBytes(b)
}

func parseGFWListBytes(b []byte) ([]string, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		decoded = b
	}
	var domains []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(decoded))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		host := extractDomainFromRule(line)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		domains = append(domains, host)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

var domainRe = regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]{2,}$`)

func isValidDomain(s string) bool {
	if len(s) == 0 {
		return false
	}
	if strings.ContainsAny(s, " \t/[]{}()") {
		return false
	}
	return domainRe.MatchString(s)
}

func extractDomainFromRule(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
		return ""
	}
	if strings.HasPrefix(line, "@@") {
		return ""
	}
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err == nil {
			h := u.Hostname()
			h = strings.TrimSuffix(h, ".")
			h = strings.ToLower(h)
			if isValidDomain(h) {
				return h
			}
		}
		return ""
	}
	line = strings.Trim(line, "|")
	line = strings.TrimPrefix(line, "||")
	line = strings.TrimPrefix(line, ".")
	if idx := strings.Index(line, "/"); idx != -1 {
		line = line[:idx]
	}
	line = strings.ReplaceAll(line, "*", "")
	line = strings.ReplaceAll(line, "^", "")
	line = strings.Trim(line, ".")
	line = strings.ToLower(line)
	if line == "" || line == "http" || line == "https" {
		return ""
	}
	if strings.Contains(line, ":") {
		if h, _, err := net.SplitHostPort(line); err == nil {
			line = h
		} else {
			parts := strings.Split(line, ":")
			line = parts[0]
		}
	}
	if isValidDomain(line) {
		return line
	}
	return ""
}

// matchDomain 判断域名是否匹配规则
func matchDomain(domain string, patterns []string) bool {
	for _, p := range patterns {
		if domain == p || strings.HasSuffix(domain, "."+p) {
			return true
		}
	}
	return false
}

// handleQuery 处理 DNS 查询
func handleQuery(serverConn *net.UDPConn, clientAddr *net.UDPAddr, query []byte, cfg *Config, ruleMgr *RuleManager, metrics *Metrics) {
	atomic.AddInt64(&metrics.dnsQueries, 1)

	var resp []byte
	domain, qtype, _, qEnd, err := parseQuestion(query)
	if err != nil {
		log.Printf("[DNS] 解析问题失败: %v", err)
		return
	}

	if ruleMgr.Match(domain) {
		ip := net.ParseIP(cfg.RedirectIP)
		if ip == nil {
			log.Printf("[DNS] 无效的重定向 IP: %s", cfg.RedirectIP)
		} else {
			var shouldIntercept bool
			if ip.To4() != nil {
				if qtype == 1 {
					resp, err = buildResponse(query, qEnd, cfg.RedirectIP)
					shouldIntercept = true
				} else {
					resp = buildEmptyResponse(query, qEnd)
					shouldIntercept = true
				}
			} else {
				if qtype == 28 {
					resp, err = buildResponse(query, qEnd, cfg.RedirectIP)
					shouldIntercept = true
				} else {
					resp = buildEmptyResponse(query, qEnd)
					shouldIntercept = true
				}
			}
			if err != nil {
				log.Printf("[DNS] 构造响应失败: %v", err)
				return
			}
			if shouldIntercept && resp != nil {
				_, _ = serverConn.WriteToUDP(resp, clientAddr)
				atomic.AddInt64(&metrics.dnsIntercepted, 1)
				log.Printf("[DNS] 拦截 %s (qtype=%d) -> %s", domain, qtype, cfg.RedirectIP)
				return
			}
		}
	}

	// 转发到上游 DNS
	upstreamDNS := normalizeUpstreamDNS(cfg.UpstreamDNS)
	upstreamAddr, err := net.ResolveUDPAddr("udp", upstreamDNS)
	if err != nil {
		log.Printf("[DNS] 解析上游 DNS 失败: %v", err)
		return
	}
	upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		log.Printf("[DNS] 连接上游 DNS 失败: %v", err)
		return
	}
	defer upstreamConn.Close()

	_, err = upstreamConn.Write(query)
	if err != nil {
		log.Printf("[DNS] 转发请求失败: %v", err)
		return
	}
	upstreamConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	bufResp := make([]byte, 512)
	n, err := upstreamConn.Read(bufResp)
	if err != nil {
		log.Printf("[DNS] 读取上游响应失败: %v", err)
		return
	}
	_, err = serverConn.WriteToUDP(bufResp[:n], clientAddr)
	if err != nil {
		log.Printf("[DNS] 发送响应给客户端失败: %v", err)
	}
}

// startDNSServer 启动 DNS 服务
func startDNSServer(cfg *Config, ruleMgr *RuleManager, metrics *Metrics) error {
	laddr, err := net.ResolveUDPAddr("udp", cfg.DNSListen)
	if err != nil {
		return fmt.Errorf("解析监听地址失败: %v", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("监听 UDP 端口失败: %v", err)
	}
	defer conn.Close()
	log.Printf("[DNS] 服务器已在 %s 上监听", cfg.DNSListen)

	buf := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[DNS] 读取 UDP 数据失败: %v", err)
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		go handleQuery(conn, addr, data, cfg, ruleMgr, metrics)
	}
}

// ============================================================================
// 代理相关函数
// ============================================================================

// parseProxyURL 解析代理 URL (支持 socks5:// 和 http://)
func parseProxyURL(proxyURL string) (*ProxyConfig, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("解析代理 URL 失败: %v", err)
	}

	proxyType := strings.ToLower(u.Scheme)
	if proxyType != "socks5" && proxyType != "http" && proxyType != "https" {
		return nil, fmt.Errorf("不支持的代理协议: %s (仅支持 socks5, http, https)", u.Scheme)
	}

	// http 和 https 都视为 HTTP 代理
	if proxyType == "https" {
		proxyType = "http"
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if proxyType == "socks5" {
			port = "1080"
		} else {
			port = "8080"
		}
	}

	cfg := &ProxyConfig{
		Type: proxyType,
		Host: host,
		Port: port,
	}

	if u.User != nil {
		cfg.Username = u.User.Username()
		cfg.Password, _ = u.User.Password()
	}

	return cfg, nil
}

// dialViaHTTP 通过 HTTP 代理建立连接
func dialViaHTTP(proxyCfg *ProxyConfig, targetHost string, targetPort string) (net.Conn, error) {
	// 连接到 HTTP 代理服务器
	conn, err := net.Dial("tcp", net.JoinHostPort(proxyCfg.Host, proxyCfg.Port))
	if err != nil {
		return nil, fmt.Errorf("连接 HTTP 代理服务器失败: %v", err)
	}

	// 构造 CONNECT 请求
	connectReq := fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n",
		targetHost, targetPort, targetHost, targetPort)

	// 如果有认证信息，添加 Proxy-Authorization 头
	if proxyCfg.Username != "" {
		auth := proxyCfg.Username + ":" + proxyCfg.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(auth))
		connectReq += "Proxy-Authorization: Basic " + encoded + "\r\n"
	}

	connectReq += "\r\n"

	// 发送 CONNECT 请求
	_, err = conn.Write([]byte(connectReq))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("发送 CONNECT 请求失败: %v", err)
	}

	// 读取响应
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("读取 HTTP 代理响应失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("HTTP 代理连接失败，状态码: %d %s", resp.StatusCode, resp.Status)
	}

	return conn, nil
}

func dialViaSocks5(socks5Cfg *ProxyConfig, targetHost string, targetPort string) (net.Conn, error) {
	// 连接到 SOCKS5 服务器
	conn, err := net.Dial("tcp", net.JoinHostPort(socks5Cfg.Host, socks5Cfg.Port))
	if err != nil {
		return nil, fmt.Errorf("连接 SOCKS5 服务器失败: %v", err)
	}

	// 认证方法协商
	authMethod := byte(0x00) // 无认证
	if socks5Cfg.Username != "" {
		authMethod = 0x02 // 用户名/密码认证
	}

	// 发送认证方法
	_, err = conn.Write([]byte{0x05, 0x01, authMethod})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("发送认证方法失败: %v", err)
	}

	// 读取服务器选择的认证方法
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("读取认证方法响应失败: %v", err)
	}
	if buf[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 版本错误: %d", buf[0])
	}
	if buf[1] == 0xFF {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 服务器拒绝所有认证方法")
	}

	// 如果需要用户名/密码认证
	if buf[1] == 0x02 {
		// 构造认证请求
		authReq := []byte{0x01} // 认证协议版本
		authReq = append(authReq, byte(len(socks5Cfg.Username)))
		authReq = append(authReq, []byte(socks5Cfg.Username)...)
		authReq = append(authReq, byte(len(socks5Cfg.Password)))
		authReq = append(authReq, []byte(socks5Cfg.Password)...)

		_, err = conn.Write(authReq)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("发送认证信息失败: %v", err)
		}

		// 读取认证响应
		authResp := make([]byte, 2)
		_, err = io.ReadFull(conn, authResp)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("读取认证响应失败: %v", err)
		}
		if authResp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 认证失败")
		}
	}

	// 发送连接请求
	req := []byte{0x05, 0x01, 0x00, 0x03} // VER, CMD=CONNECT, RSV, ATYP=DOMAINNAME
	req = append(req, byte(len(targetHost)))
	req = append(req, []byte(targetHost)...)
	portNum, _ := strconv.Atoi(targetPort)
	req = append(req, byte(portNum>>8), byte(portNum&0xFF))

	_, err = conn.Write(req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("发送连接请求失败: %v", err)
	}

	// 读取连接响应
	resp := make([]byte, 4)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("读取连接响应失败: %v", err)
	}
	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 连接失败，错误码: %d", resp[1])
	}

	// 读取绑定地址（根据 ATYP 读取不同长度）
	atyp := resp[3]
	switch atyp {
	case 0x01: // IPv4
		io.ReadFull(conn, make([]byte, 4+2))
	case 0x03: // 域名
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		io.ReadFull(conn, make([]byte, int(lenBuf[0])+2))
	case 0x04: // IPv6
		io.ReadFull(conn, make([]byte, 16+2))
	}

	return conn, nil
}

// ============================================================================
// 代理服务相关函数
// ============================================================================

// handleTCPForward 双向转发 TCP 数据（优化 HTTP/2 支持）
func handleTCPForward(clientConn, serverConn net.Conn) {
	// 设置 TCP_NODELAY，禁用 Nagle 算法，减少延迟
	if tcp, ok := clientConn.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	}
	if tcp, ok := serverConn.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	}

	// 设置读写超时，避免连接长时间挂起
	idleTimeout := 5 * time.Minute

	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 -> 服务器
	go func() {
		defer wg.Done()
		copyWithTimeout(serverConn, clientConn, idleTimeout)
		if tcp, ok := serverConn.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	// 服务器 -> 客户端
	go func() {
		defer wg.Done()
		copyWithTimeout(clientConn, serverConn, idleTimeout)
		if tcp, ok := clientConn.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	wg.Wait()
}

// copyWithTimeout 使用小缓冲区和超时机制进行数据复制（优化 HTTP/2）
func copyWithTimeout(dst, src net.Conn, timeout time.Duration) (written int64, err error) {
	// 使用 8KB 缓冲区，减少 HTTP/2 帧延迟
	buf := make([]byte, 8192)

	for {
		// 设置读超时
		src.SetReadDeadline(time.Now().Add(timeout))

		nr, er := src.Read(buf)
		if nr > 0 {
			// 设置写超时
			dst.SetWriteDeadline(time.Now().Add(timeout))

			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF && !isTimeoutError(er) {
				err = er
			}
			break
		}
	}
	return written, err
}

// isTimeoutError 检查是否为超时错误
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// getLocalPort 获取本地监听端口
func getLocalPort(conn net.Conn) (string, error) {
	if ta, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		return strconv.Itoa(ta.Port), nil
	}
	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return "", err
	}
	return port, nil
}

// readN 从连接读取 n 字节
func readN(conn net.Conn, dst *[]byte, n int) error {
	tmp := make([]byte, n)
	_, err := io.ReadFull(conn, tmp)
	if err != nil {
		return err
	}
	*dst = append(*dst, tmp...)
	return nil
}

// readClientHello 读取并解析 TLS ClientHello
func readClientHello(conn net.Conn, firstChunk []byte) (*tls.ClientHelloInfo, []byte, error) {
	buf := append([]byte(nil), firstChunk...)

	// 至少拿到记录层头部
	if len(buf) < 5 {
		if err := readN(conn, &buf, 5-len(buf)); err != nil {
			return nil, nil, err
		}
	}
	// 解析记录长度
	recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
	totalLen := 5 + recordLen
	if recordLen == 0 {
		return nil, nil, fmt.Errorf("record length = 0")
	}
	// 继续读到完整记录
	if len(buf) < totalLen {
		if err := readN(conn, &buf, totalLen-len(buf)); err != nil {
			return nil, nil, err
		}
	}

	// 现在 buf 中握手层完整
	hello := &tls.ClientHelloInfo{}
	r := bytes.NewReader(buf[5:]) // 跳过记录头

	var handshakeType uint8
	if err := binary.Read(r, binary.BigEndian, &handshakeType); err != nil {
		return nil, nil, err
	}
	if handshakeType != 1 { // 1 = client_hello
		return nil, nil, fmt.Errorf("不是 ClientHello")
	}
	// 跳过长度 3
	r.Seek(3, io.SeekCurrent)
	// 跳过版本(2) + 随机数(32)
	r.Seek(34, io.SeekCurrent)

	// SessionID
	var sidLen uint8
	binary.Read(r, binary.BigEndian, &sidLen)
	r.Seek(int64(sidLen), io.SeekCurrent)

	// CipherSuites
	var csLen uint16
	binary.Read(r, binary.BigEndian, &csLen)
	r.Seek(int64(csLen), io.SeekCurrent)

	// Compression
	var compLen uint8
	binary.Read(r, binary.BigEndian, &compLen)
	r.Seek(int64(compLen), io.SeekCurrent)

	// Extensions
	var extLen uint16
	if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
		return nil, nil, err
	}
	extData := make([]byte, extLen)
	if _, err := io.ReadFull(r, extData); err != nil {
		return nil, nil, err
	}

	for pos := 0; pos+4 <= len(extData); {
		etype := binary.BigEndian.Uint16(extData[pos : pos+2])
		el := binary.BigEndian.Uint16(extData[pos+2 : pos+4])
		if pos+4+int(el) > len(extData) {
			break
		}
		if etype == 0 { // SNI
			list := extData[pos+4 : pos+4+int(el)]
			if len(list) < 2 {
				break
			}
			listLen := binary.BigEndian.Uint16(list[:2])
			if int(listLen)+2 > len(list) || listLen == 0 {
				break
			}
			item := list[2:]
			if len(item) < 3 || item[0] != 0 {
				break
			}
			nameLen := binary.BigEndian.Uint16(item[1:3])
			if int(nameLen)+3 > len(item) {
				break
			}
			hello.ServerName = string(item[3 : 3+nameLen])
			return hello, buf, nil
		}
		pos += 4 + int(el)
	}
	return hello, buf, fmt.Errorf("未找到 SNI")
}

// handleHTTP 处理 HTTP 连接
func handleHTTP(conn net.Conn, listenPort string, initialData []byte, cfg *Config, metrics *Metrics) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("[Proxy] 读取 HTTP 请求时发生错误: %v", err)
		return
	}

	host := req.Host
	if host == "" {
		log.Printf("[Proxy] 无法识别 HTTP Host")
		return
	}

	// 去掉 Host 中自带的端口，强制使用监听端口
	targetHost := host
	if strings.Contains(targetHost, ":") {
		if h, _, err := net.SplitHostPort(targetHost); err == nil {
			targetHost = h
		}
	}

	var forwardConn net.Conn
	if cfg.Socks5Proxy != "" {
		// 通过 SOCKS5 代理连接
		socks5Cfg, err := parseProxyURL(cfg.Socks5Proxy)
		if err != nil {
			log.Printf("[Proxy] 解析 SOCKS5 配置失败: %v", err)
			return
		}
		forwardConn, err = dialViaSocks5(socks5Cfg, targetHost, listenPort)
		if err != nil {
			log.Printf("[Proxy] 通过 SOCKS5 连接失败: %v", err)
			return
		}
		atomic.AddInt64(&metrics.proxySocks5, 1)
		log.Printf("[Proxy] 通过 SOCKS5 转发: %s:%s", targetHost, listenPort)
	} else {
		// 直接连接
		forwardAddr := net.JoinHostPort(targetHost, listenPort)
		forwardConn, err = net.Dial("tcp", forwardAddr)
		if err != nil {
			log.Printf("[Proxy] 直连失败: %v", err)
			return
		}
		log.Printf("[Proxy] 直连: %s:%s", targetHost, listenPort)
	}
	defer forwardConn.Close()

	// 将初始数据发送给目标服务器
	_, err = forwardConn.Write(initialData)
	if err != nil {
		log.Printf("[Proxy] 向目标服务器发送初始数据时出错: %v", err)
		return
	}

	// 开始双向数据转发
	handleTCPForward(conn, forwardConn)
}

// handleHTTPS 处理 HTTPS 连接
func handleHTTPS(conn net.Conn, listenPort string, initialData []byte, cfg *Config, metrics *Metrics) {
	// 读取 TLS ClientHello 消息，解析 SNI
	clientHello, fullHello, err := readClientHello(conn, initialData)
	if err != nil {
		log.Printf("[Proxy] 读取 ClientHello 时发生错误: %v", err)
		return
	}

	sni := clientHello.ServerName
	if sni == "" {
		log.Printf("[Proxy] 未找到 SNI，无法转发")
		return
	}

	var forwardConn net.Conn
	if cfg.Socks5Proxy != "" {
		// 通过 SOCKS5 代理连接
		socks5Cfg, err := parseProxyURL(cfg.Socks5Proxy)
		if err != nil {
			log.Printf("[Proxy] 解析 SOCKS5 配置失败: %v", err)
			return
		}
		forwardConn, err = dialViaSocks5(socks5Cfg, sni, listenPort)
		if err != nil {
			log.Printf("[Proxy] 通过 SOCKS5 连接失败: %v", err)
			return
		}
		atomic.AddInt64(&metrics.proxySocks5, 1)
		log.Printf("[Proxy] 通过 SOCKS5 转发: %s:%s", sni, listenPort)
	} else {
		// 直接连接
		forwardAddr := net.JoinHostPort(sni, listenPort)
		forwardConn, err = net.Dial("tcp", forwardAddr)
		if err != nil {
			log.Printf("[Proxy] 直连失败: %v", err)
			return
		}
		log.Printf("[Proxy] 直连: %s:%s", sni, listenPort)
	}
	defer forwardConn.Close()

	// 将完整 ClientHello 发送给目标服务器
	_, err = forwardConn.Write(fullHello)
	if err != nil {
		log.Printf("[Proxy] 向目标服务器发送初始数据时出错: %v", err)
		return
	}

	// 开始双向数据转发
	handleTCPForward(conn, forwardConn)
}

// handleConnection 处理代理连接
func handleConnection(conn net.Conn, cfg *Config, metrics *Metrics) {
	atomic.AddInt32(&metrics.proxyConns, 1)
	defer func() {
		atomic.AddInt32(&metrics.proxyConns, -1)
		conn.Close()
	}()

	// 获取本地监听端口
	listenPort, err := getLocalPort(conn)
	if err != nil {
		log.Printf("[Proxy] 无法获取本地监听端口: %v", err)
		return
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("[Proxy] 读取连接数据时发生错误: %v", err)
		return
	}

	if n > 0 && buf[0] == 0x16 { // TLS 握手
		handleHTTPS(conn, listenPort, buf[:n], cfg, metrics)
	} else { // HTTP
		handleHTTP(conn, listenPort, buf[:n], cfg, metrics)
	}
}

// startProxyServer 启动代理服务
func startProxyServer(cfg *Config, metrics *Metrics) error {
	listeners := make([]net.Listener, 0, len(cfg.ProxyListen))
	for _, addr := range cfg.ProxyListen {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("无法监听 %s: %v", addr, err)
		}
		listeners = append(listeners, l)
		log.Printf("[Proxy] 正在监听 %s", addr)
	}

	var wg sync.WaitGroup
	for _, listener := range listeners {
		wg.Add(1)
		go func(l net.Listener) {
			defer wg.Done()
			for {
				conn, err := l.Accept()
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Temporary() {
						log.Printf("[Proxy] 接受连接临时错误: %v", err)
						continue
					}
					log.Printf("[Proxy] 接受连接错误: %v", err)
					return
				}
				go handleConnection(conn, cfg, metrics)
			}
		}(listener)
	}

	wg.Wait()
	return nil
}

// ============================================================================
// Web 管理界面
// ============================================================================

// htmlEscape 简单替换特殊 HTML 字符
func htmlEscape(s string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return replacer.Replace(s)
}

// startWebServer 启动 Web 管理界面
func startWebServer(cfg *Config, sm *ServiceManager) error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(sm.ruleMgr.filePath)
		if err != nil {
			if os.IsNotExist(err) {
				_ = os.WriteFile(sm.ruleMgr.filePath, []byte(""), 0644)
				data = []byte("")
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("读取规则文件失败: " + err.Error()))
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		// 将规则按行分割并排序显示
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		var cleanLines []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				cleanLines = append(cleanLines, line)
			}
		}
		sort.Strings(cleanLines)
		sortedContent := strings.Join(cleanLines, "\n")

		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DNS拦截与代理管理</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
	font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
	background: #f5f6fa;
	min-height: 100vh;
	padding: 20px;
}
.container {
	max-width: 1200px;
	margin: 0 auto;
	background: white;
	border-radius: 12px;
	box-shadow: 0 10px 40px rgba(0,0,0,0.2);
	overflow: hidden;
}
.header {
	background: #2c3e50;
	color: white;
	padding: 20px;
	text-align: center;
}
.header h1 {
	font-size: 28px;
	margin-bottom: 10px;
}
.header p {
	opacity: 0.9;
	font-size: 14px;
}
.content {
	padding: 20px;
}
.search-box {
	margin-bottom: 20px;
	position: relative;
}
.search-box input[type="text"] {
	width: 100%%;
	padding: 12px 280px 12px 15px;
	border: 2px solid #e0e0e0;
	border-radius: 8px;
	font-size: 15px;
	transition: all 0.3s;
}
.search-box input[type="text"]:focus {
	outline: none;
	border-color: #27ae60;
	box-shadow: 0 0 0 3px rgba(39, 174, 96, 0.1);
}
.search-option {
	position: absolute;
	right: 190px;
	top: 50%%;
	transform: translateY(-50%%);
	font-size: 13px;
	color: #666;
	cursor: pointer;
	display: flex;
	align-items: center;
	user-select: none;
}
.search-option input {
	margin-right: 4px;
	width: auto;
}
.search-icon {
	position: absolute;
	right: 15px;
	top: 50%%;
	transform: translateY(-50%%);
	color: #999;
	cursor: pointer;
	padding: 6px 12px;
	background: #95a5a6;
	color: white;
	border-radius: 4px;
	font-size: 14px;
	transition: background 0.3s;
}
.search-icon:hover {
	background: #7f8c8d;
}
.btn-add-rule {
	position: absolute;
	right: 100px;
	top: 50%%;
	transform: translateY(-50%%);
	padding: 6px 12px;
	background: #27ae60;
	color: white;
	border: none;
	border-radius: 4px;
	cursor: pointer;
	font-size: 14px;
	transition: background 0.3s;
}
.btn-add-rule:hover {
	background: #229954;
}
.stats {
	display: flex;
	gap: 15px;
	margin-bottom: 20px;
	flex-wrap: wrap;
}
.stat-item {
	flex: 1;
	min-width: 150px;
	padding: 15px;
	background: #f5f7fa;
	border-radius: 8px;
	text-align: center;
}
.stat-item .label {
	font-size: 12px;
	color: #666;
	margin-bottom: 5px;
}
.stat-item .value {
	font-size: 24px;
	font-weight: bold;
	color: #27ae60;
}
.editor-container {
	margin-bottom: 20px;
}
.editor-container label {
	display: block;
	margin-bottom: 10px;
	font-weight: 600;
	color: #333;
}
textarea {
	width: 100%%;
	padding: 15px;
	border: 2px solid #e0e0e0;
	border-radius: 8px;
	font-family: "Consolas", "Monaco", monospace;
	font-size: 14px;
	line-height: 1.6;
	resize: vertical;
	transition: all 0.3s;
}
textarea:focus {
	outline: none;
	border-color: #27ae60;
	box-shadow: 0 0 0 3px rgba(39, 174, 96, 0.1);
}
.button-group {
	display: flex;
	gap: 10px;
	flex-wrap: wrap;
}
button, .btn {
	padding: 12px 24px;
	border: none;
	border-radius: 8px;
	font-size: 15px;
	font-weight: 600;
	cursor: pointer;
	transition: all 0.3s;
	text-decoration: none;
	display: inline-block;
}
.btn-primary {
	background: #27ae60;
	color: white;
}
.btn-primary:hover {
	transform: translateY(-2px);
	box-shadow: 0 5px 15px rgba(39, 174, 96, 0.4);
	background: #229954;
}
.btn-secondary {
	background: #f5f7fa;
	color: #333;
}
.btn-secondary:hover {
	background: #e0e0e0;
}
.alert {
	padding: 12px 15px;
	border-radius: 8px;
	margin-bottom: 20px;
	display: none;
}
.alert-success {
	background: #d4edda;
	color: #155724;
	border: 1px solid #c3e6cb;
}
.alert-info {
	background: #d1ecf1;
	color: #0c5460;
	border: 1px solid #bee5eb;
}
.nav-tabs {
	display: flex;
	gap: 5px;
	margin-bottom: 20px;
	border-bottom: 2px solid #e0e0e0;
}
.nav-tab {
	padding: 12px 20px;
	cursor: pointer;
	border: none;
	background: none;
	font-size: 15px;
	color: #666;
	transition: all 0.3s;
	border-bottom: 3px solid transparent;
}
.nav-tab.active {
	color: #27ae60;
	border-bottom-color: #27ae60;
	font-weight: 600;
}
.tab-pane {
	display: none;
}
.tab-pane.active {
	display: block;
}
.form-input {
	width: 100%%;
	padding: 12px;
	border: 2px solid #e0e0e0;
	border-radius: 8px;
	font-size: 14px;
	transition: all 0.3s;
}
.form-input:focus {
	outline: none;
	border-color: #27ae60;
	box-shadow: 0 0 0 3px rgba(39, 174, 96, 0.1);
}
.toast {
	position: fixed;
	top: 20px;
	right: 20px;
	min-width: 300px;
	padding: 15px 20px;
	border-radius: 8px;
	box-shadow: 0 4px 12px rgba(0,0,0,0.15);
	z-index: 9999;
	animation: slideIn 0.3s ease-out;
}
@keyframes slideIn {
	from { transform: translateX(400px); opacity: 0; }
	to { transform: translateX(0); opacity: 1; }
}
.toast-success {
	background: #d4edda;
	color: #155724;
	border-left: 4px solid #27ae60;
}
.toast-error {
	background: #f8d7da;
	color: #721c24;
	border-left: 4px solid #e74c3c;
}
.toast-info {
	background: #d1ecf1;
	color: #0c5460;
	border-left: 4px solid #17a2b8;
}
.rules-list {
	display: none;
	margin-bottom: 20px;
}
.rules-list.active {
	display: block;
}
.rule-item {
	display: flex;
	align-items: center;
	justify-content: space-between;
	padding: 12px 15px;
	margin-bottom: 8px;
	background: #f8f9fa;
	border: 1px solid #e0e0e0;
	border-radius: 6px;
	transition: all 0.2s;
}
.rule-item:hover {
	background: #e9ecef;
	border-color: #27ae60;
}
.rule-text {
	flex: 1;
	font-family: "Consolas", "Monaco", monospace;
	font-size: 14px;
	color: #333;
	word-break: break-all;
}
.rule-actions {
	display: flex;
	gap: 8px;
	margin-left: 15px;
}
.btn-edit, .btn-delete {
	padding: 6px 12px;
	border: none;
	border-radius: 4px;
	font-size: 12px;
	cursor: pointer;
	transition: all 0.2s;
	white-space: nowrap;
}
.btn-edit {
	background: #3498db;
	color: white;
}
.btn-edit:hover {
	background: #2980b9;
}
.btn-delete {
	background: #e74c3c;
	color: white;
}
.btn-delete:hover {
	background: #c0392b;
}
.rule-item.editing .rule-text {
	display: none;
}
.rule-item.editing .rule-actions {
	display: none;
}
.rule-edit-input {
	display: none;
	flex: 1;
	padding: 8px 12px;
	border: 2px solid #27ae60;
	border-radius: 4px;
	font-family: "Consolas", "Monaco", monospace;
	font-size: 14px;
	outline: none;
}
.rule-edit-actions {
	display: none;
	gap: 8px;
	margin-left: 15px;
}
.rule-item.editing .rule-edit-input {
	display: block;
}
.rule-item.editing .rule-edit-actions {
	display: flex;
}
.btn-save, .btn-cancel {
	padding: 6px 12px;
	border: none;
	border-radius: 4px;
	font-size: 12px;
	cursor: pointer;
	transition: all 0.2s;
	white-space: nowrap;
}
.btn-save {
	background: #27ae60;
	color: white;
}
.btn-save:hover {
	background: #229954;
}
.btn-cancel {
	background: #95a5a6;
	color: white;
}
.btn-cancel:hover {
	background: #7f8c8d;
}
.metrics-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
	gap: 20px;
	margin-bottom: 30px;
}
.metric-card {
	background: white;
	padding: 20px;
	border-radius: 10px;
	text-align: center;
	transition: transform 0.3s;
	border: 1px solid #ecf0f1;
}
.metric-card:hover {
	transform: translateY(-5px);
	box-shadow: 0 5px 15px rgba(0,0,0,0.1);
}
.metric-card .icon {
	font-size: 32px;
	margin-bottom: 10px;
}
.metric-card .value {
	font-size: 32px;
	font-weight: bold;
	color: #27ae60;
	margin-bottom: 5px;
}
.metric-card .label {
	font-size: 14px;
	color: #666;
}
.info-section {
	background: #f5f7fa;
	padding: 20px;
	border-radius: 10px;
	margin-bottom: 20px;
}
.info-section h3 {
	margin-bottom: 15px;
	color: #2c3e50;
}
.info-item {
	display: flex;
	justify-content: space-between;
	padding: 10px 0;
	border-bottom: 1px solid #e0e0e0;
}
.info-item:last-child {
	border-bottom: none;
}
.info-item .key {
	font-weight: bold;
	color: #2c3e50;
}
.info-item .value {
	color: #27ae60;
}
.log-section {
	margin-bottom: 30px;
}
.log-section h3 {
	margin-bottom: 15px;
	color: #2c3e50;
}
.log-container {
	background: white;
	border-radius: 10px;
	overflow: hidden;
	border: 1px solid #e0e0e0;
}
.log-table {
	width: 100%%;
	border-collapse: collapse;
	table-layout: fixed;
}
.log-table thead {
	background: #2c3e50;
	color: white;
}
.log-table th {
	padding: 12px;
	text-align: left;
	font-weight: 500;
}
.log-table td {
	padding: 12px;
	border-bottom: 1px solid #ecf0f1;
	white-space: nowrap;
	overflow: hidden;
	text-overflow: ellipsis;
}
.log-table tbody tr:hover {
	background: #f8f9fa;
}
</style>
</head>
<body>
<div class="container">
	<div class="header">
		<h1>🛡️ DNS拦截与代理管理</h1>
		<p>规则管理 / 配置管理 / 实时日志与统计</p>
	</div>
	<div class="content">
		<div class="nav-tabs">
			<button class="nav-tab active" onclick="switchMainTab('rules', event)">📋 规则管理</button>
			<button class="nav-tab" onclick="switchMainTab('config', event)">⚙️ 配置管理</button>
			<button class="nav-tab" onclick="switchMainTab('stats', event)">📊 查看统计</button>
		</div>

		<!-- 规则管理选项卡 -->
		<div id="rules" class="tab-pane active">
		<div class="stats">
			<div class="stat-item">
				<div class="label">规则总数</div>
				<div class="value" id="totalCount">%d</div>
			</div>
			<div class="stat-item">
				<div class="label">显示数量</div>
				<div class="value" id="visibleCount">%d</div>
			</div>
			<div class="stat-item">
				<div class="label">已过滤</div>
				<div class="value" id="filteredCount">0</div>
			</div>
		</div>

		<div class="search-box">
			<input type="text" id="searchInput" placeholder="🔍 输入关键词搜索域名..." autocomplete="off">
			<label class="search-option">
				<input type="checkbox" id="exactMatch"> 完全匹配
			</label>
			<button type="button" class="btn-add-rule" id="addRuleBtn" onclick="addRuleFromSearch()">➕ 添加</button>
			<span class="search-icon">⌨️ 清除</span>
		</div>
		
		<div class="editor-container" style="margin-top:10px;">
			<label for="importUrl">从 URL 导入 gfwlist</label>
			<input type="text" id="importUrl" class="form-input" placeholder="https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt" value="https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt">
			<div class="button-group" style="margin-top:10px;">
				<button type="button" class="btn btn-primary" onclick="importGFWList()">⬇️ 从URL导入</button>
			</div>
			<small style="color:#666; font-size:12px;">外部请求将通过已配置的前置代理</small>
		</div>

		<div class="alert alert-info" id="searchAlert">
			正在搜索...
		</div>

		<!-- 搜索结果列表视图 -->
		<div id="rulesList" class="rules-list"></div>

		<form method="POST" action="/save" id="ruleForm">
			<div class="editor-container" id="editorContainer">
				<label for="content">域名规则列表（每行一个域名）</label>
				<textarea name="content" id="content" rows="20">%s</textarea>
			</div>
			<div class="button-group">
				<button type="submit" class="btn btn-primary">💾 保存规则</button>
				<button type="button" class="btn btn-secondary" onclick="sortRules()">🔤 排序</button>
				<a href="/metrics" class="btn btn-secondary" style="display:none;">📊 查看统计</a>
			</div>
		</form>
		</div>

		<!-- 配置管理选项卡 -->
		<div id="config" class="tab-pane">
			<h3>服务配置</h3>
			<div class="editor-container">
				<label>DNS 监听地址</label>
				<input type="text" id="dnsListen" class="form-input" placeholder="0.0.0.0:53">
			</div>
			<div class="editor-container">
				<label>上游 DNS 服务器</label>
				<input type="text" id="upstreamDNS" class="form-input" placeholder="119.29.29.29:53">
			</div>
			<div class="editor-container">
				<label>拦截返回 IP</label>
				<input type="text" id="redirectIP" class="form-input" placeholder="127.0.0.1">
			</div>
			<div class="editor-container">
				<label>代理监听地址（逗号分隔）</label>
				<input type="text" id="proxyListen" class="form-input" placeholder="0.0.0.0:80,0.0.0.0:443">
			</div>
			<div class="editor-container">
				<label>代理地址（必填）</label>
				<input type="text" id="socks5Proxy" class="form-input" placeholder="socks5://user:pass@host:port 或 http://user:pass@host:port" required>
				<small style="color: #666; font-size: 12px;">
					支持格式：<br>
					• SOCKS5: socks5://user:pass@proxy.com:1080<br>
					• HTTP: http://user:pass@proxy.com:8080<br>
					• HTTPS: https://user:pass@proxy.com:8080<br>
					无认证可省略 user:pass@
				</small>
			</div>
			<div id="configServiceStatus" style="margin: 20px 0; padding: 15px; background: #f5f7fa; border-radius: 8px;">
				<strong>当前服务状态：</strong><span id="statusText">检查中...</span>
			</div>
			<div class="button-group">
				<button class="btn btn-primary" onclick="saveConfig()">💾 保存配置</button>
				<button class="btn btn-secondary" onclick="loadConfig()">🔄 重新加载</button>
				<button class="btn btn-primary" onclick="startService()">▶️ 启动服务</button>
				<button class="btn btn-secondary" onclick="stopService()">⏹️ 停止服务</button>
			</div>
		</div>

		<!-- 统计信息选项卡 -->
		<div id="stats" class="tab-pane">
			<div class="metrics-grid">
				<div class="metric-card">
					<div class="icon">🔍</div>
					<div class="value" id="statDnsQueries">0</div>
					<div class="label">DNS 查询总数</div>
				</div>
				<div class="metric-card">
					<div class="icon">🛡️</div>
					<div class="value" id="statDnsBlocked">0</div>
					<div class="label">DNS 拦截次数</div>
				</div>
				<div class="metric-card">
					<div class="icon">🔗</div>
					<div class="value" id="statActiveConns">0</div>
					<div class="label">活跃代理连接</div>
				</div>
				<div class="metric-card">
					<div class="icon">🚀</div>
					<div class="value" id="statProxyForwards">0</div>
					<div class="label">代理转发次数</div>
				</div>
				<div class="metric-card">
					<div class="icon">📋</div>
					<div class="value" id="statRuleCount">0</div>
					<div class="label">规则数量</div>
				</div>
			</div>

			<div class="info-section">
				<h3>代理配置</h3>
				<div class="info-item">
					<span class="key" id="statProxyTypeLabel">加载中...</span>
					<span class="value" id="statProxyStatusValue">加载中...</span>
				</div>
			</div>

			<!-- DNS 查询日志 -->
			<div class="log-section">
				<h3>DNS 查询记录</h3>
				<div class="log-container">
					<table class="log-table" id="statDnsLogTable">
						<thead>
							<tr>
								<th>时间</th>
								<th>域名</th>
								<th>状态</th>
								<th>客户端IP</th>
							</tr>
						</thead>
						<tbody id="statDnsLogBody">
							<tr><td colspan="4" style="text-align:center;">加载中...</td></tr>
						</tbody>
					</table>
				</div>
			</div>

			<!-- 代理转发日志 -->
			<div class="log-section">
				<h3>代理转发日志</h3>
				<div class="log-container">
					<table class="log-table" id="statProxyLogTable">
						<thead>
							<tr>
								<th>时间</th>
								<th>协议</th>
								<th>目标主机</th>
								<th>客户端IP</th>
								<th>请求方法</th>
							</tr>
						</thead>
						<tbody id="statProxyLogBody">
							<tr><td colspan="5" style="text-align:center;">加载中...</td></tr>
						</tbody>
					</table>
				</div>
			</div>
		</div>
	</div>
</div>

<script>
// Toast 提示函数
function showToast(message, type = 'info') {
	const toast = document.createElement('div');
	toast.className = 'toast toast-' + type;
	toast.textContent = message;
	document.body.appendChild(toast);

	setTimeout(function() {
		toast.style.opacity = '0';
		setTimeout(function() { toast.remove(); }, 300);
	}, 3000);
}

// 选项卡切换
function switchMainTab(tabName, evt) {
	document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
	document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
	const target = evt && evt.target ? evt.target : null;
	if (target) {
		target.classList.add('active');
	} else {
		document.querySelectorAll('.nav-tab').forEach(t => {
			if ((t.getAttribute('onclick') || '').indexOf("'" + tabName + "'") !== -1) {
				t.classList.add('active');
			}
		});
	}
	document.getElementById(tabName).classList.add('active');

	// 离开统计选项卡时断开 WebSocket
	if (tabName !== 'stats') {
		disconnectStatsWebSocket();
	}

	if (tabName === 'config') {
		loadConfig();
		checkServiceStatus();
	} else if (tabName === 'stats') {
		loadStatsData();
	}
}

const textarea = document.getElementById('content');
const searchInput = document.getElementById('searchInput');
const totalCountEl = document.getElementById('totalCount');
const visibleCountEl = document.getElementById('visibleCount');
const filteredCountEl = document.getElementById('filteredCount');
const searchAlert = document.getElementById('searchAlert');
const rulesList = document.getElementById('rulesList');
const editorContainer = document.getElementById('editorContainer');
const clearSearchButton = document.querySelector('.search-icon');
const exactMatch = document.getElementById('exactMatch');

let allLines = [];
let originalContent = textarea.value;

// 初始化
function init() {
	allLines = textarea.value.split('\n').filter(line => line.trim() !== '');
	updateStats();
}

if (clearSearchButton) {
	clearSearchButton.addEventListener('click', clearSearch);
}
if (exactMatch) {
	exactMatch.addEventListener('change', function() {
		if (searchInput.value.trim() !== '') {
			searchInput.dispatchEvent(new Event('input'));
		}
	});
}

// 更新统计
function updateStats() {
	const currentLines = textarea.value.split('\n').filter(line => line.trim() !== '');
	totalCountEl.textContent = allLines.length;
	visibleCountEl.textContent = currentLines.length;
	filteredCountEl.textContent = allLines.length - currentLines.length;
}

// 渲染规则列表视图（限制显示数量）
function renderRulesList(rules) {
	rulesList.innerHTML = '';

	// 限制最多显示100条，避免性能问题
	const maxDisplay = 100;
	const displayRules = rules.slice(0, maxDisplay);

	if (rules.length > maxDisplay) {
		const notice = document.createElement('div');
		notice.style.padding = '10px';
		notice.style.background = '#fff3cd';
		notice.style.borderRadius = '4px';
		notice.style.marginBottom = '10px';
		notice.style.color = '#856404';
		notice.textContent = '找到 ' + rules.length + ' 条规则，仅显示前 ' + maxDisplay + ' 条。请输入更精确的关键词。';
		rulesList.appendChild(notice);
	}

	displayRules.forEach((rule, index) => {
		const ruleItem = document.createElement('div');
		ruleItem.className = 'rule-item';
		ruleItem.dataset.rule = rule;

		// 显示模式的文本
		const ruleText = document.createElement('span');
		ruleText.className = 'rule-text';
		ruleText.textContent = rule;

		// 显示模式的操作按钮
		const actions = document.createElement('div');
		actions.className = 'rule-actions';

		const editBtn = document.createElement('button');
		editBtn.className = 'btn-edit';
		editBtn.textContent = '编辑';
		editBtn.onclick = function() { editRule(ruleItem, rule); };

		const deleteBtn = document.createElement('button');
		deleteBtn.className = 'btn-delete';
		deleteBtn.textContent = '删除';
		deleteBtn.onclick = function() { deleteRule(rule); };

		actions.appendChild(editBtn);
		actions.appendChild(deleteBtn);

		// 编辑模式的输入框
		const editInput = document.createElement('input');
		editInput.type = 'text';
		editInput.className = 'rule-edit-input';
		editInput.value = rule;

		// 编辑模式的操作按钮
		const editActions = document.createElement('div');
		editActions.className = 'rule-edit-actions';

		const saveBtn = document.createElement('button');
		saveBtn.className = 'btn-save';
		saveBtn.textContent = '保存';
		saveBtn.onclick = function() { saveRule(ruleItem, rule, editInput.value); };

		const cancelBtn = document.createElement('button');
		cancelBtn.className = 'btn-cancel';
		cancelBtn.textContent = '取消';
		cancelBtn.onclick = function() { cancelEdit(ruleItem); };

		editActions.appendChild(saveBtn);
		editActions.appendChild(cancelBtn);

		// 组装元素
		ruleItem.appendChild(ruleText);
		ruleItem.appendChild(actions);
		ruleItem.appendChild(editInput);
		ruleItem.appendChild(editActions);
		rulesList.appendChild(ruleItem);
	});
}

// 保存规则到服务器
function saveRulesToServer() {
	const content = allLines.join('\n');
	return fetch('/save', {
		method: 'POST',
		headers: {'Content-Type': 'application/x-www-form-urlencoded'},
		body: 'content=' + encodeURIComponent(content)
	})
	.then(res => {
		if (!res.ok) throw new Error('保存失败');
		return res.text();
	})
	.then(() => {
		textarea.value = allLines.join('\n');
		showToast('规则已保存', 'success');
	})
	.catch(err => {
		showToast('保存失败: ' + err.message, 'error');
	});
}

// 搜索防抖
let searchTimeout = null;

function getFilteredRules(keyword) {
	if (exactMatch && exactMatch.checked) {
		return allLines.filter(line => line.toLowerCase() === keyword);
	}
	return allLines.filter(line => line.toLowerCase().includes(keyword));
}

// 搜索功能
searchInput.addEventListener('input', function() {
	const keyword = this.value.trim().toLowerCase();

	// 清除之前的定时器
	if (searchTimeout) {
		clearTimeout(searchTimeout);
	}

	if (keyword === '') {
		// 清除搜索：显示textarea，隐藏列表
		editorContainer.style.display = 'block';
		rulesList.classList.remove('active');
		textarea.value = allLines.join('\n');
		searchAlert.style.display = 'none';
	} else {
		// 使用防抖，延迟300ms执行搜索
		searchTimeout = setTimeout(function() {
			// 有搜索关键词：隐藏textarea，显示列表
			editorContainer.style.display = 'none';
			rulesList.classList.add('active');

			const filtered = getFilteredRules(keyword);

			// 渲染列表视图
			renderRulesList(filtered);

			searchAlert.textContent = '找到 ' + filtered.length + ' 条匹配规则';
			searchAlert.style.display = 'block';
		}, 300);
	}

	updateStats();
});

// 排序功能
function sortRules() {
	// 如果正在搜索，先清除搜索恢复完整列表
	if (searchInput.value.trim() !== '') {
		searchInput.value = '';
		searchAlert.style.display = 'none';
	}

	const lines = textarea.value.split('\n')
		.map(line => line.trim())
		.filter(line => line !== '');

	lines.sort();
	textarea.value = lines.join('\n');
	allLines = lines;
	updateStats();

	showToast('规则已按字母顺序排序', 'success');
}

// 清除搜索
function clearSearch() {
	searchInput.value = '';
	editorContainer.style.display = 'block';
	rulesList.classList.remove('active');
	textarea.value = allLines.join('\n');
	searchAlert.style.display = 'none';
	updateStats();
}

// 从搜索框添加规则
function addRuleFromSearch() {
	const domain = searchInput.value.trim();
	if (domain === '') {
		showToast('请输入域名', 'error');
		return;
	}

	// 检查是否已存在
	if (allLines.indexOf(domain) !== -1) {
		showToast('规则已存在: ' + domain, 'error');
		return;
	}

	// 添加到规则列表
	allLines.push(domain);
	allLines.sort();

	// 保存到服务器
	saveRulesToServer().then(() => {
		const keyword = searchInput.value.trim();
		if (keyword !== '') {
			editorContainer.style.display = 'none';
			rulesList.classList.add('active');
			const filtered = getFilteredRules(keyword.toLowerCase());
			renderRulesList(filtered);
			searchAlert.textContent = '找到 ' + filtered.length + ' 条匹配规则';
			searchAlert.style.display = 'block';
		} else {
			editorContainer.style.display = 'block';
			rulesList.classList.remove('active');
			searchAlert.style.display = 'none';
		}
		updateStats();
		showToast('已添加规则: ' + domain, 'success');
	});
}

// 编辑规则 - 切换到编辑状态
function editRule(ruleItem, oldRule) {
	// 取消其他正在编辑的规则
	document.querySelectorAll('.rule-item.editing').forEach(item => {
		if (item !== ruleItem) {
			cancelEdit(item);
		}
	});

	// 切换到编辑状态
	ruleItem.classList.add('editing');
	const input = ruleItem.querySelector('.rule-edit-input');
	input.focus();
	input.select();
}

// 保存规则
function saveRule(ruleItem, oldRule, newRule) {
	const trimmedNew = newRule.trim();

	if (trimmedNew === '') {
		showToast('规则不能为空', 'error');
		return;
	}

	if (trimmedNew === oldRule) {
		cancelEdit(ruleItem);
		return;
	}

	// 查找并替换规则
	const index = allLines.indexOf(oldRule);
	if (index !== -1) {
		allLines[index] = trimmedNew;

		// 保存到服务器
		saveRulesToServer().then(() => {
			// 退出编辑状态
			ruleItem.classList.remove('editing');

			// 如果正在搜索，刷新搜索结果
			const keyword = searchInput.value.trim();
			if (keyword !== '') {
				const filtered = allLines.filter(line =>
					line.toLowerCase().includes(keyword.toLowerCase())
				);
				renderRulesList(filtered);
			}
			updateStats();
			showToast('规则已更新', 'success');
		});
	}
}

// 取消编辑
function cancelEdit(ruleItem) {
	ruleItem.classList.remove('editing');
	// 恢复输入框的原始值
	const originalRule = ruleItem.dataset.rule;
	const input = ruleItem.querySelector('.rule-edit-input');
	input.value = originalRule;
}

// 删除规则
function deleteRule(rule) {
	// 从数组中删除
	const index = allLines.indexOf(rule);
	if (index !== -1) {
		allLines.splice(index, 1);

		// 保存到服务器
		saveRulesToServer().then(() => {
			// 如果正在搜索，刷新搜索结果
			const keyword = searchInput.value.trim();
			if (keyword !== '') {
				const filtered = allLines.filter(line =>
					line.toLowerCase().includes(keyword.toLowerCase())
				);
				renderRulesList(filtered);
				searchAlert.textContent = '找到 ' + filtered.length + ' 条匹配规则';
			}
			updateStats();
			showToast('已删除规则: ' + rule, 'success');
		});
	}
}

// WebSocket 连接管理
let statsWs = null;
let statsReconnectTimer = null;
let statsDnsLogs = [];
let statsProxyLogs = [];

// 格式化时间
function formatTime(timestamp) {
	const date = new Date(timestamp);
	return date.toLocaleString('zh-CN', {
		year: 'numeric',
		month: '2-digit',
		day: '2-digit',
		hour: '2-digit',
		minute: '2-digit',
		second: '2-digit'
	});
}

// 渲染DNS日志
function renderStatsDNSLogs() {
	const tbody = document.getElementById('statDnsLogBody');
	if (!statsDnsLogs || statsDnsLogs.length === 0) {
		tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">暂无记录</td></tr>';
		return;
	}
	tbody.innerHTML = statsDnsLogs.map(log =>
		'<tr><td>' + formatTime(log.time) + '</td><td>' + log.domain + '</td><td>' +
		(log.intercepted ? '<span style="color:#e74c3c">已拦截</span>' : '<span style="color:#27ae60">已放行</span>') +
		'</td><td>' + log.client_ip + '</td></tr>'
	).join('');
}

// 渲染代理日志
function renderStatsProxyLogs() {
	const tbody = document.getElementById('statProxyLogBody');
	if (!statsProxyLogs || statsProxyLogs.length === 0) {
		tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">暂无记录</td></tr>';
		return;
	}
	tbody.innerHTML = statsProxyLogs.map(log =>
		'<tr><td>' + formatTime(log.time) + '</td><td>' + log.protocol + '</td><td>' +
		log.host + '</td><td>' + log.client_ip + '</td><td>' + (log.method || '-') + '</td></tr>'
	).join('');
}

// 更新统计数据
function updateStatsDisplay(stats) {
	document.getElementById('statDnsQueries').textContent = stats.dnsQueries || 0;
	document.getElementById('statDnsBlocked').textContent = stats.dnsIntercepted || 0;
	document.getElementById('statActiveConns').textContent = stats.proxyConns || 0;
	document.getElementById('statProxyForwards').textContent = stats.proxyForwarded || 0;
}

// 更新代理配置显示
function updateStatsConfig(config) {
	const typeLabel = document.getElementById('statProxyTypeLabel');
	const statusValue = document.getElementById('statProxyStatusValue');

	// 处理 WebSocket 推送的配置格式
	if (typeLabel && config.proxyType) {
		typeLabel.textContent = config.proxyType;
	}
	if (statusValue && config.proxyStatus) {
		statusValue.textContent = config.proxyStatus;
	}
}

// 连接统计页面的 WebSocket
function connectStatsWebSocket() {
	// 清除重连定时器
	if (statsReconnectTimer) {
		clearTimeout(statsReconnectTimer);
		statsReconnectTimer = null;
	}

	// 构建 WebSocket URL
	const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
	const wsUrl = protocol + '//' + window.location.host + '/ws/logs';

	console.log('连接统计 WebSocket:', wsUrl);
	statsWs = new WebSocket(wsUrl);

	// 连接成功
	statsWs.onopen = function() {
		console.log('统计 WebSocket 连接成功');
	};

	// 接收消息
	statsWs.onmessage = function(event) {
		try {
			const data = JSON.parse(event.data);

			// 更新统计数据
			if (data.stats) {
				updateStatsDisplay(data.stats);
			}

			// 更新配置信息
			if (data.config) {
				updateStatsConfig(data.config);
			}

			// 处理初始化数据
			if (data.type === 'init') {
				if (data.data.dns) {
					statsDnsLogs = data.data.dns.slice(0, 100);
					renderStatsDNSLogs();
				}
				if (data.data.proxy) {
					statsProxyLogs = data.data.proxy.slice(0, 100);
					renderStatsProxyLogs();
				}
			}
			// 处理新的 DNS 日志
			else if (data.type === 'dns') {
				statsDnsLogs.unshift(data.data);
				if (statsDnsLogs.length > 100) {
					statsDnsLogs = statsDnsLogs.slice(0, 100);
				}
				renderStatsDNSLogs();
			}
			// 处理新的代理日志
			else if (data.type === 'proxy') {
				statsProxyLogs.unshift(data.data);
				if (statsProxyLogs.length > 100) {
					statsProxyLogs = statsProxyLogs.slice(0, 100);
				}
				renderStatsProxyLogs();
			}
			// 处理配置更新
			else if (data.type === 'config') {
				console.log('收到配置更新');
			}
		} catch (error) {
			console.error('处理 WebSocket 消息失败:', error);
		}
	};

	// 连接错误
	statsWs.onerror = function(error) {
		console.error('统计 WebSocket 错误:', error);
	};

	// 连接关闭，5秒后自动重连
	statsWs.onclose = function() {
		console.log('统计 WebSocket 连接关闭，5秒后重连...');
		statsReconnectTimer = setTimeout(connectStatsWebSocket, 5000);
	};
}

// 断开统计 WebSocket
function disconnectStatsWebSocket() {
	if (statsReconnectTimer) {
		clearTimeout(statsReconnectTimer);
		statsReconnectTimer = null;
	}
	if (statsWs) {
		statsWs.close();
		statsWs = null;
	}
}

// 加载统计数据（切换到统计选项卡时调用）
function loadStatsData() {
	// 加载规则数量
	fetch('/api/stats')
		.then(res => res.json())
		.then(data => {
			document.getElementById('statRuleCount').textContent = data.ruleCount || 0;
		})
		.catch(err => console.error('加载统计数据失败:', err));

	// 建立 WebSocket 连接以获取实时数据（包括配置信息）
	if (!statsWs || statsWs.readyState !== WebSocket.OPEN) {
		connectStatsWebSocket();
	}
}

function loadConfig() {
	fetch('/api/config')
		.then(res => res.json())
		.then(cfg => {
			document.getElementById('dnsListen').value = cfg.dns_listen || '';
			document.getElementById('upstreamDNS').value = cfg.upstream_dns || '';
			document.getElementById('redirectIP').value = cfg.redirect_ip || '';
			document.getElementById('proxyListen').value = (cfg.proxy_listen || []).join(',');
			document.getElementById('socks5Proxy').value = cfg.socks5_proxy || '';
		})
		.catch(err => showToast('加载配置失败: ' + err.message, 'error'));
}

// 保存配置
function saveConfig() {
	const socks5 = document.getElementById('socks5Proxy').value.trim();
	if (!socks5) {
		showToast('代理地址为必填项', 'error');
		return;
	}

	const cfg = {
		dns_listen: document.getElementById('dnsListen').value,
		upstream_dns: document.getElementById('upstreamDNS').value,
		redirect_ip: document.getElementById('redirectIP').value,
		proxy_listen: document.getElementById('proxyListen').value.split(',').map(s => s.trim()),
		socks5_proxy: socks5
	};

	fetch('/api/config/save', {
		method: 'POST',
		headers: {'Content-Type': 'application/json'},
		body: JSON.stringify(cfg)
	})
	.then(res => {
		if (!res.ok) {
			return res.json().then(data => {
				throw new Error(data.error || '保存失败');
			});
		}
		return res.json();
	})
	.then(data => {
		showToast(data.message || '配置已保存', 'success');
		// 检查服务是否运行中，如果是则重启
		return fetch('/api/service/status');
	})
	.then(res => res.json())
	.then(status => {
		if (status.running) {
			// 服务运行中，自动重启以应用新配置
			return fetch('/api/service/restart', {method: 'POST'})
				.then(res => res.json())
				.then(data => {
					showToast('服务已重启，新配置已生效', 'success');
					checkServiceStatus();
				});
		} else {
			checkServiceStatus();
		}
	})
	.catch(err => showToast(err.message, 'error'));
}

// 启动服务
function startService() {
	fetch('/api/service/start', {method: 'POST'})
		.then(res => {
			if (!res.ok) {
				return res.text().then(text => {
					throw new Error(text || '启动失败');
				});
			}
			return res.json();
		})
		.then(data => {
			showToast(data.message, 'success');
			checkServiceStatus();
		})
		.catch(err => showToast(err.message, 'error'));
}

// 停止服务
function stopService() {
	fetch('/api/service/stop', {method: 'POST'})
		.then(res => res.json())
		.then(data => {
			showToast(data.message, 'success');
			checkServiceStatus();
		})
		.catch(err => showToast('停止失败: ' + err.message, 'error'));
}

// 检查服务状态
function checkServiceStatus() {
	fetch('/api/service/status')
		.then(res => res.json())
		.then(data => {
			const statusText = document.getElementById('statusText');
			if (data.running) {
				statusText.innerHTML = '<span style="color: #28a745;">✅ 运行中</span>';
			} else {
				statusText.innerHTML = '<span style="color: #6c757d;">⏹️ 已停止</span>';
			}
		})
		.catch(err => {
			const statusText = document.getElementById('statusText');
			statusText.innerHTML = '<span style="color: #dc3545;">❌ 检查失败</span>';
		});
}

// 表单提交前恢复完整内容
document.getElementById('ruleForm').addEventListener('submit', function(e) {
	if (searchInput.value.trim() !== '') {
		// 在搜索状态下保存，需要先清除搜索
		e.preventDefault();
		showToast('请先清除搜索后再保存规则', 'error');
		return false;
	}
});

// 页面加载时初始化
init();

	function importGFWList() {
		const url = document.getElementById('importUrl').value.trim();
		if (!url) {
			showToast('请输入导入 URL', 'error');
			return;
		}
		fetch('/api/rules/update-gfwlist', {
			method: 'POST',
			headers: {'Content-Type': 'application/json'},
			body: JSON.stringify({url})
		})
			.then(res => res.json().then(data => ({ok: res.ok, data})))
			.then(({ok, data}) => {
				if (!ok) throw new Error(data.error || '导入失败');
				showToast('导入成功，规则数：' + data.count, 'success');
				location.reload();
			})
			.catch(err => showToast(err.message, 'error'));
	}
</script>
</body>
</html>`, len(cleanLines), len(cleanLines), htmlEscape(sortedContent))
	})

	http.HandleFunc("/save", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		content := r.FormValue("content")
		if err := sm.ruleMgr.SavePatterns(content); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("保存失败: " + err.Error()))
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// 获取配置
	http.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sm.cfg)
	})

	// 保存配置
	http.HandleFunc("/api/config/save", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var newCfg Config
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, "配置格式错误: "+err.Error(), http.StatusBadRequest)
			return
		}

		// 验证配置
		if err := newCfg.ValidateConfig(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		newCfg.WebAddr = sm.cfg.WebAddr
		if err := newCfg.SaveConfig("config.json"); err != nil {
			http.Error(w, "保存配置失败: "+err.Error(), http.StatusInternalServerError)
			return
		}

		sm.cfg = &newCfg
		sm.logMgr.cfg = &newCfg // 同步更新 LogManager 的配置引用

		// 广播配置更新到所有 WebSocket 客户端
		sm.logMgr.BroadcastConfigUpdate()

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "配置已保存"})
	})

	http.HandleFunc("/api/rules/update-gfwlist", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			URL string `json:"url"`
		}
		if r.ContentLength > 0 {
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "请求格式错误: " + err.Error()})
				return
			}
		}
		u := strings.TrimSpace(payload.URL)
		if u == "" {
			u = strings.TrimSpace(r.URL.Query().Get("url"))
		}
		if u == "" {
			u = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
		}
		if sm.cfg.Socks5Proxy == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "请先在配置管理中配置前置代理后再导入"})
			return
		}
		if err := sm.ruleMgr.UpdateFromURLViaProxy(sm.cfg.Socks5Proxy, u); err != nil {
			status := http.StatusInternalServerError
			if strings.Contains(err.Error(), "未配置前置代理") {
				status = http.StatusBadRequest
			}
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]string{"error": "从 gfwlist 更新失败: " + err.Error()})
			return
		}
		pats := sm.ruleMgr.GetPatterns()
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "已从 gfwlist 更新", "count": len(pats)})
	})

	// 启动服务
	http.HandleFunc("/api/service/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := sm.Start(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 更新自动启动状态
		sm.cfg.AutoStart = true
		sm.cfg.SaveConfig("config.json")

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "服务已启动"})
	})

	// 停止服务
	http.HandleFunc("/api/service/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := sm.Stop(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 更新自动启动状态
		sm.cfg.AutoStart = false
		sm.cfg.SaveConfig("config.json")

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "服务已停止"})
	})

	// 重启服务
	http.HandleFunc("/api/service/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if sm.IsRunning() {
			if err := sm.Stop(); err != nil {
				http.Error(w, "停止服务失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		if err := sm.Start(); err != nil {
			http.Error(w, "启动服务失败: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "服务已重启"})
	})

	// 获取服务状态
	http.HandleFunc("/api/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"running": sm.IsRunning()})
	})

	// 获取代理配置
	http.HandleFunc("/api/proxy/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		proxyStatus := "未配置"
		proxyType := "代理"

		if sm.cfg.Socks5Proxy != "" {
			proxyCfg, err := parseProxyURL(sm.cfg.Socks5Proxy)
			if err == nil {
				if proxyCfg.Type == "socks5" {
					proxyType = "SOCKS5 代理"
				} else {
					proxyType = "HTTP 代理"
				}
			}
			proxyStatus = "已配置: " + sm.cfg.Socks5Proxy
		}

		json.NewEncoder(w).Encode(map[string]string{
			"proxyType":   proxyType,
			"proxyStatus": proxyStatus,
		})
	})

	// 获取DNS日志
	http.HandleFunc("/api/logs/dns", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		limit := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit = n
			}
		}
		logs := sm.logMgr.GetDNSLogs(limit)
		json.NewEncoder(w).Encode(logs)
	})

	// 获取代理日志
	http.HandleFunc("/api/logs/proxy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		limit := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit = n
			}
		}
		logs := sm.logMgr.GetProxyLogs(limit)
		json.NewEncoder(w).Encode(logs)
	})

	http.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := map[string]interface{}{
			"dnsQueries":    atomic.LoadInt64(&sm.logMgr.metrics.dnsQueries),
			"dnsBlocked":    atomic.LoadInt64(&sm.logMgr.metrics.dnsIntercepted),
			"activeConns":   atomic.LoadInt32(&sm.logMgr.metrics.proxyConns),
			"proxyForwards": atomic.LoadInt64(&sm.logMgr.metrics.proxyForwarded),
			"ruleCount":     len(sm.ruleMgr.GetPatterns()),
		}
		json.NewEncoder(w).Encode(stats)
	})

	// WebSocket日志推送
	http.Handle("/ws/logs", websocket.Handler(func(ws *websocket.Conn) {
		sm.logMgr.AddWSClient(ws)
		defer sm.logMgr.RemoveWSClient(ws)

		// 发送最近的日志
		dnsLogs := sm.logMgr.GetDNSLogs(50)
		proxyLogs := sm.logMgr.GetProxyLogs(50)

		initMsg := map[string]interface{}{
			"type": "init",
			"data": map[string]interface{}{
				"dns":   dnsLogs,
				"proxy": proxyLogs,
			},
			"stats": map[string]interface{}{
				"dnsQueries":     atomic.LoadInt64(&sm.metrics.dnsQueries),
				"dnsIntercepted": atomic.LoadInt64(&sm.metrics.dnsIntercepted),
				"proxyConns":     atomic.LoadInt32(&sm.metrics.proxyConns),
				"proxyForwarded": atomic.LoadInt64(&sm.metrics.proxyForwarded),
				"proxySocks5":    atomic.LoadInt64(&sm.metrics.proxySocks5),
			},
			"config": sm.logMgr.getProxyConfig(),
		}

		if data, err := json.Marshal(initMsg); err == nil {
			websocket.Message.Send(ws, string(data))
		}

		// 保持连接
		var msg string
		for {
			if err := websocket.Message.Receive(ws, &msg); err != nil {
				break
			}
		}
	}))

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		dnsQueries := atomic.LoadInt64(&sm.metrics.dnsQueries)
		dnsIntercepted := atomic.LoadInt64(&sm.metrics.dnsIntercepted)
		proxyConns := atomic.LoadInt32(&sm.metrics.proxyConns)
		proxySocks5 := atomic.LoadInt64(&sm.metrics.proxySocks5)
		ruleCount := len(sm.ruleMgr.GetPatterns())

		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>服务统计</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
	font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
	background: #f5f6fa;
	min-height: 100vh;
	padding: 20px;
}
.container {
	max-width: 1200px;
	margin: 0 auto;
	background: white;
	border-radius: 12px;
	box-shadow: 0 10px 40px rgba(0,0,0,0.2);
	overflow: hidden;
}
.header {
	background: #2c3e50;
	color: white;
	padding: 20px;
	text-align: center;
}
.header h1 {
	font-size: 28px;
	margin-bottom: 10px;
}
.content {
	padding: 20px;
}
.metrics-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
	gap: 20px;
	margin-bottom: 30px;
}
.metric-card {
	background: white;
	padding: 20px;
	border-radius: 10px;
	text-align: center;
	transition: transform 0.3s;
	border: 1px solid #ecf0f1;
}
.metric-card:hover {
	transform: translateY(-5px);
	box-shadow: 0 5px 15px rgba(0,0,0,0.1);
}
.metric-card .icon {
	font-size: 32px;
	margin-bottom: 10px;
}
.metric-card .value {
	font-size: 32px;
	font-weight: bold;
	color: #27ae60;
	margin-bottom: 5px;
}
.metric-card .label {
	font-size: 14px;
	color: #666;
}
.info-section {
	background: #f5f7fa;
	padding: 20px;
	border-radius: 10px;
	margin-bottom: 20px;
}
.info-section h3 {
	margin-bottom: 15px;
	color: #333;
}
.info-item {
	display: flex;
	justify-content: space-between;
	padding: 10px 0;
	border-bottom: 1px solid #e0e0e0;
}
.info-item:last-child {
	border-bottom: none;
}
.info-item .key {
	font-weight: 600;
	color: #666;
}
.info-item .value {
	color: #333;
}
.btn {
	display: inline-block;
	padding: 12px 24px;
	background: #27ae60;
	color: white;
	text-decoration: none;
	border-radius: 8px;
	font-weight: 600;
	transition: all 0.3s;
}
.btn:hover {
	transform: translateY(-2px);
	box-shadow: 0 5px 15px rgba(39, 174, 96, 0.4);
	background: #229954;
}
.tabs {
	display: flex;
	gap: 10px;
	margin-bottom: 20px;
	border-bottom: 2px solid #e0e0e0;
}
.log-section {
	background: #f5f7fa;
	padding: 20px;
	border-radius: 10px;
	margin-bottom: 20px;
}
.log-section h3 {
	margin-bottom: 15px;
	color: #333;
}
.log-container {
	max-height: 300px;
	overflow-y: auto;
	background: white;
	border-radius: 8px;
	box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}
.log-table {
	width: 100%%;
	border-collapse: collapse;
	table-layout: fixed;
}
.log-table thead {
	position: sticky;
	top: 0;
	background: #2c3e50;
	color: white;
	z-index: 10;
}
.log-table th {
	padding: 12px;
	text-align: left;
	font-weight: 600;
	border-bottom: 2px solid #1a252f;
}
.log-table td {
	padding: 10px 12px;
	border-bottom: 1px solid #e0e0e0;
	white-space: nowrap;
	overflow: hidden;
	text-overflow: ellipsis;
}
.log-table tbody tr:nth-child(even) {
	background: #f9f9f9;
}
.log-table tbody tr:hover {
	background: #f0f0f0;
}
.log-table .blocked {
	background: #ffe0e0 !important;
	color: #e74c3c;
	font-weight: 600;
}
.log-table .allowed {
	color: #27ae60;
}
</style>
</head>
<body>
<div class="container">
	<div class="header">
		<h1>📊 服务统计信息</h1>
		<p>实时监控服务运行状态</p>
	</div>
	<div class="content">
		<!-- 移除标签页，只显示总体统计 -->

		<div class="metrics-grid">
			<div class="metric-card">
				<div class="icon">🔍</div>
				<div class="value">%d</div>
				<div class="label">DNS 查询总数</div>
			</div>
			<div class="metric-card">
				<div class="icon">🛡️</div>
				<div class="value">%d</div>
				<div class="label">DNS 拦截次数</div>
			</div>
			<div class="metric-card">
				<div class="icon">🔗</div>
				<div class="value">%d</div>
				<div class="label">活跃代理连接</div>
			</div>
			<div class="metric-card">
				<div class="icon">🚀</div>
				<div class="value">%d</div>
				<div class="label">代理转发次数</div>
			</div>
			<div class="metric-card">
				<div class="icon">📋</div>
				<div class="value">%d</div>
				<div class="label">规则数量</div>
			</div>
		</div>

		<div class="info-section">
			<h3>代理配置</h3>
			<div class="info-item">
				<span class="key" id="proxyTypeLabel">加载中...</span>
				<span class="value" id="proxyStatusValue">加载中...</span>
			</div>
		</div>

		<!-- DNS 查询日志 -->
		<div class="log-section">
			<h3>DNS 查询记录</h3>
			<div class="log-container">
				<table class="log-table" id="dnsLogTable">
					<thead>
						<tr>
							<th>时间</th>
							<th>域名</th>
							<th>状态</th>
							<th>客户端IP</th>
						</tr>
					</thead>
					<tbody id="dnsLogBody">
						<tr><td colspan="4" style="text-align:center;">加载中...</td></tr>
					</tbody>
				</table>
			</div>
		</div>

		<!-- 代理转发日志 -->
		<div class="log-section">
			<h3>代理转发日志</h3>
			<div class="log-container">
				<table class="log-table" id="proxyLogTable">
					<thead>
						<tr>
							<th>时间</th>
							<th>协议</th>
							<th>目标主机</th>
							<th>客户端IP</th>
							<th>请求方法</th>
						</tr>
					</thead>
					<tbody id="proxyLogBody">
						<tr><td colspan="5" style="text-align:center;">加载中...</td></tr>
					</tbody>
				</table>
			</div>
		</div>

		<a href="/" class="btn">← 返回规则编辑</a>
	</div>
</div>

<script>
// 格式化时间
function formatTime(timestamp) {
	const date = new Date(timestamp);
	return date.toLocaleString('zh-CN', {
		year: 'numeric',
		month: '2-digit',
		day: '2-digit',
		hour: '2-digit',
		minute: '2-digit',
		second: '2-digit'
	});
}

// DNS日志数组（最多保存100条）
let dnsLogs = [];

// 代理日志数组（最多保存100条）
let proxyLogs = [];

// 渲染DNS日志
function renderDNSLogs() {
	const tbody = document.getElementById('dnsLogBody');

	if (!dnsLogs || dnsLogs.length === 0) {
		tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">暂无数据</td></tr>';
		return;
	}

	tbody.innerHTML = dnsLogs.map(log => {
		const statusClass = log.intercepted ? 'blocked' : 'allowed';
		const statusText = log.intercepted ? '已拦截' : '已放行';
		return '<tr class="' + statusClass + '">' +
			'<td>' + formatTime(log.time) + '</td>' +
			'<td>' + log.domain + '</td>' +
			'<td>' + statusText + '</td>' +
			'<td>' + log.client_ip + '</td>' +
		'</tr>';
	}).join('');
}

// 渲染代理日志
function renderProxyLogs() {
	const tbody = document.getElementById('proxyLogBody');

	if (!proxyLogs || proxyLogs.length === 0) {
		tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">暂无数据</td></tr>';
		return;
	}

	tbody.innerHTML = proxyLogs.map(log => '<tr>' +
		'<td>' + formatTime(log.time) + '</td>' +
		'<td>' + log.protocol + '</td>' +
		'<td>' + log.host + '</td>' +
		'<td>' + log.client_ip + '</td>' +
		'<td>' + (log.method || '-') + '</td>' +
	'</tr>').join('');
}

// 更新统计数据
function updateStats(stats) {
	// 获取所有统计卡片的值元素
	const metricCards = document.querySelectorAll('.metric-card .value');

	// 按顺序更新：DNS查询、DNS拦截、活跃连接、代理转发次数、规则数量
	if (metricCards.length >= 5) {
		const dnsQueries = stats.dnsQueries || 0;
		const dnsIntercepted = (stats.dnsIntercepted !== undefined ? stats.dnsIntercepted : (stats.dnsBlocked || 0));
		const proxyConns = (stats.proxyConns !== undefined ? stats.proxyConns : (stats.activeConns || 0));
		const proxyForwarded = (stats.proxyForwarded !== undefined ? stats.proxyForwarded : (stats.proxyForwards !== undefined ? stats.proxyForwards : (stats.proxySocks5 || 0)));
		metricCards[0].textContent = dnsQueries;
		metricCards[1].textContent = dnsIntercepted;
		metricCards[2].textContent = proxyConns;
		metricCards[3].textContent = proxyForwarded;
		if (stats.ruleCount !== undefined) {
			metricCards[4].textContent = stats.ruleCount;
		}
	}
}

// 更新配置信息
function updateConfig(config) {
	const proxyTypeLabel = document.getElementById('proxyTypeLabel');
	const proxyStatusValue = document.getElementById('proxyStatusValue');

	if (proxyTypeLabel && config.proxyType) {
		proxyTypeLabel.textContent = config.proxyType;
	}
	if (proxyStatusValue && config.proxyStatus) {
		proxyStatusValue.textContent = config.proxyStatus;
	}
}

// 获取代理配置
function fetchProxyConfig() {
	fetch('/api/proxy/config')
		.then(res => res.json())
		.then(config => {
			updateConfig(config);
		})
		.catch(err => {
			console.error('获取代理配置失败:', err);
		});
}

// WebSocket连接
let ws = null;
let reconnectTimer = null;

// 连接WebSocket
function connectWebSocket() {
	// 清除重连定时器
	if (reconnectTimer) {
		clearTimeout(reconnectTimer);
		reconnectTimer = null;
	}

	// 构建WebSocket URL
	const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
	const wsUrl = protocol + '//' + window.location.host + '/ws/logs';

	console.log('连接WebSocket:', wsUrl);
	ws = new WebSocket(wsUrl);

	// 连接成功
	ws.onopen = function() {
		console.log('WebSocket连接成功');
	};

	// 接收消息
	ws.onmessage = function(event) {
		try {
			const data = JSON.parse(event.data);

			// 更新统计数据（如果存在）
			if (data.stats) {
				updateStats(data.stats);
			}

			// 更新配置信息（如果存在）
			if (data.config) {
				updateConfig(data.config);
			}

			// 处理初始化数据
			if (data.type === 'init') {
				if (data.data.dns) {
					dnsLogs = data.data.dns.slice(0, 100);
					renderDNSLogs();
				}
				if (data.data.proxy) {
					proxyLogs = data.data.proxy.slice(0, 100);
					renderProxyLogs();
				}
			}
			// 处理新的DNS日志
			else if (data.type === 'dns') {
				// 插入到数组开头
				dnsLogs.unshift(data.data);
				// 保持最多100条
				if (dnsLogs.length > 100) {
					dnsLogs = dnsLogs.slice(0, 100);
				}
				renderDNSLogs();
			}
			// 处理新的代理日志
			else if (data.type === 'proxy') {
				// 插入到数组开头
				proxyLogs.unshift(data.data);
				// 保持最多100条
				if (proxyLogs.length > 100) {
					proxyLogs = proxyLogs.slice(0, 100);
				}
				renderProxyLogs();
			}
		} catch (error) {
			console.error('处理WebSocket消息失败:', error);
		}
	};

	// 连接错误
	ws.onerror = function(error) {
		console.error('WebSocket错误:', error);
	};

	// 连接关闭，5秒后自动重连
	ws.onclose = function() {
		console.log('WebSocket连接关闭，5秒后重连...');
		reconnectTimer = setTimeout(connectWebSocket, 5000);
	};
}

// 页面加载时获取代理配置
fetchProxyConfig();

// 页面加载时自动连接WebSocket
connectWebSocket();
</script>
</body>
</html>`,
			dnsQueries, dnsIntercepted, proxyConns, proxySocks5, ruleCount,
		)
	})

	log.Printf("[Web] 管理界面监听 %s", cfg.WebAddr)
	if err := http.ListenAndServe(cfg.WebAddr, nil); err != nil {
		return fmt.Errorf("管理界面启动失败: %v", err)
	}
	return nil
}

// ============================================================================
// 主函数
// ============================================================================

// parseFlags 解析命令行参数
func parseFlags() string {
	port := flag.String("port", "10000", "Web 管理界面端口")
	flag.Parse()
	return *port
}

func main() {
	// 1. 解析命令行参数（只有端口）
	port := parseFlags()

	log.Println("========================================")
	log.Println("整合网络服务启动中...")
	log.Println("========================================")

	// 2. 加载或创建配置
	const configFile = "config.json"
	cfg, err := LoadConfig(configFile)
	if err != nil {
		log.Printf("配置文件不存在，使用默认配置")
		cfg = GetDefaultConfig()
		if err := cfg.SaveConfig(configFile); err != nil {
			log.Printf("警告: 保存默认配置失败: %v", err)
		}
	}
	cfg.WebAddr = "0.0.0.0:" + port

	// 3. 创建服务管理器
	sm := NewServiceManager(cfg)

	// 4. 启动 Web 管理界面
	go startWebServer(cfg, sm)

	log.Println("========================================")
	log.Println("Web 管理界面:")

	// 获取端口号
	var webPort string
	_, webPort, _ = net.SplitHostPort(cfg.WebAddr)
	if webPort == "" {
		webPort = "10000"
	}

	// 显示所有本机IP地址
	ips := getAllLocalIPs()
	for _, ip := range ips {
		log.Printf("  http://%s:%s", ip, webPort)
	}

	log.Println("请在网页中配置并启动服务")
	log.Println("========================================")

	// 5. 根据配置决定是否自动启动服务
	if cfg.AutoStart {
		log.Println("检测到上次服务为运行状态，正在自动启动...")
		if err := sm.Start(); err != nil {
			log.Printf("自动启动失败: %v", err)
			log.Println("请在网页中手动启动服务")
		} else {
			log.Println("服务已自动启动")
		}
	}

	// 6. 显示代理配置
	if cfg.Socks5Proxy != "" {
		proxyCfg, err := parseProxyURL(cfg.Socks5Proxy)
		if err == nil {
			if proxyCfg.Type == "socks5" {
				log.Printf("代理类型: SOCKS5 (%s)", cfg.Socks5Proxy)
			} else {
				log.Printf("代理类型: HTTP (%s)", cfg.Socks5Proxy)
			}
		} else {
			log.Printf("代理配置: %s", cfg.Socks5Proxy)
		}
	} else {
		log.Println("代理模式: 未配置（直连模式）")
	}
	log.Println("按 Ctrl+C 退出")
	log.Println("========================================")

	// 7. 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("")
	log.Println("收到退出信号，正在关闭服务...")
	log.Println("服务已停止")
}
