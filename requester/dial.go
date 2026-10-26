package requester

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/qjfoidnh/BaiduPCS-Go/baidupcs/expires"
	"github.com/qjfoidnh/BaiduPCS-Go/baidupcs/expires/cachemap"
	"github.com/rs/dnscache"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// MaxDuration 最大的Duration
	MaxDuration = 1<<63 - 1
)

var (
	localTCPAddrList = []*net.TCPAddr{}

	// ProxyAddr 代理地址
	ProxyAddr string

	// 指定走ProxyAddr的域名
	ProxyHostnameRules string

	// ErrProxyAddrEmpty 代理地址为空
	ErrProxyAddrEmpty = errors.New("proxy addr is empty")

	tcpCache = cachemap.GlobalCacheOpMap.LazyInitCachePoolOp("requester/tcp")

	// dnsResolver 通过 singleflight 合并同 host 查询；dnsLookupMu 串行化对标准库解析器的调用，
	// 避免并发 Lookup 时在 tryOneName 路径触发 panic。
	dnsResolver = &dnscache.Resolver{
		Timeout: 10 * time.Second,
	}
	dnsLookupMu sync.Mutex
)

// SetLocalTCPAddrList 设置网卡地址
func SetLocalTCPAddrList(ips ...string) {
	list := make([]*net.TCPAddr, 0, len(ips))
	for k := range ips {
		p := net.ParseIP(ips[k])
		if p == nil {
			continue
		}

		list = append(list, &net.TCPAddr{
			IP: p,
		})
	}
	localTCPAddrList = list
}

func proxyFunc(req *http.Request) (*url.URL, error) {
	u, err := checkProxyAddr(ProxyAddr)
	if err != nil {
		return http.ProxyFromEnvironment(req)
	}

	if ProxyHostnameRules != "" {
		if strings.Contains(ProxyHostnameRules, req.URL.Hostname()) {
			return u, err
		} else {
			return http.ProxyFromEnvironment(req)
		}
	}
	return u, err
}

func getLocalTCPAddr() *net.TCPAddr {
	if len(localTCPAddrList) == 0 {
		return nil
	}
	i := mathrand.Intn(len(localTCPAddrList))
	return localTCPAddrList[i]
}

func getDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: getLocalTCPAddr(),
		DualStack: true,
	}
}

func checkProxyAddr(proxyAddr string) (u *url.URL, err error) {
	if proxyAddr == "" {
		return nil, ErrProxyAddrEmpty
	}

	host, port, err := net.SplitHostPort(proxyAddr)
	if err == nil {
		u = &url.URL{
			Host: net.JoinHostPort(host, port),
		}
		return
	}

	u, err = url.Parse(proxyAddr)
	if err == nil {
		return
	}

	return
}

// SetGlobalProxy 设置代理
func SetGlobalProxy(proxyAddr string) {
	ProxyAddr = proxyAddr
}

// SetProxyHostnameRules 设置走代理的域名列表
func SetProxyHostnameRules(hostnames string) {
	ProxyHostnameRules = hostnames
}

// SetTCPHostBind 设置host绑定ip
func SetTCPHostBind(host, ip string) {
	tcpCache.Store(host, expires.NewDataExpires(net.ParseIP(ip), MaxDuration))
	return
}

func getServerName(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

const (
	// tcpIPCacheDuration 主机解析结果缓存时间
	tcpIPCacheDuration = 10 * time.Minute
	// dialAttemptTimeout 拨通单个 IP 的最长等待时间
	// 之前用 net.DialTCP 是不带超时的, 目标 IP 黑洞时会一直挂着 (SYN 重传 ~2 分钟),
	// 只能等 http.Client.Timeout 触发, 表现为 "context deadline exceeded (Client.Timeout exceeded while awaiting headers)"
	dialAttemptTimeout = 8 * time.Second
	// dialStaggerDelay 多 IP 并发拨号的错峰间隔 (类 happy-eyeballs)
	// 系统/解析器返回的第一个 IP 不可达时 (常见于 IPv6 只有 AAAA 可达路径不通), 迅速回退到下一个候选
	dialStaggerDelay = 300 * time.Millisecond
)

// resolveTCPHost
// 解析的tcpaddr没有port!!!
// 返回主机的全部候选 IP (保持解析器的优先级顺序), 只取第一个会让 IPv6 不通的环境彻底卡死
func resolveTCPHost(ctx context.Context, host string) (ips []net.IP, err error) {
	// host 已是字面量 IP 时直接返回，无需 DNS 查询
	if parsed := net.ParseIP(host); parsed != nil {
		return []net.IP{parsed}, nil
	}

	// 标准库 DNS 偶发 panic 时转为 error，避免进程崩溃
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("dns lookup panic for %q: %v", host, r)
		}
	}()

	dnsLookupMu.Lock()
	addrs, lookupErr := dnsResolver.LookupHost(ctx, host)
	dnsLookupMu.Unlock()
	if lookupErr != nil {
		return nil, lookupErr
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for host %q", host)
	}
	return ips, nil
}

// filterIPsByNetwork 按 tcp/tcp4/tcp6 过滤候选 IP
func filterIPsByNetwork(network string, ips []net.IP) (out []net.IP) {
	for _, ip := range ips {
		isV4 := ip.To4() != nil
		switch network {
		case "tcp4":
			if isV4 {
				out = append(out, ip)
			}
		case "tcp6":
			if !isV4 {
				out = append(out, ip)
			}
		default:
			out = append(out, ip)
		}
	}
	return
}

// dialOneIP 拨通单个 IP, 受 ctx 与 dialAttemptTimeout 约束
func dialOneIP(ctx context.Context, ip net.IP, port int) (net.Conn, error) {
	network := "tcp6"
	if ip.To4() != nil {
		network = "tcp4"
	}

	dialer := &net.Dialer{
		Timeout:   dialAttemptTimeout,
		KeepAlive: 30 * time.Second,
		DualStack: false, // 已经确定了具体 IP
	}
	// 绑定网卡地址时, 需与目标 IP 同族, 否则直接失败
	if local := getLocalTCPAddr(); local != nil && (local.IP.To4() != nil) == (network == "tcp4") {
		dialer.LocalAddr = local
	}

	return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
}

// dialIPs 依次(错峰)尝试所有候选 IP, 返回第一个打通的连接
func dialIPs(ctx context.Context, network string, ips []net.IP, port int) (conn net.Conn, err error) {
	ips = filterIPsByNetwork(network, ips)
	if len(ips) == 0 {
		return nil, fmt.Errorf("no %s address to dial", network)
	}
	if len(ips) == 1 {
		return dialOneIP(ctx, ips[0], port)
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}

	tryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg      sync.WaitGroup
		results = make(chan dialResult, len(ips))
	)
	for i, ip := range ips {
		wg.Add(1)
		go func(i int, ip net.IP) {
			defer wg.Done()
			// 错峰发起: 首个候选不通时, 后续的 IPv4/其它节点也能在数百毫秒内接上
			if i > 0 {
				timer := time.NewTimer(dialStaggerDelay * time.Duration(i))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-tryCtx.Done():
					return
				}
			}
			c, err := dialOneIP(tryCtx, ip, port)
			results <- dialResult{conn: c, err: err}
		}(i, ip)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var firstErr error
	for res := range results {
		if res.err == nil && conn == nil {
			conn = res.conn
			cancel() // 取消其余尝试
			continue
		}
		if res.conn != nil {
			res.conn.Close() // 多余连接
		}
		if res.err != nil && firstErr == nil {
			firstErr = res.err
		}
	}

	if conn != nil {
		return conn, nil
	}
	if firstErr == nil {
		firstErr = ctx.Err()
	}
	return nil, firstErr
}

// tcpHostIPs 取主机的候选 IP, 优先用缓存
func tcpHostIPs(ctx context.Context, host string) (ips []net.IP, err error) {
	data, err := cachemap.GlobalCacheOpMap.CacheOperationWithError("requester/tcp", host, func() (expires.DataExpires, error) {
		resolved, err := resolveTCPHost(ctx, host)
		if err != nil {
			return nil, err
		}
		return expires.NewDataExpires(resolved, tcpIPCacheDuration), nil // 传值
	})
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("no cached address for host %q", host)
	}

	switch v := data.Data().(type) {
	case []net.IP:
		ips = v
	case net.IP: // SetTCPHostBind 手动绑定的单个 IP
		if v != nil {
			ips = []net.IP{v}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no cached address for host %q", host)
	}
	return ips, nil
}

// invalidateTCPHost 拨号失败时丢弃缓存的 IP, 让下次请求重新解析,
// 避免一个不可达节点被钉住 10 分钟 (所有 ls/download 都超时)
func invalidateTCPHost(host string) {
	tcpCache.Delete(host)
}

func dialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}

		ips, err := tcpHostIPs(ctx, host)
		if err != nil {
			return nil, err
		}

		conn, err = dialIPs(ctx, network, ips, port)
		if err != nil {
			invalidateTCPHost(host)
			return nil, err
		}
		return conn, nil
	}

	// 非 tcp 请求
	conn, err = getDialer().DialContext(ctx, network, address)
	return
}

func (h *HTTPClient) dialTLSFunc() func(network, address string) (tlsConn net.Conn, err error) {
	return func(network, address string) (tlsConn net.Conn, err error) {
		conn, err := dialContext(context.Background(), network, address)
		if err != nil {
			return nil, err
		}

		return tls.Client(conn, &tls.Config{
			ServerName:         getServerName(address),
			InsecureSkipVerify: !h.https,
		}), nil
	}
}
