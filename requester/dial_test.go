package requester

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestFilterIPsByNetwork(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("2408:871a:2100:1a:0:ff:b089:349b"),
		net.ParseIP("113.200.2.156"),
	}

	if got := filterIPsByNetwork("tcp4", ips); len(got) != 1 || got[0].String() != "113.200.2.156" {
		t.Errorf("tcp4 过滤结果错误: %v", got)
	}
	if got := filterIPsByNetwork("tcp6", ips); len(got) != 1 || got[0].To4() != nil {
		t.Errorf("tcp6 过滤结果错误: %v", got)
	}
	if got := filterIPsByNetwork("tcp", ips); len(got) != 2 {
		t.Errorf("tcp 应保留全部候选: %v", got)
	}
}

// 首选 IP 黑洞(模拟 IPv6 路径不通 / CDN 节点失效)时, 必须回退到其它候选
func TestDialIPsFallbackToNextCandidate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	// dead 放在首个候选, 模拟解析器优先返回不可达地址的情况
	dead := net.ParseIP("192.0.2.1") // TEST-NET-1, 不可达
	ips := []net.IP{dead, net.ParseIP("127.0.0.1"), dead}

	start := time.Now()
	conn, err := dialIPs(context.Background(), "tcp", ips, port)
	if err != nil {
		t.Fatalf("应通过第二个候选连上, 实际错误: %v", err)
	}
	conn.Close()

	if used := time.Since(start); used > dialAttemptTimeout {
		t.Fatalf("回退太慢: %v", used)
	}
}

// 全部候选不可达时, 返回错误且耗时受单次尝试超时约束
func TestDialIPsAllCandidatesDead(t *testing.T) {
	ips := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("198.51.100.1")}

	start := time.Now()
	conn, err := dialIPs(context.Background(), "tcp", ips, 443)
	if err == nil {
		conn.Close()
		t.Fatal("预期拨号失败")
	}
	if used := time.Since(start); used > dialAttemptTimeout+3*time.Second {
		t.Fatalf("失败耗时过长: %v", used)
	}
}

// ctx 取消时拨号应立即中断, 不再死等
func TestDialIPsHonorsContext(t *testing.T) {
	ips := []net.IP{net.ParseIP("192.0.2.1")}

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	start := time.Now()
	conn, err := dialIPs(ctx, "tcp", ips, 443)
	if err == nil {
		conn.Close()
		t.Fatal("预期拨号失败")
	}
	if used := time.Since(start); used > 2*time.Second {
		t.Fatalf("未遵守 ctx 超时: %v", used)
	}
}

// 拨号失败后必须丢弃缓存的 IP, 否则坏地址会被钉住 10 分钟
func TestDialContextInvalidatesCacheOnFailure(t *testing.T) {
	const host = "dial-test.invalid"

	SetTCPHostBind(host, "192.0.2.1")
	if _, ok := tcpCache.Load(host); !ok {
		t.Fatal("SetTCPHostBind 未写入缓存")
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialAttemptTimeout+3*time.Second)
	defer cancel()

	if conn, err := dialContext(ctx, "tcp", host+":443"); err == nil {
		conn.Close()
		t.Fatal("预期拨号失败")
	}

	if _, ok := tcpCache.Load(host); ok {
		t.Fatal("拨号失败后应清除该 host 的 IP 缓存")
	}
}
