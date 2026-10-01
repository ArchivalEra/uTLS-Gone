// uTLS **服务端 ECH** 的**活**探针：真监听一个端口，等一个客户端来握。
//
// 与 `ech_server_probe_test.go` 的分工：那一个是「喂字节、看服务端说什么」（不需要网络），
// 这一个是「让**我们的客户端**与服务端真正握手完」，于是**客户端那半边**（尤其
// ECH 接受确认的算法）也进了判据 —— 而 `crypto.cloudflare.com` 那条失败的形状
// 正是「服务端接受了、客户端判了拒绝」（`ech_status = Rejected` + 解不开对端的消息）。
//
// 用法（由 Rust 侧的 `ech_utls_server.rs` 自动驱动；手工跑也行）：
//
//	cp <repo>/crates/utls/tests/fixtures/gen-reference/probes/ech_server_live_test.go /tmp/utls-ref/utls-master/
//	cd /tmp/utls-ref/utls-master
//	go test -run TestProbeECHServerLive -v -live-config-hex <..> -live-priv-hex <..>
//
// 判据是「uTLS 的服务端说什么」—— 不是我的复述。
package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

var (
	liveConfigHex = flag.String("live-config-hex", "", "服务端的 ECHConfig（单条，十六进制）")
	livePrivHex   = flag.String("live-priv-hex", "", "与之配对的 HPKE 私钥（十六进制）")
	liveHost      = flag.String("live-host", "public.example", "服务器证书的名字（= 配置的 public_name）")
	liveAddr      = flag.String("live-addr", "127.0.0.1:0", "监听地址（端口 0 = 由内核挑）")
)

func TestProbeECHServerLive(t *testing.T) {
	if *liveConfigHex == "" || *livePrivHex == "" {
		t.Skip("需要 -live-config-hex 与 -live-priv-hex")
	}
	config, err := hex.DecodeString(*liveConfigHex)
	if err != nil {
		t.Fatalf("配置不是十六进制: %v", err)
	}
	priv, err := hex.DecodeString(*livePrivHex)
	if err != nil {
		t.Fatalf("私钥不是十六进制: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: *liveHost},
		DNSNames:     []string{*liveHost},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Certificates: []Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		MinVersion:   VersionTLS13,
		MaxVersion:   VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
		Rand:         rand.Reader,
		Time:         nil,
		EncryptedClientHelloKeys: []EncryptedClientHelloKey{
			{Config: config, PrivateKey: priv, SendAsRetry: true},
		},
	}

	ln, err := net.Listen("tcp", *liveAddr)
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()
	// 这一行是给 Rust 侧的握手信号（`go test -v` 会立刻把它透出来）。
	fmt.Printf("PROBE listen=%s\n", ln.Addr().String())
	os.Stdout.Sync()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept 失败: %v", err)
	}
	srv := Server(conn, cfg)
	herr := srv.Handshake()
	st := srv.ConnectionState()
	fmt.Printf("PROBE live handshake_err=%v\n", herr)
	fmt.Printf("PROBE live ech_accepted=%v server_name=%q proto=%q\n",
		st.ECHAccepted, st.ServerName, st.NegotiatedProtocol)
}
