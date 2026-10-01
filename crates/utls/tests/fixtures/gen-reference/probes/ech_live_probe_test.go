// uTLS 的**真握手**探针 —— 对同一个 ECH 端点，拿 uTLS 自己发出的字节与结果。
//
// 用途：本仓的 ECH 在 `defo.ie` 上被 `IllegalParameter` 拒（`questions/10`），而
// uTLS 自己的服务端解码器（`ech_decoder_probe_test.go`）**吃**我们的内层。这时唯一能
// 分开「服务器太挑」与「我们的字节与 uTLS 不同」的办法，是让 **uTLS 自己**打同一个端点，
// 并把它的外层/内层字节打出来逐字节比。
//
// 用法：
//
//	cp ech_live_probe_test.go /tmp/utls-ref/utls-master/
//	cd /tmp/utls-ref/utls-master
//	CFG=$(dig +short -t TYPE65 defo.ie @1.1.1.1 | tr ' ' '\n' | sed -n 's/^ech=//p' | tr '_-' '/+' | base64 -d | od -An -tx1 | tr -d ' \n')
//	go test -run TestProbeECHLive -v -timeout 60s -ech-live-host defo.ie -ech-config-hex "$CFG"
//
// 判据是「uTLS 实际发生了什么」—— 不是我的复述。
package tls

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"testing"
	"time"
)

var echLiveHost = flag.String("ech-live-host", "", "要打的 ECH 端点（如 defo.ie）")

func TestProbeECHLive(t *testing.T) {
	if *echLiveHost == "" || *echProbeConfigHex == "" {
		t.Skip("需要 -ech-live-host 与 -ech-config-hex")
	}
	cfgBytes, err := hex.DecodeString(*echProbeConfigHex)
	if err != nil {
		t.Fatalf("配置不是十六进制: %v", err)
	}
	cfg := getUTLSTestConfig()
	cfg.MinVersion = VersionTLS13
	cfg.MaxVersion = VersionTLS13
	cfg.EncryptedClientHelloConfigList = cfgBytes
	cfg.NextProtos = []string{"h2", "http/1.1"}

	conn, err := net.DialTimeout("tcp", *echLiveHost+":443", 10*time.Second)
	if err != nil {
		t.Fatalf("连不上: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	uconn := UClient(conn, cfg, HelloChrome_70)
	uconn.SetSNI(*echLiveHost)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	ech := uconn.echCtx
	if ech == nil {
		t.Fatal("echCtx 是 nil —— ECH 没被走到")
	}
	fmt.Printf("PROBE max_name_length=%d public_name=%s\n", ech.config.MaxNameLength, ech.config.PublicName)
	outer := uconn.HandshakeState.Hello.Raw
	fmt.Printf("PROBE outer_len=%d\n", len(outer))
	fmt.Printf("PROBE outer_hex=%s\n", hex.EncodeToString(outer))
	// 与 `ech_inner_probe_test.go` 同一处出处：**不读 `ech.encodedInner`**
	// （master 分支才有的字段），显式调那条产出它的函数。
	inner, err := encodeInnerClientHelloReorderOuterExts(ech.innerHello, int(ech.config.MaxNameLength), uconn.extensionsList())
	if err != nil {
		t.Fatalf("encodeInnerClientHello: %v", err)
	}
	fmt.Printf("PROBE inner_len=%d\n", len(inner))
	fmt.Printf("PROBE inner_hex=%s\n", hex.EncodeToString(inner))

	err = uconn.Handshake()
	state := uconn.ConnectionState()
	fmt.Printf("PROBE handshake_err=%v\n", err)
	fmt.Printf("PROBE ech_accepted=%v\n", state.ECHAccepted)
	fmt.Printf("PROBE negotiated_proto=%q version=%04x\n", state.NegotiatedProtocol, state.Version)
}
