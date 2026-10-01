// uTLS 的**内层 hello** 探针 —— 内层不是公开 API，只能在包内读。
//
// 用途：本仓 `crates/utls-engine/src/ech.rs::build_inner_client_hello_body` 要复刻 uTLS 的
// 内层形状，而这一版 uTLS **不再暴露** `GetInnerClientHello`（那个 API 已删）。唯一能拿到内层
// 的办法是在**包内**读 `UConn.echCtx.encodedInner`（uTLS 自己 sealed 的明文，含补零）。
//
// 用法（它**不改** uTLS 任何一行，只多一个测试文件）：
//
//	cp <repo>/crates/utls/tests/fixtures/gen-reference/probes/ech_inner_probe_test.go /tmp/utls-ref/utls-master/
//	cd /tmp/utls-ref/utls-master
//	ECH_CONFIG_HEX=$(dig +short -t TYPE65 crypto.cloudflare.com @1.1.1.1 | tr ' ' '\n' | sed -n 's/^ech=//p' | tr '_-' '/+' | base64 -d | xxd -p | tr -d '\n')
//	go test -run TestProbeECHInner -v -ech-config-hex "$ECH_CONFIG_HEX"
//
// 判据是「uTLS 实际产出什么」—— 不是我的复述。
package tls

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"testing"
)

var echProbeConfigHex = flag.String("ech-config-hex", "", "ECHConfigList（十六进制）")

func TestProbeECHInner(t *testing.T) {
	if *echProbeConfigHex == "" {
		t.Skip("需要 -ech-config-hex")
	}
	cfgBytes, err := hex.DecodeString(*echProbeConfigHex)
	if err != nil {
		t.Fatalf("配置不是十六进制: %v", err)
	}
	cfg := getUTLSTestConfig()
	// ECH 要求两端都是 TLS 1.3（uTLS 自己会检查这一条）。
	cfg.MinVersion = VersionTLS13
	cfg.MaxVersion = VersionTLS13
	cfg.EncryptedClientHelloConfigList = cfgBytes

	uconn := UClient(&net.TCPConn{}, cfg, HelloChrome_70)
	uconn.SetSNI("crypto.cloudflare.com")

	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	ech := uconn.echCtx
	if ech == nil {
		t.Fatal("echCtx 是 nil —— ECH 没被走到")
	}
	inner := ech.innerHello
	fmt.Printf("PROBE inner fields: sessionID_len=%d random=%x ciphers=%d\n",
		len(inner.sessionId), inner.random[:8], len(inner.cipherSuites))
	// ⚠️ 不要读 `ech.encodedInner`：那个字段是 **master 分支**上的（`u_conn.go` 的
	// `[uTLS] SECTION` 里加的），v1.8.2 的发行版里没有它 —— 而发行版才是可复现的参照
	// （能按版本号从 module proxy 取回；master 只能钉文件 sha）。所以这里显式调那条
	// 产出它的函数：`u_handshake_client.go` 里真正喂给密封的就是它。
	encoded, err := encodeInnerClientHelloReorderOuterExts(inner, int(ech.config.MaxNameLength), uconn.extensionsList())
	if err != nil {
		t.Fatalf("encodeInnerClientHelloReorderOuterExts: %v", err)
	}
	fmt.Printf("PROBE encodedInner: len=%d\n", len(encoded))
	fmt.Printf("PROBE encodedInner_hex=%s\n", hex.EncodeToString(encoded))
}
