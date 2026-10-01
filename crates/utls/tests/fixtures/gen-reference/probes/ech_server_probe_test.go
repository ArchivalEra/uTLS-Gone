// uTLS **服务端 ECH** 的探针 —— 让服务器自己说「它为什么拒」。
//
// 为什么需要它：`processECHClientHello` 只在**一处**发 `IllegalParameter`
// （`decodeInnerClientHello` 失败）；**解不开密文时不发 alert**，而是当没提议过、
// 退回外层。所以「服务器拒我们」与「服务器没看懂我们」是两件不同的事，
// 而只有服务器的代码能说清是哪一件 —— 这里就跑它。
//
// 用法：
//
//	cp <repo>/crates/utls/tests/fixtures/gen-reference/probes/ech_server_probe_test.go /tmp/utls-ref/utls-master/
//	cd /tmp/utls-ref/utls-master
//	# 三串 hex 由 Rust 侧打出：
//	cargo test -p utls-engine --test ech_inner_utls -- --nocapture dump_for_the_utls_server
//	go test -run TestProbeECHServer -v -srv-outer-hex "$OUT" -srv-config-hex "$CFG" -srv-priv-hex "$PRIV"
//
// 判据是「uTLS 的服务端说什么」—— 不是我的复述。
package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

var (
	srvOuterHex  = flag.String("srv-outer-hex", "", "我们的外层 ClientHello 握手消息（十六进制）")
	srvConfigHex = flag.String("srv-config-hex", "", "服务端的 ECHConfig（单条，十六进制）")
	srvPrivHex   = flag.String("srv-priv-hex", "", "与配置配对的 HPKE 私钥（十六进制）")
	srvHost      = flag.String("srv-host", "public.example", "服务器证书的名字（要与配置的 public_name 一致）")
)

// memConn：把「客户端已发的字节」喂给服务端、把服务端吐出来的字节收进缓冲。
// 它是一台**没有网络**的 TLS 服务器：足以走完 ClientHello 的处理与应答，
// 也足以让服务端在任何一处失败时把 alert 写进我们的缓冲。
type memConn struct {
	r io.Reader
	w *bytes.Buffer
}

func (c *memConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *memConn) Write(p []byte) (int, error)        { return c.w.Write(p) }
func (c *memConn) Close() error                       { return nil }
func (c *memConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *memConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *memConn) SetDeadline(time.Time) error        { return nil }
func (c *memConn) SetReadDeadline(time.Time) error    { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error   { return nil }

func TestProbeECHServer(t *testing.T) {
	if *srvOuterHex == "" || *srvConfigHex == "" || *srvPrivHex == "" {
		t.Skip("需要 -srv-outer-hex / -srv-config-hex / -srv-priv-hex")
	}
	outer, err := hex.DecodeString(*srvOuterHex)
	if err != nil {
		t.Fatalf("外层不是十六进制: %v", err)
	}
	config, err := hex.DecodeString(*srvConfigHex)
	if err != nil {
		t.Fatalf("配置不是十六进制: %v", err)
	}
	priv, err := hex.DecodeString(*srvPrivHex)
	if err != nil {
		t.Fatalf("私钥不是十六进制: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: *srvHost},
		DNSNames:     []string{*srvHost},
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

	conn := &memConn{r: bytes.NewReader(asRecord(outer)), w: &bytes.Buffer{}}
	srv := Server(conn, cfg)
	herr := srv.Handshake()
	st := srv.ConnectionState()
	fmt.Printf("PROBE server handshake_err=%v\n", herr)
	fmt.Printf("PROBE server ech_accepted=%v server_name=%q proto=%q\n",
		st.ECHAccepted, st.ServerName, st.NegotiatedProtocol)
	fmt.Printf("PROBE server wrote %d bytes\n", conn.w.Len())
	reportAlerts(t, conn.w.Bytes())
}

// 我们记录的是**握手消息**（`01 || u24 || body`），而服务器读的是**记录**
// （`16 03 01 || u16 || 消息`）—— 第一版直接把消息喂进去，服务器报
// 「first record does not look like a TLS handshake」，正好说明它确实是在按记录读。
func asRecord(msg []byte) []byte {
	out := []byte{22, 3, 1, byte(len(msg) >> 8), byte(len(msg))}
	return append(out, msg...)
}

// 把服务端写出去的东西里的 alert 逐个报出来（`15 03 03 00 02 <level> <desc>`）。
func reportAlerts(t *testing.T, out []byte) {
	t.Helper()
	i := 0
	for i+5 <= len(out) {
		typ := out[i]
		n := int(out[i+3])<<8 | int(out[i+4])
		if i+5+n > len(out) {
			return
		}
		if typ == 21 && n >= 2 {
			fmt.Printf("PROBE server sent ALERT level=%d description=%d (%s)\n",
				out[i+5], out[i+6], alertName(out[i+6]))
		} else {
			fmt.Printf("PROBE server record type=%d len=%d\n", typ, n)
		}
		i += 5 + n
	}
}

func alertName(d byte) string {
	switch d {
	case 40:
		return "handshake_failure"
	case 47:
		return "illegal_parameter  ← defo.ie 报的就是它"
	case 50:
		return "decode_error"
	case 51:
		return "decrypt_error"
	case 70:
		return "protocol_version"
	case 80:
		return "internal_error"
	case 116:
		return "ech_required"
	default:
		return "?"
	}
}
