// REALITY 鉴权 KDF/AEAD 的**测试向量发生器**。
//
// 逐行复刻两段权威实现（不改一行语义，只把随机源换成确定性的）：
//   - 服务端开启：XTLS/REALITY `tls.go:241-260`
//     （X25519 → HKDF-SHA256(salt=random[:20], info="REALITY") → AES-256-GCM Open，
//     AAD = sessionId 置零后的原始 ClientHello）
//   - 客户端封装：Xray-core `transport/internet/reality/reality.go` UClient
//     （sessionId[0:4]=版本、[4:8]=unix time、[8:16]=shortId，Seal 后回填 Raw[39:]）
//
// hello 用上游 uTLS 的真实指纹（HelloChrome_100）+ 确定性 rand 产出 ——
// 与 utls-reference.json 同一取样原则：向量来自参照实现的实际产出，不手抄。
//
// 重新生成（本机 GOPROXY 用 goproxy.cn；utls 指向 /tmp 的参照树，见 go.mod）：
//
//	GOPROXY=https://goproxy.cn,direct go run . > ../reality-vectors.json
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

// 确定性 rand：字节流 = seed 递增（非零、非退化，可复现）。
type detRand struct{ s byte }

func (d *detRand) Read(p []byte) (int, error) {
	for i := range p {
		d.s++
		p[i] = d.s
	}
	return len(p), nil
}

func x25519(priv, peerPub []byte) ([]byte, error) {
	s, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	p, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return s.ECDH(p)
}

func authKey(shared, helloRandom []byte) ([]byte, error) {
	// tls.go:244：hkdf.New(sha256.New, AuthKey, random[:20], []byte("REALITY")).Read(32)
	r := hkdf.New(sha256.New, shared, helloRandom[:20], []byte("REALITY"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func main() {
	// ── 固定输入（与 Rust 侧测试共用，见 vectors JSON）──
	serverPrivate, _ := hex.DecodeString("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90")
	// 客户端临时私钥由 utls 生成（KeyShareKeys.Ecdhe），这里运行时取出，不固定。
	shortId, _ := hex.DecodeString("0123456789abcdef")
	xrayVer := []byte{1, 8, 13, 0}
	now := uint32(1767139200) // 2026-01-01T00:00:00Z，固定「时刻」

	// ── 客户端 hello：真实指纹 + 确定性 rand ──
	cfg := &utls.Config{Rand: &detRand{}, InsecureSkipVerify: true, ServerName: "localhost"}
	uConn := utls.UClient(nil, cfg, utls.HelloChrome_100)
	if err := uConn.BuildHandshakeState(); err != nil {
		fmt.Fprintln(os.Stderr, "BuildHandshakeState:", err)
		os.Exit(1)
	}
	hello := uConn.HandshakeState.Hello
	if len(hello.SessionId) != 32 {
		fmt.Fprintln(os.Stderr, "sessionId 长度不是 32")
		os.Exit(1)
	}

	// ── 客户端临时 X25519 私钥（KeyShareKeys.Ecdhe）与其公钥 ──
	ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		fmt.Fprintln(os.Stderr, "指纹没有 X25519 ECDHE")
		os.Exit(1)
	}
	clientEphemeral := ecdhe.Bytes()

	// ── 服务端静态密钥对（私钥固定 ⇒ 公钥可推导，两边共用同一密钥对）──
	serverPrivKey, _ := ecdh.X25519().NewPrivateKey(serverPrivate)
	serverPublic := serverPrivKey.PublicKey().Bytes()

	// ── 客户端封装（reality.go UClient）──
	// SessionId[0:4]=版本、[4:8]=time、[8:16]=shortId、[16:32]=0（make 的零值）
	copy(hello.Raw[39:], hello.SessionId) // 先把 Raw 里的 sessionId 置为当前值
	hello.SessionId[0] = xrayVer[0]
	hello.SessionId[1] = xrayVer[1]
	hello.SessionId[2] = xrayVer[2]
	hello.SessionId[3] = xrayVer[3]
	binary.BigEndian.PutUint32(hello.SessionId[4:], now)
	copy(hello.SessionId[8:], shortId)
	// AAD 约定：sessionId 置零后的原始 hello（客户端此刻 Raw[39:71] 是**全零**，
	// 因为第一条 copy 写入的是 make 的零值 —— 与服务端「plainText 覆写后再 Open」对齐）
	for i := 39; i < 71; i++ {
		hello.Raw[i] = 0
	}
	plaintext16 := make([]byte, 16)
	copy(plaintext16, hello.SessionId[:16])

	shared, err := x25519(clientEphemeral, serverPublic)
	if err != nil {
		fmt.Fprintln(os.Stderr, "X25519:", err)
		os.Exit(1)
	}
	authKey, err := authKey(shared, hello.Random)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hkdf:", err)
		os.Exit(1)
	}

	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	sessionIdCipher := aead.Seal(nil, hello.Random[20:], plaintext16, hello.Raw)

	// ── 服务端开启（tls.go）—— 自校验：AAD 用「sessionId 置零」的同一份 raw ──
	copy(hello.Raw[39:], sessionIdCipher) // 线上形态：密文回填
	serverOriginal := append([]byte{}, hello.Raw...)
	serverSid := serverOriginal[39:71]
	serverAad := append([]byte{}, serverOriginal...)
	for i := 39; i < 71; i++ {
		serverAad[i] = 0
	}
	plainBack, err := aead.Open(nil, serverOriginal[6+20:6+32], serverSid, serverAad)
	if err != nil {
		fmt.Fprintln(os.Stderr, "服务端自校验 Open 失败:", err)
		os.Exit(1)
	}
	if !bytes.Equal(plainBack, plaintext16) {
		fmt.Fprintln(os.Stderr, "服务端自校验明文不一致")
		os.Exit(1)
	}

	// ── 输出向量 ──
	hx := func(b []byte) string { return hex.EncodeToString(b) }
	out, _ := json.MarshalIndent(map[string]string{
		"server_private":       hx(serverPrivate),
		"server_public":        hx(serverPublic),
		"client_ephemeral":     hx(clientEphemeral),
		"short_id":             hx(shortId),
		"xray_version":         hx(xrayVer),
		"now":                  fmt.Sprintf("%d", now),
		"hello_random":         hx(hello.Random),
		"hello_raw_sid_cipher": hx(hello.Raw), // 线上形态（密文 sessionId 回填后）
		"plaintext16":          hx(plaintext16),
		"auth_key":             hx(authKey),
		"session_id_cipher":    hx(sessionIdCipher),
		"sni":                  "localhost",
	}, "", "  ")
	fmt.Println(string(out))
}
