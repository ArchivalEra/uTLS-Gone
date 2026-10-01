// 哪个转录？—— 用「服务器给的接受确认」反推服务器到底哈希了什么。
//
// 背景：`crypto.cloudflare.com` 判我们 `Rejected`，而同一份字节在 **uTLS 自己的服务端**上
// 是被**接受**的（`ech_server_utls_server.rs` 那条测试），且我们喂给确认的转录与
// **uTLS 自己的解码器**重建出来的字节**逐字节相同**（`ech_decoder_probe_test.go`）。
// 于是只剩一种解释：Cloudflare 哈希的是**另一串字节**。
//
// 这一条就把那串字节找出来：把「内层的几种可能形态」逐个算一遍确认值，
// 与服务器 ServerHello 里的那 8 个字节比 —— 对上的那个，就是它用的转录。
//
// 公式（两个参照实现逐字一致，见 rustls `server_ech_confirmation_secret` 与
// uTLS `handshake_client_tls13.go`）：
//
//	accept_confirmation = HKDF-Expand-Label(
//	    HKDF-Extract(salt=nil, ikm=ClientHelloInner.random),
//	    "ech accept confirmation",
//	    Hash(inner_hello_message || ServerHello_with_random_tail_zeroed), 8)
//
// 用法：
//
//	cp <repo>/crates/utls/tests/fixtures/gen-reference/probes/ech_confirmation_probe_test.go /tmp/utls-ref/utls-master/
//	cd /tmp/utls-ref/utls-master
//	go test -run TestProbeECHConfirmation -v \
//	  -conf-outer-hex "$OUTER" -conf-inner-hex "$SEALED" -conf-expanded-hex "$EXPANDED" \
//	  -conf-serverhello-hex "$SH"
package tls

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"testing"
)

var (
	confOuterHex      = flag.String("conf-outer-hex", "", "我们发的外层 ClientHello 握手消息")
	confInnerHex      = flag.String("conf-inner-hex", "", "内层的**密封形态**（含末尾补零）")
	confExpandedHex   = flag.String("conf-expanded-hex", "", "内层的**转录形态**（我们展开的那份，体）")
	confServerHello   = flag.String("conf-serverhello-hex", "", "服务器回的 ServerHello 握手消息")
	confInnerRandomHi = flag.String("conf-inner-random-hex", "", "内层随机数（不给就从密封形态里取）")
)

func TestProbeECHConfirmation(t *testing.T) {
	if *confInnerHex == "" || *confServerHello == "" {
		t.Skip("需要 -conf-inner-hex 与 -conf-serverhello-hex")
	}
	outer := mustHex(t, *confOuterHex)
	sealed := mustHex(t, *confInnerHex)
	expanded := mustHex(t, *confExpandedHex)
	sh := mustHex(t, *confServerHello)

	if len(sh) < 38 {
		t.Fatalf("ServerHello 太短：%d", len(sh))
	}
	want := sh[30:38] // 随机的最后 8 字节 = 服务器的确认值
	fmt.Printf("PROBE server_tail=%x\n", want)

	// 外层 session id（重建时被插进内层的那个）。
	outerSID := sessionIDOf(outer)
	fmt.Printf("PROBE outer_session_id_len=%d\n", len(outerSID))

	innerRandom := sealed[2:34]
	if *confInnerRandomHi != "" {
		innerRandom = mustHex(t, *confInnerRandomHi)
	}
	fmt.Printf("PROBE inner_random=%x\n", innerRandom)

	// ServerHello 的确认形态：随机数最后 8 字节清零。
	shConf := append([]byte{}, sh...)
	for i := 30; i < 38; i++ {
		shConf[i] = 0
	}

	// 内层的候选形态。`sealed` 含末尾补零；再给一个「去掉补零」的版本
	// （补零是明文里的东西，服务器解出来的明文里当然有它 —— 但万一某实现把它也哈希了）。
	noPad := sealed[:len(sealed)-trailingZeros(sealed)]

	type cand struct {
		name string
		body []byte
		sid  []byte
	}
	cands := []cand{
		{"expanded + outer_sid", expanded, outerSID},
		{"expanded + empty_sid", expanded, nil},
		{"sealed(with pad) + outer_sid", sealed, outerSID},
		{"sealed(with pad) + empty_sid", sealed, nil},
		{"sealed(no pad) + outer_sid", noPad, outerSID},
		{"sealed(no pad) + empty_sid", noPad, nil},
	}
	for _, c := range cands {
		msg := asClientHelloMessage(substituteSID(c.body, c.sid))
		report("msg", c.name, innerRandom, msg, shConf, want)
	}

	// ── 另外几种「服务器会怎么拿转录」的可能 ──
	// ① 服务器把解出来的内层当**结构体**再序列化一遍 ⇒ Go 的字段顺序（而不是重建的原始字节）。
	outerMsg := &clientHelloMsg{}
	if !outerMsg.unmarshal(outer) {
		t.Fatalf("外层解不开")
	}
	if innerMsg, err := decodeInnerClientHello(outerMsg, noPad); err == nil {
		innerMsg.original = nil // 强迫它按字段重新 marshal
		if re, err := innerMsg.marshal(); err == nil {
			report("msg", "解码后按 Go 字段顺序重排", innerRandom, re, shConf, want)
		}
	}
	// ② 转录里**不把** ServerHello 的随机尾清零（照原样哈希）。
	report("msg", "expanded+outer_sid 且 ServerHello 不清零",
		innerRandom, asClientHelloMessage(substituteSID(expanded, outerSID)), sh, want)
	// ③ 只哈希内层（不含 ServerHello）。
	report("msg", "只哈希内层（不含 ServerHello）",
		innerRandom, asClientHelloMessage(substituteSID(expanded, outerSID)), nil, want)
	// ④ 哈希算法换成 SHA-384（万一协商的其实是 1302）。
	h384 := sha512.New384()
	h384.Write(asClientHelloMessage(substituteSID(expanded, outerSID)))
	h384.Write(shConf)
	fmt.Printf("PROBE [sha384] expanded+outer_sid ⇒ %x\n", confirmation384(innerRandom, h384.Sum(nil)))
	// ⑤ 把我们的**外层**当内层用（万一 Cloudflare 把 ECH 当 GREASE 但又切了密钥）。
	report("msg", "外层当内层（+outer_sid）",
		innerRandom, asClientHelloMessage(substituteSID(outer[4:], outerSID)), shConf, want)
}

// 把候选转录算出来的确认值与服务器的那个比。
func report(kind, name string, innerRandom, msg, shConf, want []byte) {
	h := sha256.New()
	h.Write(msg)
	if shConf != nil {
		h.Write(shConf)
	}
	got := confirmation(innerRandom, h.Sum(nil))
	mark := "   "
	if hex.EncodeToString(got) == hex.EncodeToString(want) {
		mark = ">> "
	}
	fmt.Printf("PROBE %s[%s] %s ⇒ %x\n", mark, kind, name, got)
}

// accept_confirmation = ExpandLabel(Extract(0, inner_random), "ech accept confirmation", transcript, 8)
func confirmation(innerRandom, transcript []byte) []byte {
	prk, err := hkdf.Extract(sha256.New, innerRandom, nil)
	if err != nil {
		panic(err)
	}
	label := append([]byte("tls13 "), []byte("ech accept confirmation")...)
	info := []byte{0, 8, byte(len(label))}
	info = append(info, label...)
	info = append(info, byte(len(transcript)))
	info = append(info, transcript...)
	out, err := hkdf.Expand(sha256.New, prk, string(info), 8)
	if err != nil {
		panic(err)
	}
	return out
}

func confirmation384(innerRandom, transcript []byte) []byte {
	prk, err := hkdf.Extract(sha512.New384, innerRandom, nil)
	if err != nil {
		panic(err)
	}
	label := append([]byte("tls13 "), []byte("ech accept confirmation")...)
	info := []byte{0, 8, byte(len(label))}
	info = append(info, label...)
	info = append(info, byte(len(transcript)))
	info = append(info, transcript...)
	out, err := hkdf.Expand(sha512.New384, prk, string(info), 8)
	if err != nil {
		panic(err)
	}
	return out
}

func asClientHelloMessage(body []byte) []byte {
	out := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

// 内层的**密封形态**里 session id 是空的；服务器重建时会把外层的插进去。
func substituteSID(body, sid []byte) []byte {
	sidLen := int(body[34])
	out := append([]byte{}, body[:34]...)
	out = append(out, byte(len(sid)))
	out = append(out, sid...)
	return append(out, body[35+sidLen:]...)
}

func sessionIDOf(msg []byte) []byte {
	n := int(msg[38])
	return msg[39 : 39+n]
}

func trailingZeros(b []byte) int {
	n := 0
	for i := len(b) - 1; i >= 0 && b[i] == 0; i-- {
		n++
	}
	return n
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	v, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("不是十六进制: %v", err)
	}
	return v
}
