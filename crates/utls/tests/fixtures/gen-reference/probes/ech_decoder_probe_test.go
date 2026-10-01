// uTLS **服务端解码器**的探针 —— 拿它判「我们的内层 hello 服务器吃不吃」。
//
// 为什么：`defo.ie`（Go 系服务端）拒我们的方式是 `IllegalParameter`，而在 uTLS/Go 的
// 服务端代码里，那个 alert **只有一个出处** —— `decodeInnerClientHello` 返回错误
// （`ech.go`：`sendAlert(alertIllegalParameter); return nil, nil, errInvalidECHExt`）。
// 所以「uTLS 自己的解码器吃不吃我们的字节」就是那条失败**离线可复跑**的等价物；
// 它还会把**服务器重建出来的内层**（转录用的那串字节）打出来，于是
// `Rejected`（转录分叉）那一半也能离线对齐。
//
// 用法（它**不改** uTLS 任何一行，只多一个测试文件）：
//
//	cp <repo>/crates/utls/tests/fixtures/gen-reference/probes/ech_decoder_probe_test.go /tmp/utls-ref/utls-master/
//	cd /tmp/utls-ref/utls-master
//	# 两个 hex 由 Rust 侧打出：
//	cargo test -p utls-engine --test ech_inner_utls -- --nocapture dump_outer_and_inner
//	go test -run TestProbeECHDecode -v -outer-hex "$OUTER" -inner-hex "$INNER"
//
// 判据是「uTLS 的解码器说什么」—— 不是我的复述。
package tls

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"testing"
)

var (
	probeOuterHex = flag.String("outer-hex", "", "外层 ClientHello 握手消息（十六进制，不含记录头）")
	probeInnerHex = flag.String("inner-hex", "", "内层 hello 的密封形态（十六进制，含补零）")
)

func TestProbeECHDecode(t *testing.T) {
	if *probeOuterHex == "" || *probeInnerHex == "" {
		t.Skip("需要 -outer-hex 与 -inner-hex")
	}
	outerBytes, err := hex.DecodeString(*probeOuterHex)
	if err != nil {
		t.Fatalf("外层不是十六进制: %v", err)
	}
	innerBytes, err := hex.DecodeString(*probeInnerHex)
	if err != nil {
		t.Fatalf("内层不是十六进制: %v", err)
	}

	outer := &clientHelloMsg{}
	if !outer.unmarshal(outerBytes) {
		t.Fatalf("外层解不开（%d 字节）", len(outerBytes))
	}
	// 外层扩展顺序：服务器解码内层时按它做单调查找，所以它也是判据的一部分。
	rawOuterExts, err := extractRawExtensions(outer)
	if err != nil {
		t.Fatalf("外层扩展解不开: %v", err)
	}
	fmt.Printf("PROBE outer ext order: %v\n", func() []uint16 {
		var out []uint16
		for _, e := range rawOuterExts {
			out = append(out, e.extType)
		}
		return out
	}())

	inner, err := decodeInnerClientHello(outer, innerBytes)
	if err != nil {
		fmt.Printf("PROBE decode result: ERROR %v\n", err)
		t.Fatalf("uTLS 的解码器拒了我们的内层：%v", err)
	}
	recon, err := inner.marshal()
	if err != nil {
		t.Fatalf("重建的内层 marshal 失败: %v", err)
	}
	fmt.Printf("PROBE decode result: OK\n")
	fmt.Printf("PROBE reconstructed_len=%d\n", len(recon))
	fmt.Printf("PROBE reconstructed_hex=%s\n", hex.EncodeToString(recon))
	fmt.Printf("PROBE inner_ext_order=%v\n", func() []uint16 {
		var out []uint16
		for _, e := range extractRawExtsFromMsg(t, recon) {
			out = append(out, e)
		}
		return out
	}())

	// ── 服务器处理的**第一步**：解外层那条 `0xfe0d` ──
	// `processECHClientHello` 的第一件事就是 `parseECHExt(outer.encryptedClientHello)`，
	// 而它在两种情况下发 **IllegalParameter**：`errInvalidECHExt`（类型位既不是 0 也不是 1）。
	// 其余错误是 `decode_error`。所以这一步的结果决定「IllegalParameter 是不是从这儿来的」。
	echType, cs, configID, encap, payload, perr := parseECHExt(outer.encryptedClientHello)
	fmt.Printf("PROBE parseECHExt: echType=%d ciphersuite=%+v configID=0x%02x encap_len=%d payload_len=%d err=%v\n",
		echType, cs, configID, len(encap), len(payload), perr)
	if perr != nil {
		fmt.Printf("PROBE parseECHExt would send: %s\n", func() string {
			if errors.Is(perr, errInvalidECHExt) {
				return "alertIllegalParameter  ← defo.ie 报的就是它"
			}
			return "alertDecodeError"
		}())
	}
}

// 重建出来的内层里，扩展类型按线序（只看类型，便于人读）。
func extractRawExtsFromMsg(t *testing.T, msg []byte) []uint16 {
	t.Helper()
	m := &clientHelloMsg{}
	if !m.unmarshal(msg) {
		t.Fatalf("重建的内层解不开")
	}
	var out []uint16
	// clientHelloMsg 只记它认识的扩展；未知类型（如 0xfd00 已被展开，不会有）
	// 由 raw 里数一遍更可靠 —— 这里直接数线字节。
	var p int
	p = 4 + 2 + 32
	sidLen := int(msg[p])
	p += 1 + sidLen
	csLen := int(msg[p])<<8 | int(msg[p+1])
	p += 2 + csLen
	compLen := int(msg[p])
	p += 1 + compLen
	if p+2 > len(msg) {
		return out
	}
	extLen := int(msg[p])<<8 | int(msg[p+1])
	p += 2
	end := p + extLen
	for p+4 <= end {
		ty := uint16(msg[p])<<8 | uint16(msg[p+1])
		l := int(msg[p+2])<<8 | int(msg[p+3])
		out = append(out, ty)
		p += 4 + l
	}
	return out
}
