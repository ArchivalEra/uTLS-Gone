// 参考生成器：用真实的 uTLS 产出每个预设的 ClientHello 字节，并用**独立**的
// JA3 实现（从字节解析，不经 uTLS 内部结构）算出指纹。
//
// 输出 JSON 到 stdout，供 Rust 侧对账。这是本项目能拿到的最强外部证人：
// 数据来自参照实现本身，而不是我们的转写。
package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	tls "github.com/refraction-networking/utls"
)

var presets = map[string]tls.ClientHelloID{
	"chrome_58": tls.HelloChrome_58, "chrome_62": tls.HelloChrome_62,
	"chrome_70": tls.HelloChrome_70, "chrome_72": tls.HelloChrome_72,
	"chrome_83": tls.HelloChrome_83, "chrome_87": tls.HelloChrome_87,
	"chrome_96": tls.HelloChrome_96, "chrome_100": tls.HelloChrome_100,
	"chrome_102": tls.HelloChrome_102, "chrome_106": tls.HelloChrome_106_Shuffle,
	"chrome_115_pq": tls.HelloChrome_115_PQ, "chrome_120": tls.HelloChrome_120,
	"chrome_120_pq": tls.HelloChrome_120_PQ, "chrome_131": tls.HelloChrome_131,
	"chrome_133": tls.HelloChrome_133,
	"chrome_100_psk": tls.HelloChrome_100_PSK,
	"chrome_112_psk": tls.HelloChrome_112_PSK_Shuf,
	"chrome_114_psk": tls.HelloChrome_114_Padding_PSK_Shuf,
	"chrome_115_psk": tls.HelloChrome_115_PQ_PSK,
	"firefox_55": tls.HelloFirefox_55, "firefox_56": tls.HelloFirefox_56,
	"firefox_63": tls.HelloFirefox_63, "firefox_65": tls.HelloFirefox_65,
	"firefox_99": tls.HelloFirefox_99, "firefox_102": tls.HelloFirefox_102,
	"firefox_105": tls.HelloFirefox_105, "firefox_120": tls.HelloFirefox_120,
	"firefox_148": tls.HelloFirefox_148,
	"ios_11": tls.HelloIOS_11_1, "ios_12": tls.HelloIOS_12_1, "ios_13": tls.HelloIOS_13, "ios_14": tls.HelloIOS_14,
	"android_11": tls.HelloAndroid_11_OkHttp,
	"edge_85": tls.HelloEdge_85, "edge_106": tls.HelloEdge_106,
	"safari_16": tls.HelloSafari_16_0, "safari_26": tls.HelloSafari_26_3,
	"360_7": tls.Hello360_7_5, "360_11": tls.Hello360_11_0,
	"qq_11": tls.HelloQQ_11_1,
}

const greaseMarker = "GREASE"

func isGrease(v uint16) bool { return v&0x0f0f == 0x0a0a }

// ---- 一个极小的 ClientHello 读取器（独立于 uTLS 内部结构）----

type rd struct{ b []byte; p int }

func (r *rd) take(n int) []byte { s := r.b[r.p : r.p+n]; r.p += n; return s }
func (r *rd) u8() uint8         { return r.take(1)[0] }
func (r *rd) u16() uint16       { s := r.take(2); return uint16(s[0])<<8 | uint16(s[1]) }
func (r *rd) u24() int          { s := r.take(3); return int(s[0])<<16 | int(s[1])<<8 | int(s[2]) }

type extBody struct {
	Type uint16 `json:"type"`
	Body string `json:"body"`
}

type parsed struct {
	LegacyVersion uint16   `json:"legacy_version"`
	Length        int      `json:"length"`
	Ciphers       []uint16 `json:"ciphers"`
	Extensions    []uint16 `json:"extensions"`
	Groups        []uint16 `json:"groups"`
	PointFormats  []uint16 `json:"point_formats"`
	ExtLengths    [][2]int `json:"ext_lengths"` // [类型, 体长]，用于定位「总长差几字节」
	// 逐个扩展的**体内容**（十六进制）。只比长度会漏掉「长度一样、内容错了」——
	// 而那正是「把 Opaque 升级成有类型的变体」时最容易犯的错。
	ExtBodies     []extBody `json:"ext_bodies"`
	Ja3Text       string   `json:"ja3_text"`
	Ja3Md5        string   `json:"ja3_md5"`
}

func parse(raw []byte) parsed {
	r := &rd{b: raw}
	if r.u8() != 1 {
		panic("not a ClientHello")
	}
	_ = r.u24()
	var out parsed
	out.Length = len(raw)
	out.LegacyVersion = r.u16()
	out.Ciphers = []uint16{}
	out.Extensions = []uint16{}
	out.Groups = []uint16{}
	out.PointFormats = []uint16{}
	out.ExtLengths = [][2]int{}
	out.ExtBodies = []extBody{}
	r.take(32)
	r.take(int(r.u8()))
	n := int(r.u16())
	for _, c := range chunk2(r.take(n)) {
		if !isGrease(c) {
			out.Ciphers = append(out.Ciphers, c)
		}
	}
	r.take(int(r.u8()))
	en := int(r.u16())
	exts := r.take(en)
	e := &rd{b: exts}
	for e.p < len(exts) {
		id := e.u16()
		bl := int(e.u16())
		body := e.take(bl)
		if !isGrease(id) {
			out.Extensions = append(out.Extensions, id)
		}
		out.ExtLengths = append(out.ExtLengths, [2]int{int(id), len(body)})
		out.ExtBodies = append(out.ExtBodies, extBody{id, hex.EncodeToString(body)})
		if id == 10 { // supported_groups
			s := &rd{b: body[2:]}
			for _, g := range chunk2(s.take(s.p + len(body) - 2)) {
				if !isGrease(g) {
					out.Groups = append(out.Groups, g)
				}
			}
		}
		if id == 11 { // ec_point_formats
			s := &rd{b: body}
			pf := s.take(int(s.u8()))
			for _, x := range pf { out.PointFormats = append(out.PointFormats, uint16(x)) }
		}
	}
	out.Ja3Text = fmt.Sprintf("%d,%s,%s,%s,%s",
		out.LegacyVersion, join16(out.Ciphers), join16(out.Extensions),
		join16(out.Groups), join8(out.PointFormats))
	sum := md5.Sum([]byte(out.Ja3Text))
	out.Ja3Md5 = hex.EncodeToString(sum[:])
	return out
}

func chunk2(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out
}
func join16(v []uint16) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprint(x)
	}
	return strings.Join(s, "-")
}
func join8(v []uint16) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprint(x)
	}
	return strings.Join(s, "-")
}

// 随机化族的对账：**固定种子**下 uTLS 的产出是确定的，
// 所以这里能和本仓逐字段比。种子取 [i;32]，两边都好复现。
func randomizedDump() {
	type rec struct {
		Name   string `json:"name"`
		Seed   int    `json:"seed"`
		Parsed *parsed `json:"parsed,omitempty"`
		Err    string `json:"error,omitempty"`
	}
	ids := map[string]tls.ClientHelloID{
		"randomized":         tls.HelloRandomized,
		"randomized_alpn":    tls.HelloRandomizedALPN,
		"randomized_no_alpn": tls.HelloRandomizedNoALPN,
	}
	out := map[string]rec{}
	names := []string{"randomized", "randomized_alpn", "randomized_no_alpn"}
	for _, name := range names {
		for i := 0; i < 8; i++ {
			id := ids[name]
			var seed tls.PRNGSeed
			for k := range seed {
				seed[k] = byte(i)
			}
			id.Seed = &seed
			raw, err := build(id)
			key := fmt.Sprintf("%s/%d", name, i)
			if err != nil {
				out[key] = rec{Name: name, Seed: i, Err: err.Error()}
				continue
			}
			p := parse(raw)
			out[key] = rec{Name: name, Seed: i, Parsed: &p}
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "randomized" {
		randomizedDump()
		return
	}
	type entry struct {
		Name     string   `json:"name"`
		Err      string   `json:"error,omitempty"`
		HelloLen int      `json:"hello_len"`
		Parsed   *parsed  `json:"parsed,omitempty"`
		// 同一预设跑 48 次的观测：JA3 是否稳定、长度是否稳定、非 GREASE 扩展的多重集是否稳定
		Ja3Stable   bool     `json:"ja3_stable"`
		LenStable   bool     `json:"len_stable"`
		Lens        []int    `json:"lens"`
		ExtMultiset []uint16 `json:"ext_multiset"`
	}
	names := make([]string, 0, len(presets))
	for n := range presets {
		names = append(names, n)
	}
	// 稳定排序输出，便于 diff
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	out := map[string]entry{}
	for _, name := range names {
		id := presets[name]
		first := true
		var e entry
		e.Name = name
		ja3set := map[string]bool{}
		lenset := map[int]bool{}
		mset := map[string]int{}
		for run := 0; run < 48; run++ {
			raw, err := build(id)
			if err != nil {
				e.Err = err.Error()
				break
			}
			p := parse(raw)
			if first {
				e.Parsed = &p
				e.HelloLen = p.Length
				first = false
			}
			ja3set[p.Ja3Md5] = true
			lenset[p.Length] = true
			key := join16(p.Extensions)
			mset[key]++
		}
		e.Ja3Stable = len(ja3set) == 1
		e.LenStable = len(lenset) == 1
		for l := range lenset {
			e.Lens = append(e.Lens, l)
		}
		// 取出现次数最多的那个多重集（对乱序预设而言就是「规范顺序」的那一支最可能出现）
		if e.Parsed != nil {
			e.ExtMultiset = e.Parsed.Extensions
		}
		out[name] = e
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build(id tls.ClientHelloID) (raw []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	c1, _ := net.Pipe()
	defer c1.Close()
	// `OmitEmptyPsk`：uTLS 对「没有会话的 PSK 扩展」有两条路 —— 报错，或者按这个开关
	// 把空 PSK 整个省掉。这里开它，好让 `_PSK_` 预设能被**观测**（否则它们直接报错）。
	// 对非 PSK 预设它没有影响（只有 PSK 扩展读这个开关）。
	cfg := &tls.Config{ServerName: "example.com", OmitEmptyPsk: true}
	u := tls.UClient(c1, cfg, id)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}
	if u.HandshakeState.Hello == nil {
		return nil, fmt.Errorf("no handshake state")
	}
	if len(u.HandshakeState.Hello.Raw) == 0 {
		return nil, fmt.Errorf("empty Raw")
	}
	return u.HandshakeState.Hello.Raw, nil
}
