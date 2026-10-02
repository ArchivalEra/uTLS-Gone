// 「产出一条 ClientHello（uTLS 公开 API 路径）」的 Go 侧基准 —— 与
// `crates/utls-engine/examples/plan-cost.rs` 同层、同工作量，用来做**速度与 CPU 消耗**对比。
//
// # 为什么必须有它
//
// 「我们的实现有多快」只有在**同一层**上问才有意义。`plan-cost.rs` 跑的是引擎那道缝
// （`FingerprintClient::plan`：起真密钥交换 + 编码 + 记账），对应的 uTLS 动作是
// `tls.UClient(...) + BuildHandshakeState()` —— 就是本程序的 `build()`。
// 拿指纹层的 `marshal` 去比会得到一个虚高的倍数（本轮实测踩到：看着 29×，其实不可比）。
//
// # 它**不**做 JA3 解析
//
// 单位是「产出一条 hello」，不是「产出 + 独立解析」。参照发生器（`../main.go`）里的
// `parse()` 那是**另一件事**（它要 JA3 做对账）；两边都减到同一件事才可比。
//
// # 怎么跑（要一份 uTLS 源码树；见 ../README.md 的取回命令）
//
//     mkdir -p /tmp/planbench && cp bench/main.go /tmp/planbench/
//     cd /tmp/planbench && cat > go.mod <<'EOF'
//     module planbench
//     go 1.26
//     require github.com/refraction-networking/utls v0.0.0
//     replace github.com/refraction-networking/utls => /tmp/utls-ref/utls-master
//     EOF
//     go mod tidy && go build -o planbench . && ./planbench chrome_70 chrome_120
//
// # 两个必须注意的测量事项（本轮踩出来的）
//
// 1. **每进程固定开销要单独量**：同一个进程多跑几条，单位成本就摊薄 —— 只跑 48 条时
//    「µs/条」几乎全是启动开销。做法：预设名拼错（一条都不建）量固定开销；
//    同一批预设跑 n 与 10n 各一次，解出边际成本。`PLANBENCH_RUNS` 用来改每预设次数。
// 2. **预设集合要对齐**：`plan-cost` 会打出它能建的 28 档（另有 12 档引擎拒绝 ——
//    TLS 1.2 时代没有 `key_share` 的、以及用了提供者不提供的组的）。两边取同一个集合。
package main

import (
	"fmt"
	"os"
	"strconv"
	"hash/fnv"
	"net"
	"runtime"
	"time"

	tls "github.com/refraction-networking/utls"
)

var runs = func() int {
	if v := os.Getenv("PLANBENCH_RUNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 48
}()

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
	"ios_11": tls.HelloIOS_11_1, "ios_12": tls.HelloIOS_12_1, "ios_13": tls.HelloIOS_13,
	"android_11": tls.HelloAndroid_11_OkHttp,
	"edge_85": tls.HelloEdge_85, "edge_106": tls.HelloEdge_106,
	"safari_16": tls.HelloSafari_16_0, "safari_26": tls.HelloSafari_26_3,
	"360_7": tls.Hello360_7_5, "360_11": tls.Hello360_11_0,
	"qq_11": tls.HelloQQ_11_1,
}

func main() {
	only := map[string]bool{}
	for _, a := range os.Args[1:] {
		only[a] = true
	}
	names := []string{}
	for n := range presets {
		if len(only) == 0 || only[n] {
			names = append(names, n)
		}
	}
	// 让顺序稳定（Go 的 map 遍历是随机的）
	for i := 0; i+1 < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	h := fnv.New64a()
	units, nPresets := 0, 0
	// 分配口径与 Rust 侧 plan-cost 的 alloc_bytes 相同：循环内累计堆分配字节数
	// （TotalAlloc 不受 GC 影响）—— 量「分配了多少」，不是「占着多少」（后者是 RSS）。
	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)
	t0 := time.Now()
	for _, n := range names {
		id := presets[n]
		nPresets++
		for r := 0; r < runs; r++ {
			raw, err := build(id)
			if err != nil {
				panic(err)
			}
			h.Write(raw)
			units++
		}
	}
	fmt.Printf("presets=%d runs_each=%d units=%d\n", nPresets, runs, units)
	fmt.Printf("elapsed=%v\n", time.Since(t0))
	fmt.Printf("checksum=%016x\n", h.Sum64())
	runtime.ReadMemStats(&memAfter)
	fmt.Printf("alloc_bytes=%d\n", memAfter.TotalAlloc-memBefore.TotalAlloc)
}

func build(id tls.ClientHelloID) (raw []byte, err error) {
	c1, _ := net.Pipe()
	defer c1.Close()
	cfg := &tls.Config{ServerName: "example.com", OmitEmptyPsk: true}
	u := tls.UClient(c1, cfg, id)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}
	return u.HandshakeState.Hello.Raw, nil
}
