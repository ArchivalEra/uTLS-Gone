// 探针：给「不走代理跑上游那两条要外网的测试」找一个合格的替代域名。
//
// 背景与为什么不是改判据，见 `../run-upstream-suite.sh` 的文件头。要点：上游
// `tls_test.go` 里 `TestVerifyHostname` 与 `TestRealResumption` 带
// `testenv.MustHaveExternalNetwork(t)`，目标写死 `www.google.com` / `yahoo.com`。
// 这两条判的机制与对端是谁无关，所以只要找到「证书 SAN 与自身主机名一致」+
// 「支持 TLS 1.3 会话票据」的对端，就能等价地跑它们。
//
// 本探针就是那个「找」的动作，判据与上游那两条一致：
//   * HOSTNAME：`Dial` 之后 `VerifyHostname(自己)` 必须成功，
//     而 `VerifyHostname("www.yahoo.com")` 必须失败（这是判据的另一半）；
//   * RESUME：连一次、发 `GET`、读一次、关；再连一次，`DidResume` 必须为真。
//
// ⚠️ **本探针要联网，所以不进 CI、也不由任何 cargo 测试驱动**。它是「当初怎么选的
// 域名」的**记录**，要重选时手工跑一次（把本文件复制进参照树，见 ../README.md）：
//
//     cp probes/egress_candidates_test.go /tmp/utls-ref/utls-master/
//     cd /tmp/utls-ref/utls-master && GOPROXY=off go test -count=1 -v -run TestZZEgressCandidates .
//
// 本轮结果（2026-10-01，本机**无代理**直连；6 个域名各跑 4 轮，共测 4 次）：
//
//     www.baidu.com        HOSTNAME ok    RESUME yes（4/4）   ← 选它
//     www.qq.com           HOSTNAME ok    RESUME yes（4/4）
//     cloud.tencent.com    HOSTNAME ok    RESUME yes（4/4）
//     www.tencent.com      HOSTNAME ok    RESUME yes（4/4）
//     www.aliyun.com       HOSTNAME ok    RESUME yes（4/4）
//     www.jd.com           HOSTNAME ok    RESUME yes（3/4，首轮 no）
//
// ⚠️ **`www.jd.com` 那一格是不稳定的**，如实记下来：第一次实测它没复用，之后三次都复用。
// 这既说明「域名能连上」不足以说明它合格（否则第一次的 no 不会是 no），也说明
// **单次观测不能当事实** —— 上游 `TestRealResumption` 自己 `for range 10`、只要有一次
// 复用就算过，正是为了扛住这种抖动。我们因此选 4/4 稳定的 `www.baidu.com`，
// 而不是把「jd 不能复用」写进结论。
package tls

import (
	"fmt"
	"testing"
)

var egressCandidates = []string{
	"www.baidu.com",
	"www.qq.com",
	"cloud.tencent.com",
	"www.tencent.com",
	"www.aliyun.com",
	"www.jd.com",
}

// 与上游 `TestRealResumption` 同一套动作，只把返回值从 `t.Fatal` 换成「报告」。
func tryResume(host string) (bool, error) {
	config := &Config{
		ServerName:         host,
		ClientSessionCache: NewLRUClientSessionCache(0),
	}
	var last error
	for range 4 {
		conn, err := Dial("tcp", host+":443", config)
		if err != nil {
			last = err
			continue
		}
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
		conn.Read(make([]byte, 4096))
		conn.Close()

		conn, err = Dial("tcp", host+":443", config)
		if err != nil {
			last = err
			continue
		}
		st := conn.ConnectionState()
		version, resumed := st.Version, st.DidResume
		conn.Close()
		if resumed {
			return true, nil
		}
		last = fmt.Errorf("not resumed (version=0x%04x)", version)
	}
	return false, last
}

// 与上游 `TestVerifyHostname` 同一套判据（含「拿别的名字验必须失败」那半边）。
func tryHostname(host string) error {
	c, err := Dial("tcp", host+":443", nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.VerifyHostname(host); err != nil {
		return fmt.Errorf("verify self (%s): %w", host, err)
	}
	if err := c.VerifyHostname("www.yahoo.com"); err == nil {
		return fmt.Errorf("verify wrong name succeeded (should fail)")
	}
	return nil
}

func TestZZEgressCandidates(t *testing.T) {
	for _, h := range egressCandidates {
		hn := "HOSTNAME ok"
		if err := tryHostname(h); err != nil {
			hn = "HOSTNAME FAIL: " + err.Error()
		}
		res, resErr := tryResume(h)
		r := "RESUME yes"
		if !res {
			r = fmt.Sprintf("RESUME no (%v)", resErr)
		}
		fmt.Printf("CANDIDATE %-20s %-46s %s\n", h, hn, r)
	}
}
