# 测试用凭据（自签，仅供本地回环测试）

这两个文件是**测试用**的自签证书与私钥，给 `tests/common/mod.rs` 里那台本地
rustls 服务端用。它们不是秘密（私钥就在仓库里），但也**只**能用于本地测试 ——
任何真实用途都必须另生成一份。

| 文件 | 内容 |
|---|---|
| `server-cert.der` | 自签 X.509 证书，DER。`CN=localhost`，SAN：`DNS:localhost`、`DNS:example.com`、`IP:127.0.0.1`，有效期至 2126 |
| `server-key.pk8.der` | 配套私钥，EC P-256，PKCS#8 DER（无口令） |

## 复现（重新生成）

```bash
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER -out server-key.pk8.der
openssl req -new -x509 -key key.pem -out cert.pem -days 36500 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:example.com,IP:127.0.0.1"
openssl x509 -in cert.pem -outform DER -out server-cert.der
rm key.pem cert.pem        # 只留 DER：测试代码用 include_bytes! 直接读
```

生成用的 openssl 版本记在这里，便于日后核对格式：
`OpenSSL 3.6.5 29 Sep 2026 (Library: OpenSSL 3.6.5 29 Sep 2026)`。

## 为什么不用 PEM

`rustls` 的 `CertificateDer` / `PrivatePkcs8KeyDer` 都能直接从 DER 构造，于是测试里
不需要 `rustls-pemfile` 这个额外依赖 —— 少一个依赖就少一处会在升级时腐烂的地方。
