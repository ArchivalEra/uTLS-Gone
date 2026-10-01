module utlsref

go 1.26

require github.com/refraction-networking/utls v0.0.0

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
)

// 用本地 clone 的 uTLS 源码，避免依赖 github 直连（本机 proxy.golang.org 不通）。
replace github.com/refraction-networking/utls => /tmp/utls-ref/utls-master
