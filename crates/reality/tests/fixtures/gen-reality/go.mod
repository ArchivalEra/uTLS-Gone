module genreality

go 1.26

require (
	github.com/refraction-networking/utls v0.0.0
	golang.org/x/crypto v0.36.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	golang.org/x/sys v0.31.0 // indirect
)

// 与 gen-reference 同一取样原则：utls 指向本地参照树。
replace github.com/refraction-networking/utls => /tmp/utls-ref/utls-master
