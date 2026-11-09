module github.com/patrickbrandao/finger-sniffer

go 1.27

// SHA-1 no TLS 1.2 e clientes sem signature_algorithms, para observar clientes antigos (pkg/certs).
godebug tlssha1=1

require (
	github.com/fsnotify/fsnotify v1.10.1
	github.com/gopacket/gopacket v1.7.7
	github.com/miekg/dns v1.1.73
	github.com/nats-io/nats-server/v2 v2.15.2
	github.com/nats-io/nats.go v1.55.0
	github.com/oklog/ulid/v2 v2.1.1
	github.com/pressly/goose/v3 v3.29.0
	golang.org/x/net v0.62.0
	modernc.org/sqlite v1.62.0
)

require (
	github.com/antithesishq/antithesis-sdk-go v0.8.0-default-no-op // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.20.3 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/minio/highwayhash v1.0.4 // indirect
	github.com/nats-io/jwt/v2 v2.8.2 // indirect
	github.com/nats-io/nkeys v0.4.16 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/sethvargo/go-retry v0.5.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	modernc.org/libc v1.80.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
