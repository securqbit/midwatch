module github.com/securqbit/midwatch

// A modern floor rather than the oldest version the code would compile on.
// `go install` builds with the user's toolchain, and midwatch links crypto/tls,
// crypto/x509, encoding/asn1 and net/http — the exact packages whose output it
// then reasons about. Go's toolchain switching upgrades anyone on an older
// release automatically, so this keeps a stale stdlib out of a security tool.
go 1.25.0
