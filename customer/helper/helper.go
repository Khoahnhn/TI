package helper

import (
	"github.com/joeguo/tldextract"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
)

func init() {
	tldExtractor, _ = tldextract.New(defs.DefaultTLDCacheFilePath, false)
}
