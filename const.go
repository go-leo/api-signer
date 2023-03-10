package apisigner

const (
	SchemeHttp  = "http"
	SchemeHttps = "https"

	MethodGet    = "GET"
	MethodPut    = "PUT"
	MethodPost   = "POST"
	MethodDelete = "DELETE"
	MethodPatch  = "PATCH"
	MethodHead   = "HEAD"

	HeaderApiSignerDate          = "x-ca-date"
	HeaderApiSignerNonce         = "x-ca-nonce"
	HeaderApiSignerAuthorization = "Authorization"
	HeaderApiSignerAlgo          = "APISIGNER-HMAC-SHA256"
)

const (
	TimeFormat      = "20060102T150405Z"
	shortTimeFormat = "20060102"
)

// emptyStringSHA256 is a SHA256 of an empty string
const emptyStringSHA256 = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
