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

	HeaderApiSignerPrefix        = "x-apisigner"
	HeaderApiSignerDate          = "x-apisigner-date"
	HeaderApiSignerNonce         = "x-apisigner-nonce"
	HeaderApiSignerAuthorization = "Authorization"
	HeaderApiSignerAlgoStandard  = "APISIGNER-Standard-HMAC-SHA256"
	HeaderApiSignerAlgoSimple    = "APISIGNER-Simple-HMAC-SHA256"
)
