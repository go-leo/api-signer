package apisigner

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"
)

var noEscape [256]bool

func init() {
	for i := 0; i < len(noEscape); i++ {
		// expects every character except these to be escaped
		noEscape[i] = (i >= 'A' && i <= 'Z') ||
			(i >= 'a' && i <= 'z') ||
			(i >= '0' && i <= '9') ||
			i == '-' ||
			i == '.' ||
			i == '_' ||
			i == '~'
	}
}

type IClientSigner interface {
	// 设置签名所需的头字段
	SetAuthHeader(req *http.Request) error
}
type ISeverSigner interface {
	// 返回服务端生成的 Authorization 头
	Authorization(req *http.Request) (string, error)
	// 检查认证信息是否符合预期，认证失败返回错误
	Vaild(req *http.Request) error
}

type CredentialFunc func(ak string) (sk string)
type NonceRepeatedFunc func(nonce string) bool

type SingerSDK interface {
	Client(region, service string, c Credential) IClientSigner
	Server(vaildTime time.Duration, cf CredentialFunc, nf NonceRepeatedFunc) ISeverSigner
}

type Signer struct {
	Logger Logger
}

func NewSigner(logger Logger) SingerSDK {
	return &standardSigner{
		s: &Signer{
			Logger: logger,
		},
		headerName: HeaderApiSignerAlgo,
	}
}

func makeHmacSha256(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)

}

func makeSha256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

// EscapePath escapes part of a URL path
func EscapePath(path string, encodeSep bool) string {
	var buf bytes.Buffer
	for i := 0; i < len(path); i++ {
		c := path[i]
		if noEscape[c] || (c == '/' && !encodeSep) {
			buf.WriteByte(c)
		} else {
			fmt.Fprintf(&buf, "%%%02X", c)
		}
	}
	return buf.String()
}

func IsInvalidTime(signTime time.Time, vaildTime time.Duration) bool {
	now := time.Now()
	if now.Before(signTime) {
		return true
	}

	expiredTime := signTime.Add(vaildTime)
	return now.After(expiredTime)
}
