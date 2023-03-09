package apisigner

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"
)

const (
	TimeFormat                   = "20060102T150405Z"
	shortTimeFormat              = "20060102"
	headerApiSignerContentSha256 = "x-apisigner-content-sha256"
	// emptyStringSHA256 is a SHA256 of an empty string
	emptyStringSHA256 = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
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
	Sign(req *http.Request) (string, error)
	// 检查Authorization 头是否符合预期，认证失败返回错误
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

func NewSigner(logger Logger) *Signer {
	return &Signer{
		Logger: logger,
	}
}

// 获取一个标准签名对象，一般用于外部第三方调用
func (sig *Signer) Standard() SingerSDK {
	return &standardSigner{
		s:          sig,
		headerName: HeaderApiSignerAlgoStandard,
	}
}

// 获取一个简单签名对象，一般用于内部调用时认证
// func (v4 *Signer) Simple() SingerSDK {
// 	return &simpleSigner{
// 		s:          v4,
// 		headerName: HeaderApiSignerAlgoSimple,
// 	}
// }

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

func makeSha256Content(content string) []byte {
	hash := sha256.New()
	hash.Write([]byte(content))
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

func IsExpired(signTime time.Time, vaildTime time.Duration) bool {
	expiredTime := signTime.Add(vaildTime)
	return time.Now().After(expiredTime)
}
