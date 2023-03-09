package apisigner

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// func TestSigner(t *testing.T) {
// 	host := "new-media.kureader.com"
// 	path := "/admin/v1/assets/vip"
// 	method := "POST"

// 	var header = make(http.Header)
// 	buildNonce(header) // 必须包含x-jdcloud-nonce
// 	buildTime(header)  // 必须包含x-jdcloud-date
// 	header.Set("content-type", "application/json")

// 	// query可以为nil
// 	var query = make(url.Values)
// 	query["filters.1.name"] = []string{"id"}
// 	query["filters.1.values.1"] = []string{"v1"}
// 	query["filters.1.values.2"] = []string{"v2"}

// 	// body可以为""
// 	body := ""

// 	Credential := NewCredential("access key", "secret key")
// 	Logger := NewDefaultLogger(LogInfo)
// 	signer := NewSigner(*Credential, Logger)

// 	sign, err := signer.Sign(host, path, method, header, query, body)
// 	trueSign := "APISIGNER-HMAC-SHA256 Credential=access key/20190214/assets/apisigner_request, Signature=ab7f411c1af4d3938f69a24539572418fa4dcdb40e3c0dd4aa329fbca091688e"
// 	if err != nil || trueSign != sign {
// 		println(sign)
// 		t.Error("validate signature failed", err)
// 	}
// 	header.Set(HeaderApiSignerAuthorization, sign)
// }

func TestServerSigner(t *testing.T) {
	host := "new-media.kureader.com"
	uri := "/admin/v1/assets/vip"
	method := "POST"
	var query = make(url.Values)
	query["filters.1.name"] = []string{"id"}
	query["filters.1.values.1"] = []string{"v1"}
	query["filters.1.values.2"] = []string{"v2"}
	body := []byte("this is body")
	signTime := time.Unix(1678089157, 0) // 20230306T075237Z
	authorization := "APISIGNER-Standard-HMAC-SHA256 Credential=access key/20230306/region1/assets/apisigner_request, Signature=95e8a8f4cc4a2949a2bcb2e4041d2948f2b1655247ccce2f820d43b64805c056"

	// Credential := NewCredential("access key", "secret key")
	// Logger := NewDefaultLogger(LogInfo)
	serverSDK := NewSigner(nil).Standard().Server(
		1*time.Minute,
		func(ak string) (sk string) {
			return "secret key"
		},
		func(nonce string) bool {
			return true
		},
	)
	s := serverSDK.(*standardSignerServer)

	severAuthorization, err := s.signForBackend(host, uri, method, query, body, authorization, "aaaaa-bbb-ccc-ddd-eeeeee", signTime)
	if err != nil || authorization != severAuthorization {
		println(severAuthorization)
		t.Error("validate signature failed", err)
	}
}

func TestAuthFlow(t *testing.T) {
	host := "https://new-media.kureader.com"
	path := "admin/v1/assets/vip"
	method := "POST"
	body := []byte("this is body")
	// authorization := "APISIGNER-Standard-HMAC-SHA256 Credential=access key/20230306/region1/assets/apisigner_request, Signature=95e8a8f4cc4a2949a2bcb2e4041d2948f2b1655247ccce2f820d43b64805c056"

	req, err := http.NewRequest(method, host+"/"+path+"?filters.1.name=id&filters.1.values.1=v1&filters.1.values.2=v2", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	Credential := NewCredential("access key", "secret key")
	Logger := NewDefaultLogger(LogInfo)
	standard := NewSigner(Logger).Standard()
	clientSDK := standard.Client("cn-shanghai-1", "asset", *Credential)
	err = clientSDK.SetAuthHeader(req)
	if err != nil {
		t.Fatal(err)
	}
	serverSDK := standard.Server(
		1*time.Minute,
		func(ak string) (sk string) {
			return "secret key"
		},
		func(nonce string) bool {
			return false
		},
	)
	err = serverSDK.Vaild(req)
	if err != nil {
		t.Fatal(err)
	}
}

// TODO 测试 http header
// TODO 分离 ctx， 测试ctx
