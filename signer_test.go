package apisigner

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

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
	authorization := "APISIGNER-HMAC-SHA256 Credential=access key/20230306/region1/assets/apisigner_request, Signature=76c84a84e35bfde601645157fcdbc77eed506bdb46dcfd976d4a67eb355c6367"

	// Credential := NewCredential("access key", "secret key")
	// Logger := NewDefaultLogger(LogInfo)
	serverSDK := NewSigner(nil).Server(
		1*time.Minute,
		func(ak string) (sk string) {
			return "secret key"
		},
		func(nonce string) bool {
			return true
		},
	)
	s := serverSDK.(*standardSignerServer)

	severAuthorization, err := s.makeServerAuthorization(host, uri, method, query, body, authorization, "aaaaa-bbb-ccc-ddd-eeeeee", signTime)
	if err != nil || authorization != severAuthorization {
		println(severAuthorization)
		t.Error("validate signature failed", err)
	}
}

func TestAuthFlow(t *testing.T) {
	host := "http://127.0.0.1:8080"
	path := "/admin/v1/assets/coins"
	method := "POST"
	body := strings.NewReader(`{
		"operation": 0,
		"increase_req": {
			"project": "newmedia_wechat",
			"uid": 449724877852049850,
			"amount": 100,
			"way": 0,
			"vaild_time_hour": 24
		}
	}`)
	// authorization := "APISIGNER-Standard-HMAC-SHA256 Credential=access key/20230306/region1/assets/apisigner_request, Signature=95e8a8f4cc4a2949a2bcb2e4041d2948f2b1655247ccce2f820d43b64805c056"

	req, err := http.NewRequest(method, host+path, body)
	if err != nil {
		t.Fatal(err)
	}
	Credential := NewCredential("access key", "secret key")
	Logger := NewDefaultLogger(LogInfo)
	standard := NewSigner(Logger)
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
