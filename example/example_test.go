package example

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	apisigner "github.com/go-leo/api-signer"
)

func TestServer(t *testing.T) {
	host := "http://127.0.0.1:8080"
	path := "/admin/v1/assets/coins"
	method := "POST"
	payload := strings.NewReader(`{"operation":0,"increase_req":{"project":"newmedia_wechat","uid":449724877852049850,"amount":100,"way":0,"vaild_time_hour":24}}`)
	req, err := http.NewRequest(method, host+path, payload)
	if err != nil {
		panic(err)
	}
	req.Header.Add("Content-Type", "application/json")
	Credential := apisigner.NewCredential("access key", "xxxxxxxxxx")
	standard := apisigner.NewSigner(apisigner.NewDefaultLogger(apisigner.LogInfo))
	clientSDK := standard.Client("cn-shanghai-1", "asset", *Credential)
	err = clientSDK.SetAuthHeader(req)
	if err != nil {
		panic(err)
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(body))
}

/*
可以参考如下数据，判断客户端签名是否正确
上面的 TestServer 方法请求签名产生的数据，如下:

--- [Payload] --------------------------------
POST
/admin/v1/assets/coins

faa665f426e861d659ccb5caf2b2ac52677c27bf2ce57a343f2384cc94ce6c73
---[ STRING TO SIGN ]--------------------------------
APISIGNER-HMAC-SHA256
d0ddfe08-a0a1-4e30-b814-f9b16ad75ba1
20230310T055928Z
20230310/cn-shanghai-1/asset/apisigner_request
46f58efa41cd58c5f37e67ad19bdb936ddc47f3f97ef51e66b6b3da39099e15f
---[ Authorization ]--------------------------------
APISIGNER-HMAC-SHA256 Credential=access key/20230310/cn-shanghai-1/asset/apisigner_request, Signature=438e6a6e81ee1a580ad8b80d4d788ff6e4da877714a8f35714a5ad96ef9912f4


最终设置的请求头如下:
APISIGNER-HMAC-SHA256 = APISIGNER-HMAC-SHA256 Credential=access key/20230310/cn-shanghai-1/asset/apisigner_request, Signature=438e6a6e81ee1a580ad8b80d4d788ff6e4da877714a8f35714a5ad96ef9912f4
x-ca-nonce = d0ddfe08-a0a1-4e30-b814-f9b16ad75ba1
x-ca-date = 20230310T055928Z
*/
