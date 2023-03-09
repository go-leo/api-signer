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

	// 	url := "http://localhost:8080/admin/v1/assets/coins"
	// 	method := "POST"

	// 	payload := strings.NewReader(`{
	//     "operation": 0,
	//     "increase_req": {
	//         "project": "newmedia_wechat",
	//         "uid": 449724877852049850,
	//         "amount": 100,
	//         "way": 0,
	//         "vaild_time_hour": 24
	//     }
	// }`)

	// 	client := &http.Client{}
	// 	req, err := http.NewRequest(method, url, payload)

	// 	if err != nil {
	// 		fmt.Println(err)
	// 		return
	// 	}
	// 	req.Header.Add("Authorization", "APISIGNER-Standard-HMAC-SHA256 Credential=access key/20230309/cn-shanghai-1/asset/apisigner_request, Signature=c045475cff12fa08b1f51de9e2ac24007ffa339cd299ca154e73513295433de1")
	// 	req.Header.Add("x-ca-date", "20230309T121235Z")
	// 	req.Header.Add("x-ca-nonce", "b5185603-0177-485b-bba6-8b604d66276a")
	// 	req.Header.Add("User-Agent", "apifox/1.0.0 (https://www.apifox.cn)")
	// 	req.Header.Add("Content-Type", "application/json")

	host := "http://127.0.0.1:8080"
	path := "/admin/v1/assets/coins"
	method := "POST"
	payload := strings.NewReader(`{
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

	req, err := http.NewRequest(method, host+path, payload)
	if err != nil {
		panic(err)
	}
	Credential := apisigner.NewCredential("access key", "newmedia-sk")
	Logger := apisigner.NewDefaultLogger(apisigner.LogInfo)
	standard := apisigner.NewSigner(Logger).Standard()
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
