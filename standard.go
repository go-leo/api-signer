package apisigner

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gofrs/uuid"
)

type standardSigner struct {
	headerName string
	s          *Signer
}

func (ss standardSigner) Client(region, service string, c Credential) IClientSigner {
	return &standardSignerClient{
		s:       ss.s,
		c:       c,
		region:  region,
		service: service,
	}
}

func (ss standardSigner) Server(vaildTime time.Duration, cf CredentialFunc, nf NonceRepeatedFunc) ISeverSigner {
	return &standardSignerServer{
		signValidTime:   vaildTime,
		matchSK:         cf,
		isNonceRepeated: nf,
		s:               ss.s,
	}
}

type standardSignerClient struct {
	s       *Signer
	region  string
	service string
	c       Credential
}

func (client *standardSignerClient) SetAuthHeader(req *http.Request) error {
	host, path, method := req.Host, req.URL.Path, req.Method
	err := client.checkParameters(host, path, method)
	if err != nil {
		return err
	}
	query := req.URL.Query()
	body, err := parseHttpBody(req)
	if err != nil {
		return err
	}
	signTime := time.Now()
	nonce, _ := uuid.NewV4()

	// TODO 提到另一个包，ctx.build 时校验参数并生成一个 Authrition 对象（提供 authheader、signature 等方法）
	ctx := &signingCtx{
		Host:        host,
		Path:        path,
		Method:      method,
		Query:       query,
		Body:        body,
		Time:        signTime,
		Nonce:       nonce.String(),
		ServiceName: client.service,
		Region:      client.region,
		CredValues:  client.c,
	}
	authHeader := ctx.build().Header()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	for k, v := range authHeader {
		req.Header[k] = v
	}

	logSigningInfo(ctx, client.s.Logger)
	return nil
}

func (client *standardSignerClient) checkParameters(host string, path string, method string) error {
	if host == "" {
		return errors.New("host is empty")
	}
	if path == "" {
		return errors.New("path is empty")
	}
	if method == "" {
		return errors.New("method is empty")
	}

	return nil
}

type standardSignerServer struct {
	signValidTime   time.Duration
	matchSK         CredentialFunc
	isNonceRepeated NonceRepeatedFunc
	s               *Signer
}

func (server standardSignerServer) Vaild(req *http.Request) error {
	if req == nil {
		return errors.New("http request nil")
	}
	authorization := req.Header.Get(HeaderApiSignerAuthorization)
	serverAuthorization, err := server.Sign(req)
	if err != nil {
		return err
	}
	if authorization != serverAuthorization {
		return errors.New("signature invaild")
	}
	return nil
}

// need host, path, method, header, query
func (server standardSignerServer) Sign(req *http.Request) (string, error) {
	host, path, method := req.Host, req.URL.Path, req.Method
	header, query := req.Header, req.URL.Query()
	body, err := parseHttpBody(req)
	if err != nil {
		return "", err
	}
	// 检查入参数
	err = server.checkParameters(host, path, method, header)
	if err != nil {
		return "", err
	}
	authorization := header.Get(HeaderApiSignerAuthorization)
	signTime, err := time.Parse(TimeFormat, header.Get(HeaderApiSignerDate))
	if err != nil {
		return "", err
	}
	// TODO 不能大于当前时间
	if IsExpired(signTime, server.signValidTime) {
		return "", errors.New("signature has expired")
	}
	nonce := header.Get(HeaderApiSignerNonce)
	if server.isNonceRepeated(nonce) {
		return "", errors.New("nonce has be used")
	}

	return server.signForBackend(host, EscapePath(path, false), method, query, body, authorization, nonce, signTime)
}

func parseHttpBody(req *http.Request) ([]byte, error) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	// r.Body.Close()
	req.Body = ioutil.NopCloser(bytes.NewReader(body))
	return body, nil
}

func (server standardSignerServer) checkParameters(host string, path string, method string, header http.Header) error {
	if host == "" {
		return errors.New("host is empty")
	}
	if path == "" {
		return errors.New("path is empty")
	}
	if method == "" {
		return errors.New("method is empty")
	}
	if header == nil {
		return errors.New("header is empty")
	}
	if header.Get(HeaderApiSignerDate) == "" {
		return errors.New("can not get x-apisigner-date in HEAD")
	}
	if header.Get(HeaderApiSignerNonce) == "" {
		return errors.New("can not get x-apisigner-nonce in HEAD")
	}
	if header.Get(HeaderApiSignerAuthorization) == "" {
		return errors.New("can not get Authorization in HEAD")
	}

	return nil
}

func (v4 standardSignerServer) signForBackend(
	host, path, method string, query url.Values, body []byte,
	authorization, nonce string, signTime time.Time,
) (string, error) {
	creIndex, creEndIndex := strings.Index(authorization, "Credential="), strings.Index(authorization, "Signature=")-2
	if creIndex < 0 || creEndIndex < 0 || creIndex >= creEndIndex {
		return "", errors.New("authorization miss credential!")
	}
	credential := strings.Replace(authorization[creIndex:creEndIndex], "Credential=", "", 1)
	credentialArray := strings.Split(credential, "/")
	if len(credentialArray) < 5 {
		return "", errors.New("credential miss content!")
	}
	ak := credentialArray[0]
	region := credentialArray[2]
	service := credentialArray[3]
	sk := v4.matchSK(ak)

	ctx := &signingCtx{
		Host:        host,
		Path:        path,
		Method:      method,
		Query:       query,
		Body:        body,
		Time:        signTime,
		ServiceName: service,
		Region:      region,
		Nonce:       nonce,
		CredValues:  Credential{AccessKey: ak, SecretKey: sk},
	}
	authValue := ctx.build()

	logSigningInfo(ctx, v4.s.Logger)
	return authValue.authorization, nil
}

const logSignInfoMsg = `DEBUG: Request Signature:
--- [Content String] --------------------------------
%s
---[ STRING TO SIGN ]--------------------------------
%s
---[ Authorization ]--------------------------------
%s
-----------------------------------------------------`

func logSigningInfo(ctx *signingCtx, log Logger) {
	if log == nil || ctx == nil {
		return
	}
	msg := fmt.Sprintf(logSignInfoMsg, ctx.contentString, ctx.stringToSign, ctx.authorization)
	log.Log(LogInfo, msg)
}

type signingCtx struct {
	ServiceName string
	Region      string
	Host        string
	Path        string
	Method      string
	Body        []byte
	Query       url.Values
	Time        time.Time
	Nonce       string
	CredValues  Credential

	rawQuery           string
	formattedTime      string
	formattedShortTime string
	contentString      string
	bodyDigest         string
	credentialString   string
	stringToSign       string
	signature          string
	authorization      string
}

type AuthValue struct {
	signature     string
	nonce         string
	authorization string
	formattedTime string
}

func (av AuthValue) Header() http.Header {
	header := make(http.Header, 3)
	header.Add(HeaderApiSignerAuthorization, av.authorization)
	header.Add(HeaderApiSignerDate, av.formattedTime)
	header.Add(HeaderApiSignerNonce, av.nonce)
	return header
}

func (av AuthValue) Authorization() string {
	return av.authorization
}

func (av AuthValue) Signature() string {
	return av.signature
}

// build. ctx will be complete, and return AuthValue
func (ctx *signingCtx) build() *AuthValue {
	ctx.buildHost()
	ctx.buildPath()
	ctx.buildTime()
	ctx.buildRawQuery()
	ctx.buildCredentialString() // no depends
	ctx.buildBodyDigest()
	ctx.buildContentString() // depends on buildBodyDigest
	ctx.buildToSign()        // depends on buildContentString
	ctx.buildSignature()     // depends on string to sign

	parts := []string{
		HeaderApiSignerAlgoStandard + " Credential=" + ctx.CredValues.AccessKey + "/" + ctx.credentialString,
		"Signature=" + ctx.signature,
	}
	ctx.authorization = strings.Join(parts, ", ")
	return &AuthValue{
		signature:     ctx.signature,
		authorization: ctx.authorization,
		formattedTime: ctx.formattedTime,
		nonce:         ctx.Nonce,
	}
}

func (ctx *signingCtx) buildHost() {
	ctx.Host = strings.Replace(strings.ToLower(ctx.Host), "https://", "", 1)
	ctx.Host = strings.Replace(ctx.Host, "http://", "", 1)
}

func (ctx *signingCtx) buildPath() {
	if strings.Contains(ctx.Path, "?") {
		ctx.Path = ctx.Path[0:strings.Index(ctx.Path, "?")]
	}
	if ctx.Path != "" && ctx.Path[len(ctx.Path)-1:len(ctx.Path)] == "/" {
		ctx.Path = ctx.Path[0 : len(ctx.Path)-1]
	}
	if ctx.Path == "" {
		ctx.Path = "/"
	}
}

func (ctx *signingCtx) buildTime() {
	ctx.formattedTime = ctx.Time.UTC().Format(TimeFormat)
	ctx.formattedShortTime = ctx.Time.UTC().Format(shortTimeFormat)
}

func (ctx *signingCtx) buildRawQuery() {
	if ctx.Query != nil {
		keysSort := make([]string, 0)
		for key := range ctx.Query {
			sort.Strings(ctx.Query[key])
			keysSort = append(keysSort, key)
		}
		sort.Strings(keysSort)
		for i := range keysSort {
			if ctx.rawQuery != "" {
				ctx.rawQuery = strings.Join([]string{ctx.rawQuery, "&", keysSort[i], "=", strings.Join(ctx.Query[keysSort[i]], "")}, "")
			} else {
				ctx.rawQuery = strings.Join([]string{keysSort[i], "=", strings.Join(ctx.Query[keysSort[i]], "")}, "")
			}
		}
	}
}

func (ctx *signingCtx) buildContentString() {
	ctx.contentString = strings.Join([]string{
		ctx.Method,
		ctx.Path,
		ctx.rawQuery,
		ctx.bodyDigest,
	}, "\n")
}

func (ctx *signingCtx) buildCredentialString() {
	ctx.credentialString = strings.Join([]string{
		ctx.formattedShortTime,
		ctx.Region,
		ctx.ServiceName,
		"apisigner_request",
	}, "/")
}

func (ctx *signingCtx) buildToSign() {
	ctx.stringToSign = strings.Join([]string{
		HeaderApiSignerAlgoStandard,
		ctx.Nonce,
		ctx.formattedTime,
		ctx.credentialString,
		hex.EncodeToString(makeSha256([]byte(ctx.contentString))),
	}, "\n")
}

func (ctx *signingCtx) buildSignature() {
	secret := ctx.CredValues.SecretKey
	signature := makeHmacSha256([]byte("APISIGNER"+secret), []byte(ctx.stringToSign))
	ctx.signature = hex.EncodeToString(signature)
}

func (ctx *signingCtx) buildBodyDigest() {
	var hash string
	if ctx.Body == nil {
		hash = emptyStringSHA256
	} else {
		hash = hex.EncodeToString(makeSha256(ctx.Body))
	}
	ctx.bodyDigest = hash
}
