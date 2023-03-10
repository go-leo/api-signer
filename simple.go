package apisigner

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	HeaderApiSignerAK = "x-apisigner-ak"
)

type simpleSigner struct {
	headerName string
	s          *Signer
}

func (s simpleSigner) Server(vaildTime time.Duration, cf CredentialFunc, nf NonceRepeatedFunc) ISeverSigner {
	return &simpleSignerServer{
		signValidTime: vaildTime,
		matchSK:       cf,
		s:             s.s,
	}
}

// func (s simpleSigner) Client() *simpleSignerServer {
// 	return &simpleSignerServer{
// 		signValidTime: signValidTime,
// 		s:             s.s,
// 	}
// }

type simpleSignerServer struct {
	signValidTime   time.Duration
	matchSK         CredentialFunc
	isNonceRepeated NonceRepeatedFunc
	s               *Signer
}

func (server *simpleSignerServer) Vaild(req *http.Request) error {
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

// need host, path, method
func (server *simpleSignerServer) Sign(req *http.Request) (string, error) {
	host, path, method, header := req.Host, req.URL.Path, req.Method, req.Header
	err := server.checkParameters(host, path, method, header)
	if err != nil {
		return "", err
	}
	signTime, err := time.Parse(TimeFormat, header.Get(HeaderApiSignerDate))
	if err != nil {
		return "", err
	}
	if IsInvalidTime(signTime, server.signValidTime) {
		return "", errors.New("signature has expired")
	}
	authorization := header.Get(HeaderApiSignerAuthorization)
	if authorization == "" {
		return "", errors.New("header:authorization is empty")
	}
	ak, signatureHex, err := server.makeSignature(signTime, authorization)
	if err != nil {
		return "", err
	}
	severAuthorization := strings.Join([]string{
		HeaderApiSignerAlgoSimple + " Credential=" + ak + "/",
		"Signature=" + signatureHex,
	}, ", ")
	return severAuthorization, nil
}

func (server simpleSignerServer) makeSignature(signTime time.Time, authorization string) (ak, signatureHex string, err error) {
	creIndex, creEndIndex := strings.Index(authorization, "Credential="), strings.Index(authorization, "Signature=")-2
	if creIndex < 0 || creEndIndex < 0 || creIndex >= creEndIndex {
		return "", "", errors.New("authorization miss credential!")
	}
	ak = strings.Replace(authorization[creIndex:creEndIndex], "Credential=", "", 1)

	secret := server.matchSK(ak)
	timeStr := signTime.Format(TimeFormat)
	signature := makeHmacSha256([]byte("APISIGNER"+secret), []byte(timeStr+ak))
	return ak, hex.EncodeToString(signature), nil
}

func (server simpleSignerServer) checkParameters(host string, path string, method string, header http.Header) error {
	var msg string
	if host == "" {
		msg = "host is empty"
	}
	if path == "" {
		msg = "path is empty"
	}
	if method == "" {
		msg = "method is empty"
	}
	if header == nil {
		msg = "header is empty"
	}
	if header.Get(HeaderApiSignerDate) == "" {
		msg = "can not get x-apisigner-date in HEAD"
	}
	if header.Get(HeaderApiSignerAuthorization) == "" {
		msg = "can not get Authorization in HEAD"
	}
	if msg == "" {
		return nil
	}
	return errors.New(msg)
}
