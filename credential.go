package apisigner

// Credential is used to sign the request,
// AccessKey and SecretKey could be found in JDCloud console
type Credential struct {
	AccessKey string
	SecretKey string
}

// Deprecated
func NewCredentials(accessKey, secretKey string) *Credential {
	return &Credential{accessKey, secretKey}
}

func NewCredential(accessKey, secretKey string) *Credential {
	return &Credential{accessKey, secretKey}
}
