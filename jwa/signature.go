package jwa

type SignatureAlgorithm string

func (s SignatureAlgorithm) String() string {
	return string(s)
}

const (
	// HMAC using SHA-256
	HS256 SignatureAlgorithm = "HS256"
	// HMAC using SHA-384
	HS384 SignatureAlgorithm = "HS384"
	// HMAC using SHA-512
	HS512 SignatureAlgorithm = "HS512"

	// RSASSA-PKCS-v1.5 using SHA-256
	RS256 SignatureAlgorithm = "RS256"
	// RSASSA-PKCS-v1.5 using SHA-384
	RS384 SignatureAlgorithm = "RS384"
	// RSASSA-PKCS-v1.5 using SHA-512
	RS512 SignatureAlgorithm = "RS512"
	// RSASSA-PSS using SHA256 and MGF1-SHA256
	PS256 SignatureAlgorithm = "PS256"
	// RSASSA-PSS using SHA384 and MGF1-SHA384
	P384 SignatureAlgorithm = "PS384"
	// RSASSA-PSS using SHA512 and MGF1-SHA512
	P512 SignatureAlgorithm = "PS512"

	// ECDSA using P-256 and SHA-256
	ES256 SignatureAlgorithm = "ES256"
	// ECDSA using secp256k1 and SHA-256
	ES256K SignatureAlgorithm = "ES256K"
	// ECDSA using P-384 and SHA-384
	ES384 SignatureAlgorithm = "ES384"
	// ECDSA using P-521 and SHA-512
	ES512 SignatureAlgorithm = "ES512"

	// EdDSA signature algorithms
	EdDSA SignatureAlgorithm = "EdDSA"
)

var allSignatureAlgorithms = map[string]SignatureAlgorithm{
	string(HS256):  HS256,
	string(HS384):  HS384,
	string(HS512):  HS512,
	string(RS256):  RS256,
	string(RS384):  RS384,
	string(RS512):  RS512,
	string(PS256):  PS256,
	string(P384):   P384,
	string(P512):   P512,
	string(ES256):  ES256,
	string(ES256K): ES256K,
	string(ES384):  ES384,
	string(ES512):  ES512,
	string(EdDSA):  EdDSA,
}

func (s SignatureAlgorithm) Valid() bool {
	_, ok := allSignatureAlgorithms[s.String()]
	return ok
}
