package jwx

import (
	"encoding/json"
	"errors"
	"strings"
)

// JWS is a parsed compact JWS/JWT.
type JWS struct {
	Header  map[string]any
	Payload []byte
	raw     [3]string
}

// String returns the original compact serialization.
func (j *JWS) String() string {
	return j.raw[0] + "." + j.raw[1] + "." + j.raw[2]
}

// SigningInput returns header_b64.payload_b64.
func (j *JWS) SigningInput() string {
	return j.raw[0] + "." + j.raw[1]
}

// Signature returns the base64url signature part.
func (j *JWS) Signature() string {
	return j.raw[2]
}

// ParseCompact splits a compact JWS and JSON-decodes its protected header.
func ParseCompact(token string) (*JWS, error) {
	if strings.Count(token, ".") != 2 {
		return nil, errors.New("malformed token: expected 3 JWS parts")
	}
	parts := strings.SplitN(token, ".", 3)
	hb, err := Decode(parts[0])
	if err != nil {
		return nil, errMalformed("protected header", err)
	}
	var header map[string]any
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, errMalformed("protected header", err)
	}
	payload, err := Decode(parts[1])
	if err != nil {
		return nil, errMalformed("payload", err)
	}
	if _, err := Decode(parts[2]); err != nil {
		return nil, errMalformed("signature", err)
	}
	return &JWS{
		Header:  header,
		Payload: payload,
		raw:     [3]string{parts[0], parts[1], parts[2]},
	}, nil
}

func errMalformed(what string, err error) error {
	return errors.New("malformed " + what + ": " + err.Error())
}

// ClaimString extracts a string claim.
func ClaimString(payload []byte, key string) (string, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		return "", false
	}
	v, ok := m[key]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false
	}
	return s, true
}
