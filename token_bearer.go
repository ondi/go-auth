//
//
//

package auth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const AUTHORIZATION = "Authorization"

type BEARER_PAYLOAD = map[string]interface{}

type BEARER_PAYLOAD_GET interface {
	BearerPayload() BEARER_PAYLOAD
}

type TokenBearer_t struct {
	Name       string
	Value      []byte
	Payload    BEARER_PAYLOAD
	Validators []Validator[BEARER_PAYLOAD]
}

func (self *TokenBearer_t) GetName() string {
	return self.Name
}

func (self *TokenBearer_t) BearerPayload() BEARER_PAYLOAD {
	return self.Payload
}

func (self *TokenBearer_t) VerifyAndValidate(in Verifier, ts time.Time) (ok bool) {
	payload, ok := in.Verify(self.Value)
	if !ok {
		return
	}
	if json.Unmarshal(payload, &self.Payload) != nil {
		return false
	}
	for _, v := range self.Validators {
		if !v.Validate(ts, self.Name, self.Payload) {
			return false
		}
	}
	return true
}

type GetBearer_t struct {
	validators []Validator[BEARER_PAYLOAD]
}

func NewGetBearer(validators ...Validator[BEARER_PAYLOAD]) *GetBearer_t {
	return &GetBearer_t{validators: validators}
}

func (self *GetBearer_t) Tokens(r *http.Request) (out []Token) {
	var ix int
	var token string
	for _, token = range r.Header[AUTHORIZATION] {
		if ix = strings.IndexByte(token, ' '); ix > -1 && token[:ix] == "Bearer" {
			out = append(out, &TokenBearer_t{Name: AUTHORIZATION, Value: []byte(token[ix+1:]), Validators: self.validators})
		}
	}
	if c, err := r.Cookie(AUTHORIZATION); err == nil {
		if token, err = url.QueryUnescape(c.Value); err == nil {
			if ix = strings.IndexByte(token, ' '); ix > -1 && token[:ix] == "Bearer" {
				out = append(out, &TokenBearer_t{Name: AUTHORIZATION, Value: []byte(token[ix+1:]), Validators: self.validators})
			}
		}
	}
	for _, v := range r.URL.Query()["bearer"] {
		out = append(out, &TokenBasic_t{Name: AUTHORIZATION, Value: []byte(v)})
	}
	return
}