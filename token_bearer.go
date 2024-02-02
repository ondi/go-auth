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

func (self *TokenBearer_t) GetValue() []byte {
	return self.Value
}

func (self *TokenBearer_t) BearerPayload() BEARER_PAYLOAD {
	return self.Payload
}

func (self *TokenBearer_t) Validate(payload []byte, ts time.Time) (ok bool) {
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
	for _, token = range r.Header[HEADER] {
		if ix = strings.IndexByte(token, ' '); ix > -1 && strings.EqualFold(token[:ix], BEARER) {
			out = append(out, &TokenBearer_t{Name: BEARER, Value: []byte(token[ix+1:]), Validators: self.validators})
		}
	}
	if c, err := r.Cookie(HEADER); err == nil {
		if token, err = url.QueryUnescape(c.Value); err == nil {
			if ix = strings.IndexByte(token, ' '); ix > -1 && strings.EqualFold(token[:ix], BEARER) {
				out = append(out, &TokenBearer_t{Name: BEARER, Value: []byte(token[ix+1:]), Validators: self.validators})
			}
		}
	}
	for _, v := range r.URL.Query()["bearer"] {
		out = append(out, &TokenBearer_t{Name: BEARER, Value: []byte(v), Validators: self.validators})
	}
	return
}
