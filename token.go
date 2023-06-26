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

type PAYLOAD_TYPE = map[string]interface{}

type PAYLOAD_TYPE_GET interface {
	GetPayload() PAYLOAD_TYPE
}

type TokenBearer_t struct {
	Name       string
	Value      []byte
	Payload    PAYLOAD_TYPE
	Validators []Validator[PAYLOAD_TYPE]
}

func (self *TokenBearer_t) GetName() string {
	return self.Name
}

func (self *TokenBearer_t) GetPayload() PAYLOAD_TYPE {
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

type TokenBasic_t struct {
	Name  string
	Value []byte
}

func (self *TokenBasic_t) GetName() string {
	return self.Name
}

func (self *TokenBasic_t) VerifyAndValidate(in Verifier, ts time.Time) (ok bool) {
	_, ok = in.Verify(self.Value)
	return
}

type GetBearer_t struct {
	validators []Validator[PAYLOAD_TYPE]
}

func NewGetBearer(validators ...Validator[PAYLOAD_TYPE]) *GetBearer_t {
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
	return
}

type GetBasic_t struct {
}

func NewGetBasic() *GetBasic_t {
	return &GetBasic_t{}
}

func (self *GetBasic_t) Tokens(r *http.Request) (out []Token) {
	var ix int
	var token string
	for _, token = range r.Header[AUTHORIZATION] {
		if ix = strings.IndexByte(token, ' '); ix > -1 && token[:ix] == "Basic" {
			out = append(out, &TokenBasic_t{Name: AUTHORIZATION, Value: []byte(token[ix+1:])})
		}
	}
	if c, err := r.Cookie(AUTHORIZATION); err == nil {
		if token, err = url.QueryUnescape(c.Value); err == nil {
			if ix = strings.IndexByte(token, ' '); ix > -1 && token[:ix] == "Basic" {
				out = append(out, &TokenBasic_t{Name: AUTHORIZATION, Value: []byte(token[ix+1:])})
			}
		}
	}
	return
}
