//
//
//

package auth

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const AUTHORIZATION = "Authorization"

type PAYLOAD_TYPE = map[string]interface{}

type Token_t struct {
	Name       string
	Value      []byte
	Payload    PAYLOAD_TYPE
	Validators []Validator[PAYLOAD_TYPE]
}

func (self *Token_t) GetName() string {
	return self.Name
}

func (self *Token_t) GetPayload() PAYLOAD_TYPE {
	return self.Payload
}

func (self *Token_t) VerifyAndValidate(in Verifier, ts time.Time) (ok bool) {
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

type GetTokens_t struct {
	validators []Validator[PAYLOAD_TYPE]
}

func NewGetTokens(validators ...Validator[PAYLOAD_TYPE]) GetTokens {
	return &GetTokens_t{validators: validators}
}

func (self *GetTokens_t) Tokens(r *http.Request) (out []Token) {
	var ix int
	var token string
	for _, token = range r.Header[AUTHORIZATION] {
		ix = strings.IndexByte(token, ' ')
		out = append(out, &Token_t{Name: AUTHORIZATION, Value: []byte(token[ix+1:]), Validators: self.validators})
	}
	if c, err := r.Cookie(AUTHORIZATION); err == nil {
		if token, err = url.QueryUnescape(c.Value); err == nil {
			ix = strings.IndexByte(token, ' ')
			out = append(out, &Token_t{Name: AUTHORIZATION, Value: []byte(token[ix+1:]), Validators: self.validators})
		}
	}
	return
}

type GetAddr_t struct {
}

func NewGetAddr() GetAddr {
	return &GetAddr_t{}
}

func (self *GetAddr_t) Addr(r *http.Request) (out string) {
	if out = r.Header.Get("X-Forwarded-For"); len(out) > 0 {
		return
	}
	if out = r.Header.Get("X-Real-IP"); len(out) > 0 {
		return
	}
	if out, _, _ = net.SplitHostPort(r.RemoteAddr); len(out) > 0 {
		return
	}
	return r.RemoteAddr
}

func NewError() http.Handler {
	return &WriteStatus_t{Status: http.StatusUnauthorized}
}

func NewRequired() Required_t {
	return Required_t{AUTHORIZATION: {}}
}

type Exp_t struct {
	Nbf int64
	Exp int64
}

func NewExp() Validator[PAYLOAD_TYPE] {
	return &Exp_t{Nbf: 60, Exp: -60}
}

func (self *Exp_t) Validate(ts time.Time, name string, payload PAYLOAD_TYPE) (ok bool) {
	var test float64
	// not before
	temp, ok := payload["nbf"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return
		}
		if ok = ts.Unix()+self.Nbf >= int64(test); !ok {
			return
		}
	}
	// expire
	temp, ok = payload["exp"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return
		}
		if ok = ts.Unix()+self.Exp < int64(test); !ok {
			return
		}
	}
	return true
}

func Validators[T any](in ...Validator[T]) []Validator[T] {
	return in
}
