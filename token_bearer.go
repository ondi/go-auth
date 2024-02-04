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

type Validator interface {
	Validate(ts time.Time, name string, in BEARER_PAYLOAD) bool
}

type TokenBearer_t struct {
	Name       string
	Value      []byte
	Body       BEARER_PAYLOAD
	Validators []Validator
}

func NewTokenBearer(validator ...Validator) *TokenBearer_t {
	return &TokenBearer_t{
		Validators: validator,
	}
}

func (self *TokenBearer_t) Create(name string, value []byte) Token {
	return &TokenBearer_t{
		Name:       name,
		Value:      value,
		Validators: self.Validators,
	}
}

func (self *TokenBearer_t) GetName() string {
	return self.Name
}

func (self *TokenBearer_t) GetValue() []byte {
	return self.Value
}

func (self *TokenBearer_t) GetBody() any {
	return self.Body
}

func (self *TokenBearer_t) Parse(payload []byte) error {
	return json.Unmarshal(payload, &self.Body)
}

func (self *TokenBearer_t) Validate(ts time.Time) (ok bool) {
	for _, v := range self.Validators {
		if v.Validate(ts, self.Name, self.Body) == false {
			return false
		}
	}
	return true
}

func (self *TokenBearer_t) Find(r *http.Request) (out []Token) {
	var ix int
	var token string
	for _, token = range r.Header[HEADER] {
		if ix = strings.IndexByte(token, ' '); ix > -1 && strings.EqualFold(token[:ix], BEARER) {
			out = append(out, self.Create(BEARER, []byte(token[ix+1:])))
		}
	}
	if c, err := r.Cookie(HEADER); err == nil {
		if token, err = url.QueryUnescape(c.Value); err == nil {
			if ix = strings.IndexByte(token, ' '); ix > -1 && strings.EqualFold(token[:ix], BEARER) {
				out = append(out, self.Create(BEARER, []byte(token[ix+1:])))
			}
		}
	}
	for _, v := range r.URL.Query()["bearer"] {
		out = append(out, self.Create(BEARER, []byte(v)))
	}
	return
}

type Exp_t struct {
	Nbf int64
	Exp int64
}

func NewExp() *Exp_t {
	return &Exp_t{Nbf: 60, Exp: -60}
}

func (self *Exp_t) Validate(ts time.Time, name string, payload BEARER_PAYLOAD) (ok bool) {
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
