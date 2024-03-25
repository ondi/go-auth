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

type Validator interface {
	Validate(ts time.Time, token *TokenBearer_t) error
}

type TokenBearer_t struct {
	Name       string
	Value      []byte
	Body       map[string]interface{}
	Err        error
	validators []Validator
}

func NewTokenBearer(validators ...Validator) *TokenBearer_t {
	return &TokenBearer_t{
		validators: validators,
	}
}

func (self *TokenBearer_t) Create(name string, value []byte) Token {
	return &TokenBearer_t{
		Name:       name,
		Value:      value,
		validators: self.validators,
	}
}

func (self *TokenBearer_t) GetName() string {
	return self.Name
}

func (self *TokenBearer_t) GetValue() []byte {
	return self.Value
}

func (self *TokenBearer_t) GetError() error {
	return self.Err
}

func (self *TokenBearer_t) Validate(ts time.Time, payload []byte, verify_error error) error {
	if self.Err = verify_error; self.Err != nil {
		return self.Err
	}
	if self.Err = json.Unmarshal(payload, &self.Body); self.Err != nil {
		return self.Err
	}
	for _, v := range self.validators {
		if self.Err = v.Validate(ts, self); self.Err != nil {
			return self.Err
		}
	}
	return nil
}

type FindBearer_t struct {
	*TokenBearer_t
	keys []string
}

func NewFindBearer(bearer *TokenBearer_t, extra_keys ...string) *FindBearer_t {
	return &FindBearer_t{
		TokenBearer_t: bearer,
		keys:          append([]string{HEADER}, extra_keys...),
	}
}

func (self *FindBearer_t) Find(r *http.Request) (out []Token) {
	var ix int
	var token string
	for _, v := range self.keys {
		for _, token = range r.Header[v] {
			if ix = strings.IndexByte(token, ' '); ix > -1 && strings.EqualFold(token[:ix], BEARER) {
				out = append(out, self.Create(v, []byte(token[ix+1:])))
			}
		}
		if c, err := r.Cookie(v); err == nil {
			if token, err = url.QueryUnescape(c.Value); err == nil {
				if ix = strings.IndexByte(token, ' '); ix > -1 && strings.EqualFold(token[:ix], BEARER) {
					out = append(out, self.Create(v, []byte(token[ix+1:])))
				}
			}
		}
	}
	for _, v := range r.URL.Query()["bearer"] {
		out = append(out, self.Create("bearer", []byte(v)))
	}
	return
}

type Exp_t struct {
	Nbf int64
	Exp int64
}

// nbf = -60
// exp = 60
func NewExp(nbf int64, exp int64) *Exp_t {
	return &Exp_t{Nbf: nbf, Exp: exp}
}

func (self *Exp_t) Validate(ts time.Time, token *TokenBearer_t) error {
	var test float64
	// not before
	temp, ok := token.Body["nbf"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return VALIDATE_ERROR
		}
		if ok = ts.Unix() >= int64(test)+self.Nbf; !ok {
			return VALIDATE_ERROR
		}
	}
	// expire
	temp, ok = token.Body["exp"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return VALIDATE_ERROR
		}
		if ok = ts.Unix() < int64(test)+self.Exp; !ok {
			return VALIDATE_ERROR
		}
	}
	return nil
}
