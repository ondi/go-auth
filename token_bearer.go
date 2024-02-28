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
	Validate(ts time.Time, token *TokenBearer_t) bool
}

type TokenBearer_t struct {
	Name       string
	Value      []byte
	Body       map[string]interface{}
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

func (self *TokenBearer_t) Decode(payload []byte) error {
	return json.Unmarshal(payload, &self.Body)
}

func (self *TokenBearer_t) Validate(ts time.Time) (ok bool) {
	for _, v := range self.validators {
		if v.Validate(ts, self) == false {
			return false
		}
	}
	return true
}

type FindBearer_t struct {
	*TokenBearer_t
}

func NewFindBearer(bearer *TokenBearer_t) *FindBearer_t {
	return &FindBearer_t{TokenBearer_t: bearer}
}

func (self *FindBearer_t) Find(r *http.Request) (out []Token) {
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

// nbf = -60
// exp = 60
func NewExp(nbf int64, exp int64) *Exp_t {
	return &Exp_t{Nbf: nbf, Exp: exp}
}

func (self *Exp_t) Validate(ts time.Time, token *TokenBearer_t) (ok bool) {
	var test float64
	// not before
	temp, ok := token.Body["nbf"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return
		}
		if ok = ts.Unix() >= int64(test)+self.Nbf; !ok {
			return
		}
	}
	// expire
	temp, ok = token.Body["exp"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return
		}
		if ok = ts.Unix() < int64(test)+self.Exp; !ok {
			return
		}
	}
	return true
}
