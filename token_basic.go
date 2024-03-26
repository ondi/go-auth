//
//
//

package auth

import (
	"net/http"
	"net/url"
	"time"
)

type TokenBasic_t struct {
	Name  string
	Value []byte
	Err   error
}

func NewTokenBasic() *TokenBasic_t {
	return &TokenBasic_t{}
}

func (self *TokenBasic_t) Create(name string, value []byte) Token {
	return &TokenBasic_t{
		Name:  name,
		Value: value,
	}
}

func (self *TokenBasic_t) GetName() string {
	return self.Name
}

func (self *TokenBasic_t) GetValue() []byte {
	return self.Value
}

func (self *TokenBasic_t) GetError() error {
	return self.Err
}

func (self *TokenBasic_t) Validate(ts time.Time, payload []byte, verify_error error) error {
	self.Err = verify_error
	return self.Err
}

type FindBasic_t struct {
	*TokenBasic_t
	keys []KeyPrefix_t
}

func NewFindBasic(basic *TokenBasic_t, extra_keys ...KeyPrefix_t) *FindBasic_t {
	return &FindBasic_t{
		TokenBasic_t: basic,
		keys:         append([]KeyPrefix_t{{Key: HEADER, Prefix: BASIC}}, extra_keys...),
	}
}

func (self *FindBasic_t) Find(r *http.Request) (out []Token) {
	var token string
	for _, v := range self.keys {
		for _, token = range r.Header[v.Key] {
			if HasPrefix(token, v.Prefix) {
				out = append(out, self.Create(v.Key, []byte(token[NextSymbol(v.Prefix):])))
			}
		}
		if c, err := r.Cookie(v.Key); err == nil {
			if token, err = url.QueryUnescape(c.Value); err == nil {
				if HasPrefix(token, v.Prefix) {
					out = append(out, self.Create(v.Key, []byte(token[NextSymbol(v.Prefix):])))
				}
			}
		}
	}
	for _, v := range r.URL.Query()["basic"] {
		out = append(out, self.Create("basic", []byte(v)))
	}
	return
}
