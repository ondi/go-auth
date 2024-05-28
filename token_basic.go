//
//
//

package auth

import (
	"bytes"
	"net/http"
	"net/url"
	"time"
)

type TokenBasic_t struct {
	Name  string
	Value []byte
	Error error
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
	return self.Error
}

func (self *TokenBasic_t) Validate(ts time.Time, payload []byte, verify_error error) error {
	if self.Error = verify_error; self.Error != nil {
		return self.Error
	}
	if ix := bytes.IndexByte(payload, ':'); ix > -1 {
		self.Value = payload[:ix]
	} else {
		self.Value = payload
	}
	return nil
}

type FindBasic_t struct {
	*TokenBasic_t
	keys []KeyPrefix_t
}

func NewFindBasic(basic *TokenBasic_t, extra_keys ...KeyPrefix_t) *FindBasic_t {
	return &FindBasic_t{
		TokenBasic_t: basic,
		keys:         append([]KeyPrefix_t{{Key: HEADER, Prefix: "Basic"}}, extra_keys...),
	}
}

func (self *FindBasic_t) Find(r *http.Request) (out []Token) {
	var ix int
	var token string
	for _, v := range self.keys {
		for _, token = range r.Header[v.Key] {
			if ix = HasPrefix(token, v.Prefix); ix > -1 {
				out = append(out, self.Create(v.Key, []byte(token[ix:])))
			}
		}
		if c, err := r.Cookie(v.Key); err == nil {
			if token, err = url.QueryUnescape(c.Value); err == nil {
				if ix = HasPrefix(token, v.Prefix); ix > -1 {
					out = append(out, self.Create(v.Key, []byte(token[ix:])))
				}
			}
		}
	}
	for _, v := range r.URL.Query()["basic"] {
		out = append(out, self.Create("basic", []byte(v)))
	}
	return
}
