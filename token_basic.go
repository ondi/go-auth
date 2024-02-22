//
//
//

package auth

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

type TokenBasic_t struct {
	Name  string
	Value []byte
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

func (self *TokenBasic_t) Decode(payload []byte) error {
	return nil
}

func (self *TokenBasic_t) Validate(ts time.Time) (ok bool) {
	return true
}

type FindBasic_t struct {
	*TokenBasic_t
}

func NewFindBasic(basic *TokenBasic_t) *FindBasic_t {
	return &FindBasic_t{TokenBasic_t: basic}
}

func (self *FindBasic_t) Find(r *http.Request) (out []Token) {
	var ix int
	var token string
	for _, token = range r.Header[HEADER] {
		if ix = strings.IndexByte(token, ' '); ix > -1 && strings.EqualFold(token[:ix], BASIC) {
			out = append(out, self.Create(BASIC, []byte(token[ix+1:])))
		}
	}
	if c, err := r.Cookie(HEADER); err == nil {
		if token, err = url.QueryUnescape(c.Value); err == nil {
			if ix = strings.IndexByte(token, ' '); ix > -1 && strings.EqualFold(token[:ix], BASIC) {
				out = append(out, self.Create(BASIC, []byte(token[ix+1:])))
			}
		}
	}
	for _, v := range r.URL.Query()["basic"] {
		out = append(out, self.Create(BASIC, []byte(v)))
	}
	return
}
