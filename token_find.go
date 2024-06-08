//
//
//

package auth

import (
	"net/http"
	"net/url"
)

type TokenFind_t struct {
	create TokenCreate
	keys   []KeyPrefix_t
}

func NewTokenFind(create TokenCreate, keys ...KeyPrefix_t) *TokenFind_t {
	return &TokenFind_t{
		create: create,
		keys:   keys,
	}
}

func (self *TokenFind_t) Find(r *http.Request) (out []Token) {
	var ix int
	var token string
	for _, v := range self.keys {
		for _, token = range r.Header[v.Key] {
			if ix = HasPrefix(token, v.Prefix); ix > -1 {
				out = append(out, self.create.Create(v.Key, []byte(token[ix:])))
			}
		}
		if c, err := r.Cookie(v.Key); err == nil {
			if token, err = url.QueryUnescape(c.Value); err == nil {
				if ix = HasPrefix(token, v.Prefix); ix > -1 {
					out = append(out, self.create.Create(v.Key, []byte(token[ix:])))
				}
			}
		}
		for _, v2 := range r.URL.Query()[v.Prefix] {
			out = append(out, self.create.Create(v.Key, []byte(v2)))
		}
	}
	return
}
