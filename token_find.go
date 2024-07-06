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
	keys   []FindArgs_t
}

func NewTokenFind(create TokenCreate, keys ...FindArgs_t) *TokenFind_t {
	return &TokenFind_t{
		create: create,
		keys:   keys,
	}
}

func (self *TokenFind_t) Find(r *http.Request) (out []Token) {
	var ix int
	var token string
	for _, v := range self.keys {
		for _, token = range r.Header[v.HeaderKey] {
			if ix = HasPrefix(token, v.HeaderPrefix); ix > -1 {
				out = append(out, self.create.Create(v.HeaderKey, []byte(token[ix:])))
			}
		}
		if c, err := r.Cookie(v.HeaderKey); err == nil {
			if token, err = url.QueryUnescape(c.Value); err == nil {
				if ix = HasPrefix(token, v.HeaderPrefix); ix > -1 {
					out = append(out, self.create.Create(v.HeaderKey, []byte(token[ix:])))
				}
			}
		}
		for _, v2 := range r.URL.Query()[v.QueryKey] {
			out = append(out, self.create.Create(v.QueryKey, []byte(v2)))
		}
	}
	return
}
