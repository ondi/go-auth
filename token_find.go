//
//
//

package auth

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

type TokenArgs_t struct {
	Name         string
	Type         string
	HeaderKey    string
	HeaderPrefix string
	QueryKey     string
}

type TokenFind_t struct {
	create TokenCreator
	args   []TokenArgs_t
}

func NewTokenFind(create TokenCreator, args ...TokenArgs_t) *TokenFind_t {
	return &TokenFind_t{
		create: create,
		args:   args,
	}
}

func (self *TokenFind_t) TokenFind(r *http.Request) (out []Token) {
	var ix int
	var token string
	for _, v := range self.args {
		for _, token = range r.Header[v.HeaderKey] {
			if ix = HasPrefix(token, v.HeaderPrefix); ix > -1 {
				out = append(out, self.create.TokenCreate(v.Name, v.Type, []byte(token[ix:])))
			}
		}
		if c, err := r.Cookie(v.HeaderKey); err == nil {
			if token, err = url.QueryUnescape(c.Value); err == nil {
				if ix = HasPrefix(token, v.HeaderPrefix); ix > -1 {
					out = append(out, self.create.TokenCreate(v.Name, v.Type, []byte(token[ix:])))
				}
			}
		}
		for _, v2 := range r.URL.Query()[v.QueryKey] {
			out = append(out, self.create.TokenCreate(v.Name, v.Type, []byte(v2)))
		}
	}
	return
}

func HasPrefix(in string, prefix string) (res int) {
	res = len(prefix)
	if len(in) < res || strings.EqualFold(in[:res], prefix) == false {
		return -1
	}
	for {
		v, size := utf8.DecodeRuneInString(in[res:])
		if unicode.IsSpace(v) == false {
			break
		}
		res += size
	}
	return
}

func KeysGlob(pattern string, Hmac bool, Cert bool, DER bool) (out []Key_t, err error) {
	matched, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	key := Key_t{
		Hmac: Hmac,
		Cert: Cert,
		DER:  DER,
	}
	for _, v := range matched {
		if key.Value, err = os.ReadFile(v); err != nil {
			return
		}
		out = append(out, key)
	}
	return
}
