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
	QueryKey     string
	HeaderKey    string
	HeaderPrefix []string
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

func (self *TokenFind_t) TokenFind(r *http.Request) (keys_found int, out []Token) {
	var ix int
	var token string
	for _, v1 := range self.args {
		for _, token = range r.Header[v1.HeaderKey] {
			keys_found++
			for _, v2 := range v1.HeaderPrefix {
				if ix = HasPrefix(token, v2); ix > -1 {
					out = append(out, self.create.TokenCreate(v1.Name, v1.Type, []byte(token[ix:])))
					break
				}
			}
		}
		if c, err := r.Cookie(v1.HeaderKey); err == nil {
			keys_found++
			if token, err = url.QueryUnescape(c.Value); err == nil {
				for _, v2 := range v1.HeaderPrefix {
					if ix = HasPrefix(token, v2); ix > -1 {
						out = append(out, self.create.TokenCreate(v1.Name, v1.Type, []byte(token[ix:])))
					}
				}
			}
		}
		for _, v2 := range r.URL.Query()[v1.QueryKey] {
			keys_found++
			out = append(out, self.create.TokenCreate(v1.Name, v1.Type, []byte(v2)))
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

func AppendGlob(in []Key_t, pattern string, Hmac bool, Cert bool, DER bool) (out []Key_t, err error) {
	out = in
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
		key.Id = v
		out = append(out, key)
	}
	return
}
