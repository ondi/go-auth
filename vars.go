//
//
//

package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var (
	VALIDATOR    = &Validator_t{Nbf: 60, Exp: -60}
	UNAUTHORIZED = &Unauthorized_t{}
	ERROR_EMPTY  = errors.New("NOT INITIALIZED")
)

type auth_t string

type Unauthorized_t struct{}

func (*Unauthorized_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
}

type TokenValue_t struct {
	Name  string
	Value string
}

func Auth(ctx context.Context, name string) (res map[string]interface{}) {
	res, _ = ctx.Value(auth_t(name)).(map[string]interface{})
	return
}

func TOKEN(r *http.Request) (out []TokenValue_t) {
	var ix int
	var token string
	for _, token = range r.Header["Authorization"] {
		if ix = strings.IndexByte(token, ' '); ix > -1 {
			out = append(out, TokenValue_t{Name: "AUTH", Value: token[ix+1:]})
		}
	}
	if c, err := r.Cookie("Authorization"); err == nil {
		if token, err = url.QueryUnescape(c.Value); err == nil {
			if ix = strings.IndexByte(token, ' '); ix > -1 {
				out = append(out, TokenValue_t{Name: "AUTH", Value: token[ix+1:]})
			}
		}
	}
	return
}

func ADDR(r *http.Request) (out string) {
	if out = r.Header.Get("X-Forwarded-For"); len(out) > 0 {
		return
	}
	if out = r.Header.Get("X-Real-IP"); len(out) > 0 {
		return
	}
	if out, _, _ = net.SplitHostPort(r.RemoteAddr); len(out) > 0 {
		return
	}
	return r.RemoteAddr
}
