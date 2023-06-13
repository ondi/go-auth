//
//
//

package auth

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var (
	EXP           = &Exp_t{Nbf: 60, Exp: -60}
	ERROR         = Serve401_t{}
	REQUIRED      = Required_t{AUTHORIZATION: {}}
	AUTHORIZATION = "Authorization"
)

type auth_t string

type Serve401_t struct{}

func (Serve401_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
}

type TokenValue_t struct {
	Name  string
	Value []byte
}

func Auth(ctx context.Context, name string) (res map[string]interface{}) {
	res, _ = ctx.Value(auth_t(name)).(map[string]interface{})
	return
}

func WithValue(ctx context.Context, name string, value interface{}) context.Context {
	return context.WithValue(ctx, auth_t(name), value)
}

func WithContext(ctx context.Context, r *http.Request, count int) *http.Request {
	if count > 0 {
		return r.WithContext(ctx)
	}
	return r
}

func TOKEN(r *http.Request) (out []TokenValue_t) {
	var ix int
	var token string
	for _, token = range r.Header[AUTHORIZATION] {
		ix = strings.IndexByte(token, ' ')
		out = append(out, TokenValue_t{Name: AUTHORIZATION, Value: []byte(token[ix+1:])})
	}
	if c, err := r.Cookie(AUTHORIZATION); err == nil {
		if token, err = url.QueryUnescape(c.Value); err == nil {
			ix = strings.IndexByte(token, ' ')
			out = append(out, TokenValue_t{Name: AUTHORIZATION, Value: []byte(token[ix+1:])})
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
