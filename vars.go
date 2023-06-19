//
//
//

package auth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var (
	EXP           = &Exp_t{Nbf: 60, Exp: -60}
	ERROR         = &WriteStatus_t{Status: http.StatusUnauthorized}
	REQUIRED      = Required_t{AUTHORIZATION: {}}
	AUTHORIZATION = "Authorization"
)

type auth_t string

type WriteStatus_t struct {
	Status int
}

func (self *WriteStatus_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(self.Status)
}

type TokenValue_t struct {
	Name    string
	Value   []byte
	Payload PAYLOAD_TYPE
}

func (self *TokenValue_t) GetName() string {
	return self.Name
}

func (self *TokenValue_t) GetValue() []byte {
	return self.Value
}

func (self *TokenValue_t) GetPayload() PAYLOAD_TYPE {
	return self.Payload
}

func (self *TokenValue_t) SetPayload(payload []byte) (err error) {
	return json.Unmarshal(payload, &self.Payload)
}

func Auth[T any](ctx context.Context, name string) (res T) {
	res, _ = ctx.Value(auth_t(name)).(T)
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

func TOKEN(r *http.Request) (out []Token[PAYLOAD_TYPE]) {
	var ix int
	var token string
	for _, token = range r.Header[AUTHORIZATION] {
		ix = strings.IndexByte(token, ' ')
		out = append(out, &TokenValue_t{Name: AUTHORIZATION, Value: []byte(token[ix+1:])})
	}
	if c, err := r.Cookie(AUTHORIZATION); err == nil {
		if token, err = url.QueryUnescape(c.Value); err == nil {
			ix = strings.IndexByte(token, ' ')
			out = append(out, &TokenValue_t{Name: AUTHORIZATION, Value: []byte(token[ix+1:])})
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
