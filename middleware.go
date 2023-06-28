//
//
//

package auth

import (
	"context"
	"net/http"
	"time"
)

type auth_t string
type Required_t map[string]struct{}

type Verifier interface {
	Verify(path string, in []byte) (payload []byte, ok bool)
	Required(path string, in Required_t) (ok bool)
}

type Validator[T any] interface {
	Validate(ts time.Time, name string, in T) bool
}

type Token interface {
	GetName() string
	VerifyAndValidate(path string, in Verifier, ts time.Time) bool
}

type GetTokens interface {
	Tokens(r *http.Request) []Token
}

// cast to PAYLOAD_TYPE_GET
func GetValue(ctx context.Context, name string) interface{} {
	return ctx.Value(auth_t(name))
}

func SetValue(ctx context.Context, name string, value interface{}) context.Context {
	return context.WithValue(ctx, auth_t(name), value)
}

func WithContext(ctx context.Context, r *http.Request, count int) *http.Request {
	if count > 0 {
		return r.WithContext(ctx)
	}
	return r
}

type Auth_t struct {
	tokens     GetTokens
	verifier   Verifier
	next_ok    http.Handler
	next_error http.Handler
}

func NewAuth(next_ok http.Handler, next_error http.Handler, tokens GetTokens, verifier Verifier) (self *Auth_t) {
	self = &Auth_t{
		tokens:     tokens,
		verifier:   verifier,
		next_ok:    next_ok,
		next_error: next_error,
	}
	return
}

func (self *Auth_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ts := time.Now()
	ctx := r.Context()
	found := Required_t{}
	for _, token := range self.tokens.Tokens(r) {
		if token.VerifyAndValidate(r.URL.Path, self.verifier, ts) {
			ctx = SetValue(ctx, token.GetName(), token)
			found[token.GetName()] = struct{}{}
		}
	}
	if self.verifier.Required(r.URL.Path, found) {
		self.next_ok.ServeHTTP(w, WithContext(ctx, r, len(found)))
	} else {
		self.next_error.ServeHTTP(w, WithContext(ctx, r, len(found)))
	}
}

type WriteStatus_t struct {
	Status int
}

func (self *WriteStatus_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(self.Status)
}

func NewUnauthorized() *WriteStatus_t {
	return &WriteStatus_t{Status: http.StatusUnauthorized}
}

func NewRequired() Required_t {
	return Required_t{AUTHORIZATION: {}}
}
