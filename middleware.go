//
//
//

package auth

import (
	"context"
	"net/http"
	"time"
)

const (
	BASIC  = "Basic"
	BEARER = "Bearer"
	HEADER = "Authorization"
)

// &auth_key used for context.Value
var auth_key = 1

type Token interface {
	GetName() string
	GetValue() []byte
	Validate(payload []byte, ts time.Time) bool
}

type Parser interface {
	Parse(path string, in []byte) (payload []byte, ok bool)
	Approve(path string, found []Token) (ok bool)
}

type Validator[T any] interface {
	Validate(ts time.Time, name string, in T) bool
}

type GetTokens interface {
	Tokens(r *http.Request) []Token
}

func CtxGet(ctx context.Context) (res []Token) {
	res, _ = ctx.Value(&auth_key).([]Token)
	return
}

func ctx_set(ctx context.Context, value []Token) context.Context {
	return context.WithValue(ctx, &auth_key, value)
}

type Auth_t struct {
	tokens     GetTokens
	parser     Parser
	next_ok    http.Handler
	next_error http.Handler
}

func NewAuth(next_ok http.Handler, next_error http.Handler, tokens GetTokens, parser Parser) (self *Auth_t) {
	self = &Auth_t{
		tokens:     tokens,
		parser:     parser,
		next_ok:    next_ok,
		next_error: next_error,
	}
	return
}

func (self *Auth_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ts := time.Now()
	ctx := r.Context()
	var found []Token
	for _, token := range self.tokens.Tokens(r) {
		if payload, ok := self.parser.Parse(r.URL.Path, token.GetValue()); ok {
			if token.Validate(payload, ts) {
				found = append(found, token)
			}
		}
	}
	if self.parser.Approve(r.URL.Path, found) {
		self.next_ok.ServeHTTP(w, r.WithContext(ctx_set(ctx, found)))
	} else {
		self.next_error.ServeHTTP(w, r.WithContext(ctx))
	}
}

type WriteStatus_t struct {
	Status int
}

func (self *WriteStatus_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(self.Status)
}

func New401() *WriteStatus_t {
	return &WriteStatus_t{Status: http.StatusUnauthorized}
}
