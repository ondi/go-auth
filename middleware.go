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

// &auth_key used for context.Value key
var auth_key = 1

type Token interface {
	GetName() string
	GetValue() []byte
	GetBody() any
	Parse(payload []byte) error
	Validate(ts time.Time) bool
}

type NewToken interface {
	Create(name string, value []byte) Token
	Find(r *http.Request, out *[]Token)
}

type Parser interface {
	Parse(path string, value []byte) (payload []byte, ok bool)
	Approve(path string, found []Token) (ok bool)
}

func CtxGet(ctx context.Context) (res []Token) {
	res, _ = ctx.Value(&auth_key).([]Token)
	return
}

func ctx_set(ctx context.Context, value []Token) context.Context {
	return context.WithValue(ctx, &auth_key, value)
}

type Auth_t struct {
	token      []NewToken
	parser     Parser
	next_ok    http.Handler
	next_error http.Handler
}

func NewAuth(next_ok http.Handler, next_error http.Handler, parser Parser, token ...NewToken) (self *Auth_t) {
	self = &Auth_t{
		token:      token,
		parser:     parser,
		next_ok:    next_ok,
		next_error: next_error,
	}
	return
}

func (self *Auth_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ts := time.Now()
	ctx := r.Context()
	var in, out []Token
	for _, v := range self.token {
		v.Find(r, &in)
	}
	for _, token := range in {
		if payload, ok := self.parser.Parse(r.URL.Path, token.GetValue()); ok {
			if token.Parse(payload) == nil && token.Validate(ts) {
				out = append(out, token)
			}
		}
	}
	if self.parser.Approve(r.URL.Path, out) {
		self.next_ok.ServeHTTP(w, r.WithContext(ctx_set(ctx, out)))
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
