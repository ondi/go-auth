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

// &auth_{passed,failed} used for context.Value key
var (
	auth_passed = 1
	auth_failed = 1
)

type Token interface {
	GetName() string
	GetValue() []byte
	Decode(payload []byte) error
	Validate(ts time.Time) bool
}

type CreateToken interface {
	Create(name string, value []byte) Token
}

type FindToken interface {
	CreateToken
	Find(r *http.Request) []Token
}

type Parser interface {
	Verify(path string, value []byte) (payload []byte, ok bool)
	Approve(path string, passed []Token) (ok bool)
}

func Passed(ctx context.Context) (res []Token) {
	res, _ = ctx.Value(&auth_passed).([]Token)
	return
}

func Failed(ctx context.Context) (res []Token) {
	res, _ = ctx.Value(&auth_failed).([]Token)
	return
}

type Auth_t struct {
	token       []FindToken
	parser      Parser
	next_passed http.Handler
	next_failed http.Handler
}

func NewAuth(next_passed http.Handler, next_failed http.Handler, parser Parser, token ...FindToken) (self *Auth_t) {
	self = &Auth_t{
		token:       token,
		parser:      parser,
		next_passed: next_passed,
		next_failed: next_failed,
	}
	return
}

func (self *Auth_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ts := time.Now()
	var passed, failed []Token
	for _, v1 := range self.token {
		for _, v2 := range v1.Find(r) {
			if payload, ok := self.parser.Verify(r.URL.Path, v2.GetValue()); ok && v2.Decode(payload) == nil && v2.Validate(ts) {
				passed = append(passed, v2)
			} else {
				failed = append(failed, v2)
			}
		}
	}
	if self.parser.Approve(r.URL.Path, passed) {
		self.next_passed.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), &auth_passed, passed)))
	} else {
		self.next_failed.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), &auth_failed, failed)))
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
