//
//
//

package auth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

const (
	BASIC  = "Basic"
	BEARER = "Bearer"
	HEADER = "Authorization"
)

var (
	// &auth used for context.Value key
	auth             = 1
	ERROR_VERIFY     = errors.New("parse/verify failed")
	ERROR_FORMAT_NBF = errors.New("nbf format")
	ERROR_FORMAT_EXP = errors.New("exp format")
	ERROR_NBF        = errors.New("nbf")
	ERROR_EXP        = errors.New("exp")
)

type Token interface {
	GetName() string
	GetValue() []byte
	GetError() error
	Validate(ts time.Time, payload []byte, verify_error error) error
}

type CreateToken interface {
	Create(name string, value []byte) Token
}

type FindToken interface {
	CreateToken
	Find(r *http.Request) []Token
}

type Parser interface {
	Verify(path string, value []byte) (payload []byte, err error)
	Approve(path string, passed []Token) (ok bool)
}

type Found_t struct {
	Passed []Token
	Failed []Token
}

func Found(ctx context.Context) (res Found_t) {
	res, _ = ctx.Value(&auth).(Found_t)
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
	found, _ := r.Context().Value(&auth).(Found_t)
	for _, v1 := range self.token {
		for _, v2 := range v1.Find(r) {
			if payload, err := self.parser.Verify(r.URL.Path, v2.GetValue()); v2.Validate(ts, payload, err) == nil {
				found.Passed = append(found.Passed, v2)
			} else {
				found.Failed = append(found.Failed, v2)
			}
		}
	}
	if self.parser.Approve(r.URL.Path, found.Passed) {
		self.next_passed.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), &auth, found)))
	} else {
		self.next_failed.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), &auth, found)))
	}
}

type Status_t struct {
	StatusCode int
}

func (self *Status_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(self.StatusCode)
}

func NewStatus(StatusCode int) *Status_t {
	return &Status_t{StatusCode: StatusCode}
}

func NewStatus401() *Status_t {
	return &Status_t{StatusCode: http.StatusUnauthorized}
}
