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

// &auth used for context.Value key
var auth = 1

var VERIFY_ERROR = errors.New("verification failed")
var VALIDATE_ERROR = errors.New("validation failed")

type Token interface {
	GetName() string
	GetValue() []byte
	Validate(payload []byte, verify_error error, ts time.Time) error
	Error() error
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
			if payload, err := self.parser.Verify(r.URL.Path, v2.GetValue()); v2.Validate(payload, err, ts) == nil {
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

type WriteStatus_t struct {
	Status int
}

func (self *WriteStatus_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(self.Status)
}

func New401() *WriteStatus_t {
	return &WriteStatus_t{Status: http.StatusUnauthorized}
}
