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

var (
	// &auth used for context.Value key
	auth               = 1
	ERROR_NO_VERIFIERS = errors.New("no verifiers")
	ERROR_FORMAT_NBF   = errors.New("nbf format")
	ERROR_FORMAT_EXP   = errors.New("exp format")
	ERROR_NBF          = errors.New("nbf")
	ERROR_EXP          = errors.New("exp")
	KEY_BEARER         = FindArgs_t{Name: "bearer", HeaderKey: "Authorization", HeaderPrefix: "Bearer", QueryKey: "bearer"}
	KEY_BASIC          = FindArgs_t{Name: "basic", HeaderKey: "Authorization", HeaderPrefix: "Basic", QueryKey: "basic"}
)

type Token interface {
	GetName() string
	GetValue() []byte
	GetError() error
	SetError(error)
	Validate(ts time.Time, payload []byte) error
}

type TokenCreator interface {
	TokenCreate(name string, value []byte) Token
}

type TokenFinder interface {
	TokenFind(r *http.Request) []Token
}

type Verifier interface {
	Verify(token []byte) (payload []byte, err error)
	Approve(passed []Token) (ok bool)
}

type Routes interface {
	Verifier(path string) (verifier Verifier, ok bool)
}

type found_t struct {
	Passed []Token
	Failed []Token
}

func Passed(ctx context.Context) (passed []Token) {
	if found, _ := ctx.Value(&auth).(*found_t); found != nil {
		passed = found.Passed
	}
	return
}

func Found(ctx context.Context) (passed []Token, failed []Token) {
	if found, _ := ctx.Value(&auth).(*found_t); found != nil {
		passed, failed = found.Passed, found.Failed
	}
	return
}

func AppendCtx(ctx context.Context, passed []Token, failed []Token) context.Context {
	found, _ := ctx.Value(&auth).(*found_t)
	if found == nil {
		found = &found_t{}
		ctx = context.WithValue(ctx, &auth, found)
	}
	found.Passed = append(found.Passed, passed...)
	found.Failed = append(found.Failed, failed...)
	return ctx
}

type Auth_t struct {
	find        []TokenFinder
	routes      Routes
	next_passed http.Handler
	next_failed http.Handler
}

func NewAuth(next_passed http.Handler, next_failed http.Handler, routes Routes, find ...TokenFinder) (self *Auth_t) {
	self = &Auth_t{
		find:        find,
		routes:      routes,
		next_passed: next_passed,
		next_failed: next_failed,
	}
	return
}

func (self *Auth_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	var payload []byte
	var passed, failed []Token
	ts := time.Now()
	verifier, ok := self.routes.Verifier(r.URL.Path)
	if ok {
		for _, v1 := range self.find {
			for _, v2 := range v1.TokenFind(r) {
				if payload, err = verifier.Verify(v2.GetValue()); err != nil {
					v2.SetError(err)
				}
				if err = v2.Validate(ts, payload); err != nil {
					v2.SetError(err)
				}
				if v2.GetError() != nil {
					failed = append(failed, v2)
				} else {
					passed = append(passed, v2)
				}
			}
		}
		if verifier.Approve(passed) {
			self.next_passed.ServeHTTP(w, r.WithContext(AppendCtx(r.Context(), passed, failed)))
			return
		}
	}
	self.next_failed.ServeHTTP(w, r.WithContext(AppendCtx(r.Context(), passed, failed)))
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
