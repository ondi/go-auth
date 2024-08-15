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
	auth                      = 1
	ERROR_VERIFY_FAILED       = errors.New("verify failed")
	ERROR_VALIDATE_FORMAT_NBF = errors.New("validate format nbf")
	ERROR_VALIDATE_FORMAT_EXP = errors.New("validate format exp")
	ERROR_VALIDATE_NBF        = errors.New("validate nbf")
	ERROR_VALIDATE_EXP        = errors.New("validate exp")
	KEY_BEARER                = TokenArgs_t{Name: "bearer", Type: "Bearer", HeaderKey: "Authorization", HeaderPrefix: "Bearer", QueryKey: "bearer"}
	KEY_BASIC                 = TokenArgs_t{Name: "basic", Type: "Basic", HeaderKey: "Authorization", HeaderPrefix: "Basic", QueryKey: "basic"}
)

type Token interface {
	GetName() string
	GetType() string
	GetValue() []byte
	GetError() error
	SetError(error)
	Validate(ts time.Time, payload []byte) error
}

type TokenCreator interface {
	TokenCreate(Name string, Type string, Value []byte) Token
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

type Found_t struct {
	Passed []Token
	Failed []Token
}

func Found(ctx context.Context) (found Found_t) {
	if temp, _ := ctx.Value(&auth).(*Found_t); temp != nil {
		found = *temp
	}
	return
}

func AppendCtx(ctx context.Context, found Found_t) context.Context {
	temp, _ := ctx.Value(&auth).(*Found_t)
	if temp == nil {
		temp = &Found_t{}
		ctx = context.WithValue(ctx, &auth, temp)
	}
	temp.Passed = append(temp.Passed, found.Passed...)
	temp.Failed = append(temp.Failed, found.Failed...)
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
	var found Found_t
	var payload []byte
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
					found.Failed = append(found.Failed, v2)
				} else {
					found.Passed = append(found.Passed, v2)
				}
			}
		}
		if verifier.Approve(found.Passed) {
			self.next_passed.ServeHTTP(w, r.WithContext(AppendCtx(r.Context(), found)))
			return
		}
	}
	self.next_failed.ServeHTTP(w, r.WithContext(AppendCtx(r.Context(), found)))
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
