//
//
//

package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const HEADER = "Authorization"

var (
	// &auth used for context.Value key
	auth               = 1
	ERROR_NO_VERIFIERS = errors.New("no verifiers")
	ERROR_FORMAT_NBF   = errors.New("nbf format")
	ERROR_FORMAT_EXP   = errors.New("exp format")
	ERROR_NBF          = errors.New("nbf")
	ERROR_EXP          = errors.New("exp")
	KEY_BEARER         = FindArgs_t{HeaderKey: HEADER, HeaderPrefix: "Bearer", QueryKey: "bearer"}
	KEY_BASIC          = FindArgs_t{HeaderKey: HEADER, HeaderPrefix: "Basic", QueryKey: "basic"}
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

type Verifiers interface {
	Verifier(path string) (verifier Verifier, ok bool)
}

type Found_t struct {
	Passed []Token
	Failed []Token
}

type FindArgs_t struct {
	HeaderKey    string
	HeaderPrefix string
	QueryKey     string
}

func HasPrefix(in string, prefix string) (res int) {
	res = len(prefix)
	if len(in) < res || strings.EqualFold(in[:res], prefix) == false {
		return -1
	}
	for {
		v, size := utf8.DecodeRuneInString(in[res:])
		if unicode.IsSpace(v) == false {
			break
		}
		res += size
	}
	return
}

func Found(ctx context.Context) (res Found_t) {
	res, _ = ctx.Value(&auth).(Found_t)
	return
}

type Auth_t struct {
	find        []TokenFinder
	verifiers   Verifiers
	next_passed http.Handler
	next_failed http.Handler
}

func NewAuth(next_passed http.Handler, next_failed http.Handler, verifiers Verifiers, find ...TokenFinder) (self *Auth_t) {
	self = &Auth_t{
		find:        find,
		verifiers:   verifiers,
		next_passed: next_passed,
		next_failed: next_failed,
	}
	return
}

func (self *Auth_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	var payload []byte
	ts := time.Now()
	found, _ := r.Context().Value(&auth).(Found_t)
	verifier, ok := self.verifiers.Verifier(r.URL.Path)
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
			self.next_passed.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), &auth, found)))
			return
		}
	}
	self.next_failed.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), &auth, found)))
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
