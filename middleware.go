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

	"github.com/ondi/go-tst"
)

const HEADER = "Authorization"

var (
	// &auth used for context.Value key
	auth             = 1
	ERROR_VERIFY     = errors.New("parse/verify failed")
	ERROR_FORMAT_NBF = errors.New("nbf format")
	ERROR_FORMAT_EXP = errors.New("exp format")
	ERROR_NBF        = errors.New("nbf")
	ERROR_EXP        = errors.New("exp")
	KEY_BEARER       = KeyPrefix_t{Key: HEADER, Prefix: "Bearer"}
	KEY_BASIC        = KeyPrefix_t{Key: HEADER, Prefix: "Basic"}
)

type Token interface {
	GetName() string
	GetValue() []byte
	GetError() error
	SetError(error)
	Validate(path string, ts time.Time, payload []byte) error
}

type TokenCreate interface {
	Create(name string, value []byte) Token
}

type TokenFind interface {
	Find(r *http.Request) []Token
}

type Verifier interface {
	Verify(token []byte) (payload []byte, err error)
	Approve(passed []Token) (ok bool)
}

type Parser interface {
	Verifier(path string) (verifier Verifier, ok bool)
}

type Found_t struct {
	Passed []Token
	Failed []Token
}

type KeyPrefix_t struct {
	Key    string
	Prefix string
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
	find        []TokenFind
	parser      Parser
	next_passed http.Handler
	next_failed http.Handler
}

func NewAuth(next_passed http.Handler, next_failed http.Handler, parser Parser, find ...TokenFind) (self *Auth_t) {
	self = &Auth_t{
		find:        find,
		parser:      parser,
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
	verifier, ok := self.parser.Verifier(r.URL.Path)
	if ok {
		for _, v1 := range self.find {
			for _, v2 := range v1.Find(r) {
				if payload, err = verifier.Verify(v2.GetValue()); err != nil {
					v2.SetError(err)
				}
				if err = v2.Validate(r.URL.Path, ts, payload); err != nil {
					v2.SetError(err)
				}
				if v2.GetError() != nil {
					found.Failed = append(found.Failed, v2)
				} else {
					found.Passed = append(found.Passed, v2)
				}
			}
		}
	}
	if verifier.Approve(found.Passed) {
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

type AuthNone_t struct {
	passed http.Handler
	failed http.Handler
	allow  *tst.Tree3_t[struct{}]
}

func NewAuthNone(passed http.Handler, failed http.Handler, allow []string) (self *AuthNone_t) {
	self = &AuthNone_t{
		passed: passed,
		failed: failed,
		allow:  tst.NewTree3[struct{}](),
	}
	for _, v := range allow {
		self.allow.Add(v, struct{}{})
	}
	return
}

func (self *AuthNone_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := self.allow.Search(r.URL.Path); ok {
		self.passed.ServeHTTP(w, r)
	} else {
		self.failed.ServeHTTP(w, r)
	}
}
