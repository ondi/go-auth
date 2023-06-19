//
//
//

package auth

import (
	"net/http"
	"regexp"
	"time"

	"github.com/ondi/go-tst"
)

type Addr_t func(r *http.Request) string
type Token_t[T any] func(r *http.Request) []Token[T]
type Required_t map[string]struct{}
type PAYLOAD_TYPE = map[string]interface{}

type Token[T any] interface {
	GetName() string
	GetValue() []byte
	GetPayload() T
	SetPayload(payload []byte) error
}

type Verifier interface {
	Verify(in []byte) (payload []byte, ok bool)
}

type Validator[T any] interface {
	Validate(ts time.Time, in Token[T]) bool
}

type Validators[T any] []Validator[T]

func (self Validators[T]) Validate(ts time.Time, in Token[T]) bool {
	for _, v := range self {
		if !v.Validate(ts, in) {
			return false
		}
	}
	return true
}

type TokenAddr_t[T any] struct {
	token_only *TokenOnly_t[T]
	addr_only  *AddrOnly_t
}

func NewTokenAddr[T any](next_ok http.Handler, next_error http.Handler, token Token_t[T], addr Addr_t, except map[string]string, required Required_t, verify Verifier, validate ...Validator[T]) (self *TokenAddr_t[T], err error) {
	self = &TokenAddr_t[T]{}
	if self.addr_only, err = NewAddrOnly(next_ok, next_error, addr, except); err != nil {
		return
	}
	self.token_only = NewTokenOnly(next_ok, self.addr_only, token, required, verify, validate...)
	return
}

func (self *TokenAddr_t[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	self.token_only.ServeHttp(w, r)
}

type TokenOnly_t[T any] struct {
	token      Token_t[T]
	verify     Verifier
	validate   Validators[T]
	required   Required_t
	next_ok    http.Handler
	next_error http.Handler
}

func NewTokenOnly[T any](next_ok http.Handler, next_error http.Handler, token Token_t[T], required Required_t, verify Verifier, validate ...Validator[T]) (self *TokenOnly_t[T]) {
	self = &TokenOnly_t[T]{
		token:      token,
		verify:     verify,
		validate:   validate,
		required:   required,
		next_ok:    next_ok,
		next_error: next_error,
	}
	return
}

func (self *TokenOnly_t[T]) ServeHttp(w http.ResponseWriter, r *http.Request) {
	var count int
	ts := time.Now()
	ctx := r.Context()
	required := Required_t{}
	for _, token := range self.token(r) {
		if payload, ok := self.verify.Verify(token.GetValue()); ok {
			if token.SetPayload(payload) != nil {
				continue
			}
			if !self.validate.Validate(ts, token) {
				continue
			}
			count++
			ctx = WithValue(ctx, token.GetName(), token.GetPayload())
			if _, ok = self.required[token.GetName()]; ok {
				required[token.GetName()] = struct{}{}
			}
		}
	}
	if len(self.required) == len(required) {
		self.next_ok.ServeHTTP(w, WithContext(ctx, r, count))
	} else {
		self.next_error.ServeHTTP(w, WithContext(ctx, r, count))
	}
}

type AddrOnly_t struct {
	addr       Addr_t
	except     *tst.Tree1_t[*regexp.Regexp]
	next_ok    http.Handler
	next_error http.Handler
}

func NewAddrOnly(next_ok http.Handler, next_error http.Handler, addr Addr_t, except map[string]string) (self *AddrOnly_t, err error) {
	self = &AddrOnly_t{
		addr:       addr,
		except:     &tst.Tree1_t[*regexp.Regexp]{},
		next_ok:    next_ok,
		next_error: next_error,
	}

	var re *regexp.Regexp
	for k, v := range except {
		if re, err = regexp.Compile(v); err != nil {
			return
		}
		self.except.Add(k, re)
	}

	return
}

func (self *AddrOnly_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if re, ok := self.except.Search(r.URL.Path); ok {
		if addr := self.addr(r); re.MatchString(addr) {
			self.next_ok.ServeHTTP(w, r)
			return
		}
	}
	self.next_error.ServeHTTP(w, r)
}
