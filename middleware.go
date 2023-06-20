//
//
//

package auth

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/ondi/go-tst"
)

var (
	EXP           = &Exp_t{Nbf: 60, Exp: -60}
	ERROR         = &WriteStatus_t{Status: http.StatusUnauthorized}
	REQUIRED      = Required_t{AUTHORIZATION: {}}
	AUTHORIZATION = "Authorization"
)

type auth_t string

type GetAddr_t func(r *http.Request) string
type GetToken_t[T any] func(r *http.Request) []Token[T]
type Required_t map[string]struct{}
type PAYLOAD_TYPE = map[string]interface{}

type Verifier interface {
	Verify(in []byte) (payload []byte, ok bool)
}

type Validator[T any] interface {
	Validate(ts time.Time, name string, in T) bool
}

type Token[T any] interface {
	GetName() string
	GetPayload() T
	Verify(in Verifier) bool
	Validate(ts time.Time, in []Validator[T]) bool
}

func Auth[T any](ctx context.Context, name string) (res T) {
	res, _ = ctx.Value(auth_t(name)).(T)
	return
}

func WithValue(ctx context.Context, name string, value interface{}) context.Context {
	return context.WithValue(ctx, auth_t(name), value)
}

func WithContext(ctx context.Context, r *http.Request, count int) *http.Request {
	if count > 0 {
		return r.WithContext(ctx)
	}
	return r
}

type TokenAddr_t[T any] struct {
	token_only *TokenOnly_t[T]
	addr_only  *AddrOnly_t
}

func NewTokenAddr[T any](next_ok http.Handler, next_error http.Handler, token GetToken_t[T], addr GetAddr_t, except map[string]string, required Required_t, verifier Verifier, validators ...Validator[T]) (self *TokenAddr_t[T], err error) {
	self = &TokenAddr_t[T]{}
	if self.addr_only, err = NewAddrOnly(next_ok, next_error, addr, except); err != nil {
		return
	}
	self.token_only = NewTokenOnly(next_ok, self.addr_only, token, required, verifier, validators...)
	return
}

func (self *TokenAddr_t[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	self.token_only.ServeHttp(w, r)
}

type TokenOnly_t[T any] struct {
	token      GetToken_t[T]
	verifier   Verifier
	validators []Validator[T]
	required   Required_t
	next_ok    http.Handler
	next_error http.Handler
}

func NewTokenOnly[T any](next_ok http.Handler, next_error http.Handler, token GetToken_t[T], required Required_t, verifier Verifier, validators ...Validator[T]) (self *TokenOnly_t[T]) {
	self = &TokenOnly_t[T]{
		token:      token,
		verifier:   verifier,
		validators: validators,
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
		if token.Verify(self.verifier) {
			if token.Validate(ts, self.validators) {
				count++
				ctx = WithValue(ctx, token.GetName(), token.GetPayload())
				if _, ok := self.required[token.GetName()]; ok {
					required[token.GetName()] = struct{}{}
				}
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
	addr       GetAddr_t
	except     *tst.Tree1_t[*regexp.Regexp]
	next_ok    http.Handler
	next_error http.Handler
}

func NewAddrOnly(next_ok http.Handler, next_error http.Handler, addr GetAddr_t, except map[string]string) (self *AddrOnly_t, err error) {
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

type WriteStatus_t struct {
	Status int
}

func (self *WriteStatus_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(self.Status)
}
