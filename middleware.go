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

type auth_t string
type Required_t map[string]struct{}

type Verifier interface {
	Verify(in []byte) (payload []byte, ok bool)
}

type Validator[T any] interface {
	Validate(ts time.Time, name string, in T) bool
}

type Token interface {
	GetName() string
	VerifyAndValidate(in Verifier, ts time.Time) bool
}

type GetTokens interface {
	Tokens(r *http.Request) []Token
}

type GetAddr interface {
	Addr(r *http.Request) string
}

// cast to PAYLOAD_TYPE_GET
func Auth(ctx context.Context, name string) interface{} {
	return ctx.Value(auth_t(name))
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

type TokenAddr_t struct {
	token_only *TokenOnly_t
	addr_only  *AddrOnly_t
}

func NewTokenAddr(next_ok http.Handler, next_error http.Handler, tokens GetTokens, addr GetAddr, except map[string]string, required Required_t, verifier Verifier) (self *TokenAddr_t, err error) {
	self = &TokenAddr_t{}
	if self.addr_only, err = NewAddrOnly(next_ok, next_error, addr, except); err != nil {
		return
	}
	self.token_only = NewTokenOnly(next_ok, self.addr_only, tokens, required, verifier)
	return
}

func (self *TokenAddr_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	self.token_only.ServeHttp(w, r)
}

type TokenOnly_t struct {
	tokens     GetTokens
	verifier   Verifier
	required   Required_t
	next_ok    http.Handler
	next_error http.Handler
}

func NewTokenOnly(next_ok http.Handler, next_error http.Handler, tokens GetTokens, required Required_t, verifier Verifier) (self *TokenOnly_t) {
	self = &TokenOnly_t{
		tokens:     tokens,
		verifier:   verifier,
		required:   required,
		next_ok:    next_ok,
		next_error: next_error,
	}
	return
}

func (self *TokenOnly_t) ServeHttp(w http.ResponseWriter, r *http.Request) {
	var count int
	ts := time.Now()
	ctx := r.Context()
	required := Required_t{}
	for _, token := range self.tokens.Tokens(r) {
		if token.VerifyAndValidate(self.verifier, ts) {
			count++
			ctx = WithValue(ctx, token.GetName(), token)
			if _, ok := self.required[token.GetName()]; ok {
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
	addr       GetAddr
	except     *tst.Tree1_t[*regexp.Regexp]
	next_ok    http.Handler
	next_error http.Handler
}

func NewAddrOnly(next_ok http.Handler, next_error http.Handler, addr GetAddr, except map[string]string) (self *AddrOnly_t, err error) {
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
		if addr := self.addr.Addr(r); re.MatchString(addr) {
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
