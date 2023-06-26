//
//
//

package auth

import (
	"bytes"
	"context"
	"net/http"
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

type BearerBasic_t struct {
	bearer *Bearer_t
	basic  *Basic_t
}

func NewBearerBasic(next_ok http.Handler, next_error http.Handler, get_bearer GetTokens, get_basic GetTokens, except map[string]string, required Required_t, verifier Verifier) (self *BearerBasic_t, err error) {
	self = &BearerBasic_t{}
	if self.basic, err = NewBasic(next_ok, next_error, get_basic, except); err != nil {
		return
	}
	self.bearer = NewBearer(next_ok, self.basic, get_bearer, required, verifier)
	return
}

func (self *BearerBasic_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	self.bearer.ServeHttp(w, r)
}

type Bearer_t struct {
	tokens     GetTokens
	verifier   Verifier
	required   Required_t
	next_ok    http.Handler
	next_error http.Handler
}

func NewBearer(next_ok http.Handler, next_error http.Handler, tokens GetTokens, required Required_t, verifier Verifier) (self *Bearer_t) {
	self = &Bearer_t{
		tokens:     tokens,
		verifier:   verifier,
		required:   required,
		next_ok:    next_ok,
		next_error: next_error,
	}
	return
}

func (self *Bearer_t) ServeHttp(w http.ResponseWriter, r *http.Request) {
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

type BasicVerify_t []byte

func (self BasicVerify_t) Verify(in []byte) (payload []byte, ok bool) {
	return nil, bytes.Equal(self, in) || len(self) == 0
}

type Basic_t struct {
	tokens     GetTokens
	except     *tst.Tree1_t[BasicVerify_t]
	next_ok    http.Handler
	next_error http.Handler
}

func NewBasic(next_ok http.Handler, next_error http.Handler, tokens GetTokens, except map[string]string) (self *Basic_t, err error) {
	self = &Basic_t{
		tokens:     tokens,
		except:     &tst.Tree1_t[BasicVerify_t]{},
		next_ok:    next_ok,
		next_error: next_error,
	}

	for k, v := range except {
		self.except.Add(k, []byte(v))
	}

	return
}

func (self *Basic_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ts := time.Now()
	for _, token := range self.tokens.Tokens(r) {
		if verify, ok := self.except.Search(r.URL.Path); ok {
			if token.VerifyAndValidate(verify, ts) {
				self.next_ok.ServeHTTP(w, r)
				return
			}
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
