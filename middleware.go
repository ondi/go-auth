//
//
//

package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/ondi/go-tst"
)

type Addr_t func(r *http.Request) string
type Token_t func(r *http.Request) []TokenValue_t

type Verifier interface {
	Verify(token []byte) (payload []byte, ok bool)
}

type Validator interface {
	Validate(ts time.Time, token_name string, in map[string]interface{}) (ok bool)
}

type TokenAddr_t struct {
	addr       Addr_t
	token      Token_t
	verify     Verifier
	validate   []Validator
	except     *tst.Tree1_t[*regexp.Regexp]
	next_ok    http.Handler
	next_error http.Handler
}

func NewTokenAddr(verify Verifier, except map[string]string, next_ok http.Handler, next_error http.Handler, addr Addr_t, token Token_t, validate ...Validator) (self *TokenAddr_t, err error) {
	self = &TokenAddr_t{
		addr:       addr,
		token:      token,
		verify:     verify,
		validate:   validate,
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

func (self *TokenAddr_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var ok bool
	var err error
	var count int
	var payload []byte
	ts := time.Now()
	ctx := r.Context()
NEXT_TOKEN:
	for _, token := range self.token(r) {
		if payload, ok = self.verify.Verify([]byte(token.Value)); ok {
			var values map[string]interface{}
			if err = json.Unmarshal(payload, &values); err != nil {
				continue
			}
			for _, v := range self.validate {
				if !v.Validate(ts, token.Name, values) {
					continue NEXT_TOKEN
				}
			}
			ctx = context.WithValue(ctx, auth_t(token.Name), values)
			count++
		}
	}
	if count > 0 {
		self.next_ok.ServeHTTP(w, r.WithContext(ctx))
		return
	}
	re, ok := self.except.Search(r.URL.Path)
	if ok {
		if addr := self.addr(r); re.MatchString(addr) {
			self.next_ok.ServeHTTP(w, r)
			return
		}
	}
	self.next_error.ServeHTTP(w, r)
}

func VerifyToken(verify Verifier, next_ok http.HandlerFunc, next_error http.HandlerFunc, token Token_t, validate ...Validator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		var err error
		var count int
		var payload []byte
		ts := time.Now()
		ctx := r.Context()
	NEXT_TOKEN:
		for _, token := range token(r) {
			if payload, ok = verify.Verify([]byte(token.Value)); ok {
				var values map[string]interface{}
				if err = json.Unmarshal(payload, &values); err != nil {
					continue
				}
				for _, v := range validate {
					if !v.Validate(ts, token.Name, values) {
						continue NEXT_TOKEN
					}
				}
				ctx = context.WithValue(ctx, auth_t(token.Name), values)
				count++
			}
		}
		if count > 0 {
			next_ok.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		next_error(w, r)
	}
}

func VerifyAddr(re *regexp.Regexp, next_ok http.HandlerFunc, next_error http.HandlerFunc, addr Addr_t, validate Validator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if addr := addr(r); re.MatchString(addr) {
			next_ok.ServeHTTP(w, r)
		} else {
			next_error(w, r)
		}
		return
	}
}
