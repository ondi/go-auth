//
//
//

package auth

import (
	"context"
	"net/http"
	"regexp"

	"github.com/ondi/go-tst"
)

type TokenAddr_t struct {
	verify     Verifier_t
	except     *tst.Tree1_t
	validate   Validator
	next_ok    http.Handler
	next_error Error
}

func NewTokenAddr(verify Verifier_t, except map[string]string, next_ok http.Handler, next_error Error, validate Validator) (self *TokenAddr_t, err error) {
	self = &TokenAddr_t{
		verify:     verify,
		except:     &tst.Tree1_t{},
		validate:   validate,
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
	payload, ok, err := self.verify.Verify(TOKENS.GetTokens(r), self.validate)
	if ok {
		self.next_ok.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), auth_key_t("AUTH"), payload)))
		return
	}
	re, ok := self.except.Search(r.URL.Path).(*regexp.Regexp)
	if ok {
		if addr := ADDR.GetAddr(r); re.MatchString(addr) {
			self.next_ok.ServeHTTP(w, r)
			return
		}
	}
	self.next_error.ShowError(w, r, err)
}

func VerifyToken(verify Verifier_t, next_ok http.HandlerFunc, next_error Error, validate Validator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, ok, err := verify.Verify(TOKENS.GetTokens(r), validate)
		if ok {
			next_ok.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), auth_key_t("AUTH"), payload)))
		} else {
			next_error.ShowError(w, r, err)
		}
	}
}

func VerifyAddr(re *regexp.Regexp, next_ok http.HandlerFunc, next_error Error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if addr := ADDR.GetAddr(r); re.MatchString(addr) {
			next_ok.ServeHTTP(w, r)
		} else {
			next_error.ShowError(w, r, nil)
		}
		return
	}
}
