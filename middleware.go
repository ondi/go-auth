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

type Ts interface {
	Ts() (nbf int64, exp int64)
}

type Middleware_t struct {
	verify     Verify_t
	except     *tst.Tree1_t
	next_ok    http.Handler
	next_error http.Handler
	ts         Ts
}

func (self Middleware_t) WithNext(next_ok http.Handler, next_error http.Handler) http.Handler {
	return Middleware_t{
		verify:     self.verify,
		except:     self.except,
		next_ok:    next_ok,
		next_error: next_error,
		ts:         self.ts,
	}
}

func New(AuthGlob string, except map[string]string, next_ok http.Handler, next_error http.Handler, ts Ts) (self Middleware_t, err error) {
	if self.verify, err = NewVerify(AuthGlob); err != nil {
		return
	}
	self.except = &tst.Tree1_t{}
	var re *regexp.Regexp
	for k, v := range except {
		if re, err = regexp.Compile(v); err != nil {
			return
		}
		self.except.Add(k, re)
	}
	self.next_ok = next_ok
	self.next_error = next_error
	self.ts = ts
	return
}

func (self Middleware_t) Names() []string {
	return self.verify.Names()
}

func (self Middleware_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if re, ok := self.except.Search(r.URL.Path).(*regexp.Regexp); ok {
		if addr := RemoteAddr(r); re.MatchString(addr) {
			self.next_ok.ServeHTTP(w, r)
		} else {
			self.next_error.ServeHTTP(w, r)
		}
		return
	}
	nbf, exp := self.ts.Ts()
	payload, ok, err := self.verify.Check(r.Header["Authorization"], nbf, exp)
	if ok && err == nil {
		self.next_ok.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), auth_key_t("AUTH"), payload)))
	} else {
		self.next_error.ServeHTTP(w, r)
	}
	return
}
