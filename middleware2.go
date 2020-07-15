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

type Middleware2_t struct {
	verify     Verify_t
	except     *tst.Tree1_t
	next_ok    http.Handler
	next_error http.Handler
}

func (self Middleware2_t) WithNext(next_ok http.Handler, next_error http.Handler) http.Handler {
	return Middleware2_t{verify: self.verify, except: self.except, next_ok: next_ok, next_error: next_error}
}

func New(AuthGlob string, except map[string]string, next_ok http.Handler, next_error http.Handler) (res Middleware2_t, err error) {
	if res.verify, err = NewVerify(AuthGlob); err != nil {
		return
	}
	res.except = &tst.Tree1_t{}
	var re *regexp.Regexp
	for k, v := range except {
		if re, err = regexp.Compile(v); err != nil {
			return
		}
		res.except.Add(k, re)
	}
	res.next_ok = next_ok
	res.next_error = next_error
	return
}

func (self Middleware2_t) Names() []string {
	return self.verify.Names()
}

func (self Middleware2_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if re, ok := self.except.Search(r.URL.Path).(*regexp.Regexp); ok {
		if addr := RemoteAddr(r); re.MatchString(addr) {
			self.next_ok.ServeHTTP(w, r)
		} else {
			self.next_error.ServeHTTP(w, r)
		}
		return
	}
	ts := time.Now().Unix()
	payload, ok, err := self.verify.Check(r.Header["Authorization"], ts, ts)
	if ok && err == nil {
		self.next_ok.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), auth_key_t("AUTH"), payload)))
	} else {
		self.next_error.ServeHTTP(w, r)
	}
	return
}
