package auth

import (
	"bytes"
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ondi/go-jwt"
	"github.com/ondi/go-log"
	"github.com/ondi/go-tst"
)

type Auth_t struct {
	verify []jwt.Verifier
	except *tst.Tree1_t
	next   http.Handler
}

type Sign_t struct {
	sign jwt.Signer
}

type auth_key_t string

func Auth(ctx context.Context) (res map[string]interface{}, ok bool) {
	res, ok = ctx.Value(auth_key_t("AUTH")).(map[string]interface{})
	return
}

func (self Auth_t) Middleware(next http.Handler) http.Handler {
	return Auth_t{verify: self.verify, next: next}
}

func RemoteAddr(r *http.Request) (addr string) {
	if addr = r.Header.Get("X-Forwarded-For"); len(addr) > 0 {
		return
	}
	if addr = r.Header.Get("X-Real-IP"); len(addr) > 0 {
		return
	}
	if addr, _, _ = net.SplitHostPort(r.RemoteAddr); len(addr) > 0 {
		return
	}
	return r.RemoteAddr
}

func SetupSign(self *Sign_t, AuthKey string) (err error) {
	var buf []byte
	self.sign = &jwt.Sign_t{}
	if buf, err = ioutil.ReadFile(AuthKey); err != nil {
		return
	}
	return self.sign.LoadKeyPem(buf)
}

func (self Sign_t) Sign(bits int, payload map[string]interface{}) (bytes.Buffer, error) {
	return jwt.Sign(self.sign, bits, payload)
}

func SetupAuth(self *Auth_t, AuthCrt string, next http.Handler) (matched []string, err error) {
	if matched, err = filepath.Glob(AuthCrt); err != nil {
		return
	}
	var buf []byte
	for _, certfile := range matched {
		verify := &jwt.Verify_t{}
		if buf, err = ioutil.ReadFile(certfile); err == nil {
			if strings.HasSuffix(certfile, ".crt") {
				err = verify.LoadCertPem(buf)
			} else {
				err = verify.LoadCertDer(buf)
			}
		}
		if err != nil {
			log.Error("AuthCert: %v %v", certfile, err)
			continue
		}
		self.verify = append(self.verify, verify)
	}
	self.except = &tst.Tree1_t{}
	self.next = next
	return
}

// not thread safe, use at init()
func (self Auth_t) Except(path string, match_ip string) (err error) {
	var re *regexp.Regexp
	if re, err = regexp.Compile(match_ip); err != nil {
		return
	}
	self.except.Add(path, re)
	return
}

func (self Auth_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if re, ok := self.except.Search(r.URL.Path).(*regexp.Regexp); ok {
		if addr := RemoteAddr(r); re.MatchString(addr) {
			self.next.ServeHTTP(w, r)
		} else {
			http.Error(w, "ACCESS DENIED: "+addr, http.StatusForbidden)
		}
		return
	}
	var i int
	var ok bool
	ts := time.Now().Unix()
	for _, token := range r.Header["Authorization"] {
		ix := strings.LastIndexByte(token, ' ')
		if ix == -1 {
			continue
		}
		header, payload, signature, err := jwt.Parse([]byte(token[ix+1:]))
		if err != nil {
			continue
		}
		for i = 0; i < len(self.verify); i++ {
			if header.Alg != self.verify[i].Name(header.HashBits) {
				continue
			}
			if ok, err = jwt.Verify(self.verify[i], header.HashBits, signature, []byte(token[ix+1:])); err == nil && ok {
				if err = jwt.Validate(payload, ts+60, ts); err == nil {
					break
				}
			}
		}
		if i == len(self.verify) {
			log.Debug("AUTH: %v, %v", ok, err)
			continue
		}
		self.next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), auth_key_t("AUTH"), payload)))
		return
	}
	http.Error(w, "Authorization required", http.StatusUnauthorized)
	return
}
