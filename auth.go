package auth

import (
	"bytes"
	"context"
	"fmt"
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
	sign   jwt.Signer
	verify []jwt.Verifier
	except *tst.Tree1_t
	next   http.Handler
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

func Setup(self *Auth_t, AuthCrt string, AuthKey string, next http.Handler) (err error) {
	var buf []byte
	self.sign = &jwt.Sign_t{}
	if buf, err = ioutil.ReadFile(AuthKey); err == nil {
		err = self.sign.LoadKeyPem(buf)
	}
	if err != nil {
		log.Debug("AuthKey: %v", err)
	}

	var matched []string
	if matched, err = filepath.Glob(AuthCrt); err != nil {
		return
	}

	log.Debug("AUTH CERTIFICATES: %v", matched)

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

func (self Auth_t) Sign(bits int, payload map[string]interface{}) (bytes.Buffer, error) {
	return jwt.Sign(self.sign, bits, payload)
}

func (self Auth_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	temp := self.except.Search(r.URL.Path)
	if re, ok := temp.(*regexp.Regexp); ok {
		if addr := RemoteAddr(r); re.MatchString(addr) {
			self.next.ServeHTTP(w, r)
		} else {
			http.Error(w, "ACCESS DENIED: "+addr, http.StatusForbidden)
		}
		return
	}
	token := r.Header.Get("Authorization")
	ix := strings.LastIndexByte(token, ' ')
	if ix == -1 {
		http.Error(w, "invalid header", http.StatusUnauthorized)
		return
	}
	header, payload, signature, err := jwt.Parse([]byte(token[ix+1:]))
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	var i int
	var ok bool
	ts := time.Now().Unix()
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
		http.Error(w, fmt.Sprintf("verification failed: %v, %v", ok, err), http.StatusUnauthorized)
		return
	}
	self.next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), auth_key_t("AUTH"), payload)))
}
