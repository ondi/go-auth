//
//
//

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

var (
	VALIDATOR   = &Validator_t{Nbf: 60, Exp: -60}
	ERROR_MATCH = errors.New("NO MATCHING ELEMENTS")
)

type auth_t string

var ctx_auth auth_t = "AUTH"

func Auth(ctx context.Context) (res map[string]interface{}) {
	res, _ = ctx.Value(ctx_auth).(map[string]interface{})
	return
}

func ERROR(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		http.Error(w, "AUTHORIZATION REQUIRED: "+err.Error(), http.StatusUnauthorized)
	} else {
		http.Error(w, "AUTHORIZATION REQUIRED", http.StatusUnauthorized)
	}
}

type Validator_t struct {
	Nbf        int64
	Exp        int64
	ExtraCheck func(r *http.Request, ts time.Time, in map[string]interface{}) error
}

func (self *Validator_t) Validate(r *http.Request, ts time.Time, payload []byte) (out *http.Request, err error) {
	var test float64
	var res map[string]interface{}

	if err = json.Unmarshal(payload, &res); err != nil {
		return
	}

	// not before
	temp, ok := res["nbf"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return r, fmt.Errorf("nbf format error")
		}
		if int64(test) > ts.Unix()+self.Nbf {
			return r, fmt.Errorf("nbf=%v", int64(test))
		}
	}
	// expire
	temp, ok = res["exp"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return r, fmt.Errorf("exp format error")
		}
		if int64(test) < ts.Unix()+self.Exp {
			return r, fmt.Errorf("exp=%v", int64(test))
		}
	}

	if self.ExtraCheck != nil {
		if err = self.ExtraCheck(r, ts, res); err != nil {
			return
		}
	}

	out = r.WithContext(context.WithValue(r.Context(), ctx_auth, res))
	return
}

func (self *Validator_t) GetToken(r *http.Request) (res []string) {
	res = r.Header["Authorization"]
	if c, err := r.Cookie("Authorization"); err == nil {
		if v, err := url.QueryUnescape(c.Value); err == nil {
			res = append(res, v)
		}
	}
	return
}

func (self *Validator_t) GetAddr(r *http.Request) (addr string) {
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
