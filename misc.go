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
	VALIDATOR   = (&Validator_t{Nbf: 60, Exp: -60}).Validate
	ERROR_MATCH = errors.New("NO MATCHING ELEMENTS")
)

type auth_t string

var ctx_auth auth_t = "AUTH"

func Auth(ctx context.Context) (res map[string]interface{}) {
	res, _ = ctx.Value(ctx_auth).(map[string]interface{})
	return
}

type Validator_t struct {
	Nbf int64
	Exp int64
}

func (self *Validator_t) Validate(r *http.Request, payload []byte) (res map[string]interface{}, err error) {
	now := time.Now().Unix()

	var ts float64
	res = map[string]interface{}{}
	if err = json.Unmarshal(payload, &res); err != nil {
		return
	}
	// not before
	temp, ok := res["nbf"]
	if ok {
		if ts, ok = temp.(float64); !ok {
			return res, fmt.Errorf("nbf format error")
		}
		if int64(ts) > now+self.Nbf {
			return res, fmt.Errorf("nbf=%v", int64(ts))
		}
	}
	// expire
	temp, ok = res["exp"]
	if ok {
		if ts, ok = temp.(float64); !ok {
			return res, fmt.Errorf("exp format error")
		}
		if int64(ts) < now+self.Exp {
			return res, fmt.Errorf("exp=%v", int64(ts))
		}
	}
	return
}

func TOKEN(r *http.Request) (res []string) {
	res = r.Header["Authorization"]
	if c, err := r.Cookie("Authorization"); err == nil {
		if v, err := url.QueryUnescape(c.Value); err == nil {
			res = append(res, v)
		}
	}
	return
}

func ADDR(r *http.Request) (addr string) {
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

func ERROR(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		http.Error(w, "AUTHORIZATION REQUIRED: "+err.Error(), http.StatusUnauthorized)
	} else {
		http.Error(w, "AUTHORIZATION REQUIRED", http.StatusUnauthorized)
	}
}
