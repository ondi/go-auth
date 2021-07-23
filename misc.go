//
//
//

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

var E401H = E401H_t{}
var E401F = E401H.ServeHTTP
var TS = Ts_t{60, -60}

type E401H_t struct{}

func (E401H_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "AUTHORIZATION REQUIRED "+GetRemoteAddr(r), http.StatusUnauthorized)
}

type Ts_t struct {
	Nbf int64
	Exp int64
}

func (self Ts_t) Ts() (int64, int64) {
	ts := time.Now().Unix()
	return ts + self.Nbf, ts + self.Exp
}

type NoTs_t struct{}

func (NoTs_t) Ts() (int64, int64) {
	return 1<<63 - 1, -1 << 63
}

type auth_key_t string

func Auth(ctx context.Context) (res map[string]interface{}, ok bool) {
	res, ok = ctx.Value(auth_key_t("AUTH")).(map[string]interface{})
	return
}

var GetTokens = func(r *http.Request) (res []string) {
	res = r.Header["Authorization"]
	if c, err := r.Cookie("Authorization"); err == nil {
		if v, err := url.QueryUnescape(c.Value); err == nil {
			res = append(res, v)
		}
	}
	return
}

var GetRemoteAddr = func(r *http.Request) (addr string) {
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

var Validate = func(payload []byte, nbf int64, exp int64) (res map[string]interface{}, ok bool, err error) {
	var ts float64
	var temp interface{}
	res = map[string]interface{}{}
	if err = json.Unmarshal(payload, &res); err != nil {
		return
	}
	// not before
	if temp, ok = res["nbf"]; ok {
		if ts, ok = temp.(float64); !ok {
			return res, false, fmt.Errorf("nbf format error")
		}
		if int64(ts) > nbf {
			return res, false, fmt.Errorf("nbf=%v", int64(ts)-nbf)
		}
	}
	// expire
	if temp, ok = res["exp"]; ok {
		if ts, ok = temp.(float64); !ok {
			return res, false, fmt.Errorf("exp format error")
		}
		if int64(ts) < exp {
			return res, false, fmt.Errorf("exp=%v", int64(ts)-exp)
		}
	}
	return res, true, nil
}
