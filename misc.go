//
//
//

package auth

import (
	"context"
	"net"
	"net/http"
	"time"
)

var E401H = E401H_t{}
var E401F = E401H.ServeHTTP
var TS = Ts_t{60, -60}

type E401H_t struct{}

func (E401H_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "AUTHORIZATION REQUIRED "+RemoteAddr(r), http.StatusUnauthorized)
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
