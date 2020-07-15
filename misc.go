//
//
//

package auth

import (
	"context"
	"net"
	"net/http"
)

var E401 = E401_t{}

type auth_key_t string

type E401_t struct{}

func (E401_t) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "AUTHORIZATION REQUIRED "+RemoteAddr(r), http.StatusUnauthorized)
}

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
