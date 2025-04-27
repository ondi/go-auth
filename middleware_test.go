//
//
//

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/assert"
)

var router = http.DefaultServeMux

func Test001(t *testing.T) {
	verify_bearer, err := NewVerifyBearer(nil, "")
	assert.NilError(t, err)

	verify_basic, err := NewVerifyBasic(nil, "")
	assert.NilError(t, err)

	verifiy_noauth, err := NewVerifyNoAuth()
	assert.NilError(t, err)

	noauth := NewAuth(
		router,
		NewStatus401(),
	)
	noauth.AddVerifier("/noath", verifiy_noauth)

	basic := NewAuth(
		router,
		noauth,
		NewTokenFind(
			NewTokenBasic(),
			KEY_BASIC,
		),
	)
	basic.AddVerifier("/basic", verify_basic)

	bearer := NewAuth(
		router,
		basic,
		NewTokenFind(
			NewTokenBearer(
				NewExp(-60, 60),
			),
			KEY_BEARER,
		),
	)
	bearer.AddVerifier("/bearer", verify_bearer)

	r1 := httptest.NewRequest("GET", "http://localhost", nil)
	w1 := httptest.NewRecorder()
	bearer.ServeHTTP(w1, r1)
}
