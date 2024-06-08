//
//
//

package auth

import (
	"testing"

	"gotest.tools/assert"
)

func Test001(t *testing.T) {
	parse_bearer, err := NewParseBearer(nil, map[string]string{"/": HEADER})
	assert.NilError(t, err)

	parse_basic, err := NewParseBasic(map[string]string{"/": "base64basic"})
	assert.NilError(t, err)

	bearer := NewAuth(nil, nil, parse_bearer, NewTokenFind(NewTokenBearer(NewExp(-60, 60)), KEY_BEARER))
	basic := NewAuth(nil, nil, parse_basic, NewTokenFind(NewTokenBasic(), KEY_BASIC))

	_, _ = bearer, basic
	// bearer.ServeHTTP(nil, nil)
}
