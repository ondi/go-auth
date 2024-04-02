//
//
//

package auth

import (
	"testing"

	"gotest.tools/assert"
)

func Test001(t *testing.T) {
	parse_bearer, err := NewParseBearer(nil, map[string]int{"/": 1})
	assert.NilError(t, err)

	parse_basic, err := NewParseBasic(map[string]string{"/": "base64basic"})
	assert.NilError(t, err)

	bearer := NewAuth(nil, nil, parse_bearer, NewFindBearer(NewTokenBearer(NewExp(-60, 60))))
	basic := NewAuth(nil, nil, parse_basic, NewFindBasic(NewTokenBasic()))

	_, _ = bearer, basic
	// bearer.ServeHTTP(nil, nil)
}
