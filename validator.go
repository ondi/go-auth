//
//
//

package auth

import (
	"context"
	"encoding/json"
	"time"
)

type Validator_t struct {
	Nbf        int64
	Exp        int64
	ExtraCheck func(ctx context.Context, ts time.Time, token_name string, in map[string]interface{}) (out context.Context, ok bool)
}

func (self *Validator_t) Validate(ctx context.Context, ts time.Time, token_name string, payload []byte) (out context.Context, ok bool) {
	var test float64
	var values map[string]interface{}

	err := json.Unmarshal(payload, &values)
	if err != nil {
		return
	}

	// not before
	temp, ok := values["nbf"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return
		}
		if ok = ts.Unix()+self.Nbf >= int64(test); !ok {
			return
		}
	}
	// expire
	temp, ok = values["exp"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return
		}
		if ok = ts.Unix()+self.Exp < int64(test); !ok {
			return
		}
	}

	if self.ExtraCheck != nil {
		if ctx, ok = self.ExtraCheck(ctx, ts, token_name, values); !ok {
			return
		}
	}

	out = context.WithValue(ctx, auth_t(token_name), values)
	return
}
