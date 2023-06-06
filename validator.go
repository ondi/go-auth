//
//
//

package auth

import (
	"time"
)

type Exp_t struct {
	Nbf int64
	Exp int64
}

func (self *Exp_t) Validate(ts time.Time, token_name string, in map[string]interface{}) (ok bool) {
	var test float64
	// not before
	temp, ok := in["nbf"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return
		}
		if ok = ts.Unix()+self.Nbf >= int64(test); !ok {
			return
		}
	}
	// expire
	temp, ok = in["exp"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return
		}
		if ok = ts.Unix()+self.Exp < int64(test); !ok {
			return
		}
	}
	return
}
