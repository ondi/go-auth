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

func (self *Exp_t) Validate(ts time.Time, in Token) (ok bool) {
	payload := in.GetPayload()
	// not before
	temp, ok := payload["nbf"].(float64)
	if ok {
		if ok = ts.Unix()+self.Nbf >= int64(temp); !ok {
			return
		}
	}
	// expire
	temp, ok = payload["exp"].(float64)
	if ok {
		if ok = ts.Unix()+self.Exp < int64(temp); !ok {
			return
		}
	}
	return
}
