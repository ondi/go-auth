//
//
//

package auth

import "time"

func Validators[T any](in ...Validator[T]) []Validator[T] {
	return in
}

type Exp_t struct {
	Nbf int64
	Exp int64
}

func NewExp() *Exp_t {
	return &Exp_t{Nbf: 60, Exp: -60}
}

func (self *Exp_t) Validate(ts time.Time, name string, payload BEARER_PAYLOAD) (ok bool) {
	var test float64
	// not before
	temp, ok := payload["nbf"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return
		}
		if ok = ts.Unix()+self.Nbf >= int64(test); !ok {
			return
		}
	}
	// expire
	temp, ok = payload["exp"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return
		}
		if ok = ts.Unix()+self.Exp < int64(test); !ok {
			return
		}
	}
	return true
}
