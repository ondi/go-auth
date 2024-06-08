//
//
//

package auth

import (
	"encoding/json"
	"time"
)

type Validator interface {
	Validate(ts time.Time, token *TokenBearer_t) error
}

type TokenBearer_t struct {
	Name       string
	Value      []byte
	Body       map[string]interface{}
	Error      error
	validators []Validator
}

func NewTokenBearer(validators ...Validator) *TokenBearer_t {
	return &TokenBearer_t{
		validators: validators,
	}
}

func (self *TokenBearer_t) Create(name string, value []byte) Token {
	return &TokenBearer_t{
		Name:       name,
		Value:      value,
		validators: self.validators,
	}
}

func (self *TokenBearer_t) GetName() string {
	return self.Name
}

func (self *TokenBearer_t) GetValue() []byte {
	return self.Value
}

func (self *TokenBearer_t) GetError() error {
	return self.Error
}

func (self *TokenBearer_t) Validate(ts time.Time, payload []byte, verify_error error) error {
	if self.Error = verify_error; self.Error != nil {
		return self.Error
	}
	if self.Error = json.Unmarshal(payload, &self.Body); self.Error != nil {
		return self.Error
	}
	for _, v := range self.validators {
		if self.Error = v.Validate(ts, self); self.Error != nil {
			return self.Error
		}
	}
	return nil
}

type Exp_t struct {
	Nbf int64
	Exp int64
}

// nbf = -60
// exp = 60
func NewExp(nbf int64, exp int64) *Exp_t {
	return &Exp_t{Nbf: nbf, Exp: exp}
}

func (self *Exp_t) Validate(ts time.Time, token *TokenBearer_t) error {
	var test float64
	// not before
	temp, ok := token.Body["nbf"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return ERROR_FORMAT_NBF
		}
		if ok = ts.Unix() >= int64(test)+self.Nbf; !ok {
			return ERROR_NBF
		}
	}
	// expire
	temp, ok = token.Body["exp"]
	if ok {
		if test, ok = temp.(float64); !ok {
			return ERROR_FORMAT_EXP
		}
		if ok = ts.Unix() < int64(test)+self.Exp; !ok {
			return ERROR_EXP
		}
	}
	return nil
}
