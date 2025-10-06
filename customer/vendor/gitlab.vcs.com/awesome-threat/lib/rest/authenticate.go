package rest

import (
	"encoding/json"
	"fmt"
)

type (
	Authenticate struct {
		Type       string      `json:"type" yaml:"type"`
		Attributes interface{} `json:"attributes" yaml:"attributes"`
	}

	AuthenticateBasicAuth struct {
		Username string `json:"username" yaml:"username"`
		Password string `json:"password" yaml:"password"`
	}

	AuthenticateToken struct {
		Token string `json:"token" yaml:"token"`
	}
)

func (auth *Authenticate) Get() (interface{}, error) {
	switch auth.Type {
	case TypeAuthenticateBasicAuth:
		return auth.GetBasicAuth()
	case TypeAuthenticateToken:
		return auth.GetToken()
	case TypeAuthenticateNone:
		return nil, nil
	default:
		err := fmt.Errorf("invalid value <authenticate.type>")
		logger.Errorf("%v", err)
		return nil, err
	}
}

func (auth *Authenticate) GetBasicAuth() (*AuthenticateBasicAuth, error) {
	var basic AuthenticateBasicAuth
	if auth.Attributes != nil {
		bts, err := json.Marshal(auth.Attributes)
		if err != nil {
			logger.Errorf("failed to marshal <authenticate.attributes>, reason: %v", err)
			return nil, err
		}
		if err = json.Unmarshal(bts, &basic); err != nil {
			logger.Errorf("failed to unmarshal <authenticate.attributes> to AuthenticateBasicAuth, reason: %v", err)
			return nil, err
		}
	}
	// Success
	return &basic, nil
}

func (auth *Authenticate) GetToken() (*AuthenticateToken, error) {
	var token AuthenticateToken
	if auth.Attributes != nil {
		bts, err := json.Marshal(auth.Attributes)
		if err != nil {
			logger.Errorf("failed to marshal <authenticate.attributes>, reason: %v", err)
			return nil, err
		}
		if err = json.Unmarshal(bts, &token); err != nil {
			logger.Errorf("failed to unmarshal <authenticate.attributes> to AuthenticateToken, reason: %v", err)
			return nil, err
		}
	}
	// Success
	return &token, nil
}
