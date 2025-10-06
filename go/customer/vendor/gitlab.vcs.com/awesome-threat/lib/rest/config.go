package rest

import (
	"fmt"
	"net/url"
)

type (
	Proxy struct {
		Enable   bool   `json:"enable" yaml:"enable"`
		Scheme   string `json:"scheme" yaml:"scheme"`
		Host     string `json:"host" yaml:"host"`
		Port     int    `json:"port" yaml:"port"`
		Username string `json:"username" yaml:"username"`
		Password string `json:"password" yaml:"password"`
	}
)

func (body *Proxy) String() string {
	host := body.Host
	if body.Port != 0 {
		host = fmt.Sprintf("%s:%d", host, body.Port)
	}
	u := url.URL{
		Scheme: body.Scheme,
		Host:   host,
	}
	if body.Username != "" || body.Password != "" {
		u.User = url.UserPassword(body.Username, body.Password)
	}
	// Success
	return u.String()
}
