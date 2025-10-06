package handler

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/labstack/echo/v4/middleware"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

type (
	CustomValidator struct {
		validator *validator.Validate
	}

	JWTBody struct {
		UserName string `json:"preferred_username"`
	}

	Middleware struct {
		conf *model.Config
	}
)

func NewMiddleware(conf *model.Config) *Middleware {
	return &Middleware{
		conf: conf,
	}
}

func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.validator.Struct(i)
}

func Validate(c echo.Context, pointer interface{}) error {
	err := c.Bind(pointer)
	if err != nil {
		return err
	}
	err = c.Validate(pointer)
	if err != nil {
		return err
	}
	// Success
	return nil
}

func ExtractToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		cookie, err := c.Cookie("access_token_cookie")
		if err != nil {
			logger.Error("token not found")
			return rest.JSON(c).Code(rest.StatusUnauthorized).Go()
		}
		claims := strings.Split(cookie.Value, `.`)
		if len(claims) != 3 {
			logger.Error("token not found")
			return rest.JSON(c).Code(rest.StatusUnauthorized).Go()
		}
		switch len(claims[1]) % 4 {
		case 2:
			claims[1] += "=="
			break
		case 3:
			claims[1] += "="
			break
		}
		data, err := base64.StdEncoding.DecodeString(claims[1])
		if err != nil {
			logger.Error("token not found")
			return rest.JSON(c).Code(rest.StatusUnauthorized).Go()
		}
		jwtBody := &JWTBody{}
		if err = json.Unmarshal(data, jwtBody); err != nil {
			logger.Error("token not found")
			return rest.JSON(c).Code(rest.StatusUnauthorized).Go()
		}

		// Success
		c.Set(`user_name`, jwtBody.UserName)
		return next(c)
	}
}

func CustomTimeoutMiddleware(timeout time.Duration) echo.MiddlewareFunc {
	return middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout:      timeout,
		ErrorMessage: "Request time out",
		OnTimeoutRouteErrorHandler: func(err error, c echo.Context) {
			logger.Errorf("error timeout: %s", err)
		},
	})
}

// verifyApiKey is a middleware function that checks the API key provided in the
// Authorization header of the request. It verifies if the API key matches the
// expected key stored in the configuration. If the keys do not match or if the
// expected key is not set, it logs an error and returns an unauthorized response.
// If the keys match, it calls the next handler in the chain.
func (m *Middleware) verifyApiKey(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		auth := c.Request().Header.Get("Authorization")
		apiKey := strings.Replace(auth, "Bearer ", "", -1)
		if apiKey != m.conf.App.APIKey && m.conf.App.APIKey != "" {
			logger.Errorf("[verifyApiKey] api key not match %v", apiKey)
			return rest.JSON(c).Code(rest.StatusUnauthorized).Go()
		}

		return next(c)
	}
}
