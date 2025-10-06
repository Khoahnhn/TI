package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-playground/mold/v4/modifiers"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

type (
	CustomValidator struct {
		validator *validator.Validate
	}

	JWTBody struct {
		UserName string `json:"preferred_username"`
	}
)

type Middleware struct {
	userRepo mongo.UserRepository
}

func NewMiddleware(userRepo mongo.UserRepository) *Middleware {
	return &Middleware{userRepo: userRepo}
}

func (cv *CustomValidator) Validate(i interface{}) error {
	modifier := modifiers.New()
	modifier.Struct(context.Background(), i)
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

func phoneValidator(fl validator.FieldLevel) bool {
	phone := fl.Field().String()
	re := regexp.MustCompile(`^[+0-9 .]{8,15}$`)
	return re.MatchString(phone)
}

func businessEmailValidator(fl validator.FieldLevel) bool {
	email := strings.ToLower(fl.Field().String())
	if email == "" {
		return true
	}
	for _, domain := range defs.MailListPersonal {
		if strings.HasSuffix(email, "@"+domain) {
			return false
		}
	}
	return true
}


func codeValidator(fl validator.FieldLevel) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	return re.MatchString(fl.Field().String())
}

func ExtractToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if secret != "" {
			key := c.Request().Header.Get("X-API-KEY")
			if key == secret {
				c.Set(`user_name`, defs.DefaultCreator)
				return next(c)
			}
		}
		cookie, err := c.Cookie("access_token_cookie")
		if err != nil {
			logger.Error("token not found")
			return rest.JSON(c).Code(rest.StatusForbidden).Go()
		}
		claims := strings.Split(cookie.Value, `.`)
		if len(claims) != 3 {
			logger.Error("token not found")
			return rest.JSON(c).Code(rest.StatusForbidden).Go()
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
			return rest.JSON(c).Code(rest.StatusForbidden).Go()
		}
		jwtBody := &JWTBody{}
		if err = json.Unmarshal(data, jwtBody); err != nil {
			logger.Error("token not found")
			return rest.JSON(c).Code(rest.StatusForbidden).Go()
		}
		// Success
		c.Set(`user_name`, jwtBody.UserName)
		return next(c)
	}
}

func GetPPUserInfoFromHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		orgId := c.Request().Header.Get(defs.OrgIdHeader)
		orgName := c.Request().Header.Get(defs.OrgNameHeader)
		userId := c.Request().Header.Get(defs.UserIdHeader)
		UserFullname := c.Request().Header.Get(defs.UserFullnameHeader)
		if orgId == "" || userId == "" {
			return c.JSON(http.StatusBadRequest, model.APIResponse{
				Code:    defs.StatusCode_badRequest,
				Message: "header missing",
			})
		}
		userInfo := model.PPUserInfo{
			UserId:       userId,
			OrgId:        orgId,
			OrgName:      orgName,
			UserFullname: UserFullname,
		}
		c.Set(defs.PP_USER_INFO_CTX, userInfo)

		return next(c)
	}
}

func (m *Middleware) PermissionAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		userInfo, ok := c.Get(defs.PP_USER_INFO_CTX).(model.PPUserInfo)
		if !ok {
			log.Print("[error] user unauthorized")
			return BadRequest(c, "Unauthorized", nil)
		}
		user, err := m.userRepo.Get(context.Background(), userInfo.UserId)
		if err != nil {
			log.Print("[error] user info not found")
			return BadRequest(c, "Failed to get user", nil)
		}
		if user.GroupRole.GroupRole != "admin" {
			log.Print("[error] user not admin")
			return BadRequest(c, "Forbidden", nil)
		}
		c.Set(defs.ContextUserCurrent, user)
		return next(c)
	}
}
