package handler

import (
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

type (
	CustomValidator struct {
		validator *validator.Validate
	}
)

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
