package rest

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type jsonHandler struct {
	ctx  echo.Context
	code int
	msg  string
	body interface{}
	data interface{}
}

func (h *jsonHandler) Message(msg string) JsonInterface {
	// Success
	h.msg = msg
	return h
}

var threshold = http.StatusBadRequest

func JSON(c echo.Context) JsonInterface {
	// Success
	return &jsonHandler{ctx: c}
}

func (h *jsonHandler) Code(code int) JsonInterface {
	// Success
	h.code = code
	return h
}

func (h *jsonHandler) Body(data interface{}) JsonInterface {
	// Success
	h.body = data
	return h
}

func (h *jsonHandler) Data(data interface{}) JsonInterface {
	// Success
	h.data = data
	return h
}

func (h *jsonHandler) Log(data interface{}) JsonInterface {
	if h.code < threshold {
		logger.Infof("code %d: %v", h.code, data)
	} else {
		logger.Errorf("code %d: %v", h.code, data)
	}
	// Success
	return h
}

func (h *jsonHandler) Go() error {
	status := StatusText(h.code)
	if status == "" {
		panic(nil)
	}
	res := &response{
		Success: Success(h.code),
		Message: h.msg,
		Detail:  h.body,
		Data:    h.data,
	}
	if res.Message == "" {
		res.Message = status
	}
	// Success
	return h.ctx.JSON(h.code, res)
}
