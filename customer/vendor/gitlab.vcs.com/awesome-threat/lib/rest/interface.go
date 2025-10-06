package rest

import (
	"io"
	"os"

	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
)

type (
	JsonInterface interface {
		Code(code int) JsonInterface
		Message(msg string) JsonInterface
		Body(data interface{}) JsonInterface
		Data(data interface{}) JsonInterface
		Log(data interface{}) JsonInterface
		Go() error
	}

	StreamInterface interface {
		Code(code int) StreamInterface
		ContentType(contentType string) StreamInterface
		Body(data io.Reader) StreamInterface
		Go() error
	}

	AttachmentInterface interface {
		Name(name string) AttachmentInterface
		Path(path string) AttachmentInterface
		Go() error
	}
)

var logger pencil.Logger

func init() {
	logger, _ = pencil.New(Module, pencil.DebugLevel, true, os.Stdout)
}
