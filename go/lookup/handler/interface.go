package handler

import (
	"ws-lookup/adapter/elastic"

	"github.com/labstack/echo/v4"
)

type (
	LookupHandlerInterface interface {
		Elastic() elastic.GlobalRepository
		Lookup(c echo.Context) error
		Identify(c echo.Context) error
	}

	DomainHandlerInterface interface {
		Elastic() elastic.GlobalRepository
		Lookup(c echo.Context) error
		LookupMultiple(c echo.Context) error
	}

	IPAddressHandlerInterface interface {
		Elastic() elastic.GlobalRepository
		Lookup(c echo.Context) error
		LookupMultiple(c echo.Context) error
	}

	URLHandlerInterface interface {
		Elastic() elastic.GlobalRepository
		Lookup(c echo.Context) error
	}

	FileHandlerInterface interface {
		Elastic() elastic.GlobalRepository
		Lookup(c echo.Context) error
	}

	CVEHandlerInterface interface {
		Elastic() elastic.GlobalRepository
		LookupMultiple(c echo.Context) error
	}
)
