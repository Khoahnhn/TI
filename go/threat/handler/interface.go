package handler

import "github.com/labstack/echo/v4"

type (
	AlertHandlerInterface interface {
		Export(c echo.Context) error
	}

	TTIHandlerInterface interface {
		Export(c echo.Context) error
		Delivery(c echo.Context) error
	}

	CVEHandlerInterface interface {
		Identify(c echo.Context) error
		Config(c echo.Context) error
		Search(c echo.Context) error
		ValidateCVE(c echo.Context) error
		LifecycleCVE(c echo.Context) error
		Statistic(c echo.Context) error
		Detail(c echo.Context) error
		Create(c echo.Context) error
		Edit(c echo.Context) error
		Exist(c echo.Context) error
		CVEHistory(c echo.Context) error
		Confirm(c echo.Context) error
		RejectCVEs(c echo.Context) error
		ExportListCve(c echo.Context) error
		CheckReject(c echo.Context) error
		ExportCveById(c echo.Context) error
		CreateLifecycle(c echo.Context) error
		EPSSHistory(c echo.Context) error
		CVELifeCycleV2(c echo.Context) error
		CVEsInternalFlag(c echo.Context) error
		SearchInternalFlag(c echo.Context) error
	}

	CPEHandlerInterface interface {
		Config(c echo.Context) error
		Search(c echo.Context) error
		Statistic(c echo.Context) error
		Exist(c echo.Context) error
		Create(c echo.Context) error
		Delete(c echo.Context) error
		StatisticPopular(c echo.Context) error
		SearchPopular(c echo.Context) error
		CreatePopular(c echo.Context) error
		DeletePopular(c echo.Context) error
		SuggestVendor(c echo.Context) error
		SuggestProduct(c echo.Context) error
		SuggestVersion(c echo.Context) error
		SuggestUpdate(c echo.Context) error
		SearchVendor(c echo.Context) error
		SearchProduct(c echo.Context) error
		SearchVersion(c echo.Context) error
		SearchUpdate(c echo.Context) error
	}

	IndicatorInterface interface {
		Config(c echo.Context) error
		Search(c echo.Context) error
		Statistic(c echo.Context) error
		Create(c echo.Context) error
		Edit(c echo.Context) error
		History(c echo.Context) error
		Validate(c echo.Context) error
		Predict(c echo.Context) error
		Tags(c echo.Context) error
	}
)
