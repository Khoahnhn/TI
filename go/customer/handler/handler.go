package handler

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

var (
	logger pencil.Logger
	secret string
)

func init() {
	logger, _ = pencil.New(defs.HandlerMain, pencil.DebugLevel, true, os.Stdout)
}

type ErrorCode int

const (
	CodeSuccess                  ErrorCode = 0
	CodeBadRequest               ErrorCode = 3
	CodeInternalError            ErrorCode = 13
	CodeNotFound                 ErrorCode = 5
	CodeForbidden                ErrorCode = 6 // TODO: change this
	CodeDeleteLimitExceeded      ErrorCode = 1000
	CodeDeleteConditionNotMatch  ErrorCode = 1001
	CodeRejectLimitExceeded      ErrorCode = 1002
	CodeRejectConditionNotMatch  ErrorCode = 1003
	CodeDeliverLimitExceeded     ErrorCode = 1004
	CodeDeliverConditionNotMatch ErrorCode = 1005
	CodeExportLimitExceeded      ErrorCode = 1006
)

type APIResponse struct {
	Code    ErrorCode   `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Errors  []APIError  `json:"errors,omitempty"`
}

type APIError struct {
	Field   string `json:"field,omitempty"`
	Message string `json:"message,omitempty"`
}

func Success(c echo.Context, message string, data interface{}) error {
	return c.JSON(http.StatusOK, APIResponse{
		Code:    CodeSuccess,
		Message: defs.ToUpperFirstLetter(message),
		Data:    data,
	})
}

func BadRequest(c echo.Context, message string, errors []APIError) error {
	return c.JSON(http.StatusBadRequest, APIResponse{
		Code:    CodeBadRequest,
		Message: defs.ToUpperFirstLetter(message),
		Errors:  errors,
	})
}

func Forbidden(c echo.Context, mesage string) error {
	return c.JSON(http.StatusForbidden, APIResponse{
		Code:    CodeForbidden,
		Message: mesage,
	})
}

func InternalServerError(c echo.Context, message string) error {
	return c.JSON(http.StatusInternalServerError, APIResponse{
		Code:    CodeInternalError,
		Message: defs.ToUpperFirstLetter(message),
	})
}

func NotFound(c echo.Context, message string) error {
	return c.JSON(http.StatusNotFound, APIResponse{
		Code:    CodeNotFound,
		Message: defs.ToUpperFirstLetter(message),
	})
}

func CustomError(c echo.Context, httpCode int, errorCode ErrorCode, message string) error {
	return c.JSON(httpCode, APIResponse{
		Code:    errorCode,
		Message: defs.ToUpperFirstLetter(message),
	})
}

func ValidationError(c echo.Context, err error) error {
	if ve, ok := err.(validator.ValidationErrors); ok {
		errors := make([]APIError, 0, len(ve))
		for _, fe := range ve {
			errors = append(errors, APIError{
				Field:   fe.Field(),
				Message: fmt.Sprintf("failed on '%s' tag", fe.Tag()),
			})
		}
		return c.JSON(http.StatusBadRequest, APIResponse{
			Code:    CodeBadRequest,
			Message: "Validation error",
			Errors:  errors,
		})
	}

	// fallback nếu không phải lỗi validator
	return c.JSON(http.StatusBadRequest, APIResponse{
		Code:    CodeBadRequest,
		Message: "Invalid request",
		Errors: []APIError{
			{Field: "", Message: err.Error()},
		},
	})
}

func APIHandlerStart(conf *model.Config) {
	secret = conf.App.Secret
	// ======================================================================================
	// Initialization Echo webservice
	e := echo.New()
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format:           "[${time_rfc3339}][${remote_ip} -> ${host}][${protocol}-${method}][${status}]: ${uri} | in: ${bytes_in} - out: ${bytes_out} | ${latency_human} | error: ${error}\n",
		CustomTimeFormat: clock.FormatRFC3339,
		Output:           os.Stdout,
	}))
	e.Use(middleware.Recover())
	e.Use(middleware.RemoveTrailingSlash())
	e.Validator = &CustomValidator{validator: validator.New()}
	// ======================================================================================
	// Default Database
	if conf.Adapter.Elastic.Index.TIAsset == "" {
		conf.Adapter.Elastic.Index.TIAsset = defs.IndexAsset
	}
	if conf.Adapter.Elastic.Index.TIAssetHistory == "" {
		conf.Adapter.Elastic.Index.TIAssetHistory = defs.IndexAssetHistory
	}
	if conf.Adapter.Mongo.Database.TIAccount == "" {
		conf.Adapter.Mongo.Database.TIAccount = defs.DatabaseTIAccount
	}
	v := validator.New()
	_ = v.RegisterValidation("phone", phoneValidator)
	_ = v.RegisterValidation("business_email", businessEmailValidator)
	v.RegisterValidation("code", codeValidator)
	e.Validator = &CustomValidator{validator: v}
	// ======================================================================================
	// elasticsearch
	esClient, err := newElastic(conf)
	if err != nil {
		log.Fatal(err)
	}

	// Handler
	kafkaHandler, err := NewKafkaHandler(conf)
	if err != nil {
		log.Fatal(err)
	}
	assetHandler := NewAssetHandler(*conf, kafkaHandler)
	roleHandler := NewRoleHandler(*conf)
	permissionHandler := NewPermissionHandler(*conf)
	featureHandler := NewFeatureHandler(*conf)
	userRepository := mongo.NewUserRepository(conf.Adapter.Mongo.Account, conf.Adapter.Mongo.Database.TIAccount)
	middlewareHandler := NewMiddleware(userRepository)
	assetDomainIPAddressHandler := NewAssetDomainIPAddressHandler(*conf, esClient, kafkaHandler)
	assetProductHandler := NewAssetProductHandler(*conf, kafkaHandler)
	organizationHandler := NewOrganizationHandler(*conf)
	managerUserHandler := NewManagerUserHandler(*conf)
	// ======================================================================================
	// Route
	root := os.Getenv(defs.EnvApiRoot)
	if root == "" {
		root = defs.DefaultApiRoot
	}
	rootApi := e.Group(root)
	/*
		Customer Handler
	*/
	customerOrganization := rootApi.Group("/organization")
	customerOrganization.GET("/:id", managerUserHandler.GetOrganization)
	customerOrganization.POST("/search", managerUserHandler.SearchOrganization)
	customerOrganization.GET("/:id/user/:username", managerUserHandler.GetUser)
	/*
		User
	*/
	user := rootApi.Group("/pp/users", GetPPUserInfoFromHeader)
	user.POST("/search", managerUserHandler.GetUsers)
	user.POST("/statistical", managerUserHandler.GetStatistical)

	user.POST("/create", managerUserHandler.CreateUser, middlewareHandler.PermissionAdmin)
	user.PUT("/:id", managerUserHandler.EditUser, middlewareHandler.PermissionAdmin)
	user.DELETE("/:id", managerUserHandler.DeleteUser, middlewareHandler.PermissionAdmin)
	/*
		Package Handler
	*/
	rolePackage := rootApi.Group("/package")
	rolePackage.POST("", roleHandler.CreateRole, ExtractToken)
	rolePackage.PUT("/:id", roleHandler.EditRole, ExtractToken)
	rolePackage.GET("/:id/detail", roleHandler.DetailRole)
	rolePackage.DELETE("/:id", roleHandler.DeleteRole, ExtractToken)
	rolePackage.POST("/search", roleHandler.Search)
	rolePackage.POST("/statistic", roleHandler.Statistic)
	/*
		Permission Handler
	*/
	permission := rootApi.Group("/permission")
	permission.POST("/list", permissionHandler.GetPermissions)
	permission.POST("/update/:id", permissionHandler.UpdatePermission)
	permission.POST("/change-module", permissionHandler.ChangeModule)
	/*
		Feature Handler
	*/
	feature := rootApi.Group("/feature")
	feature.POST("/create", featureHandler.Create, ExtractToken)
	feature.PUT("/edit/:id", featureHandler.Edit, ExtractToken)
	feature.GET("/detail/:id", featureHandler.DetailFeature)
	feature.POST("/list", featureHandler.GetAllFeature)
	/*
		Asset Group
	*/
	asset := rootApi.Group("/asset", middleware.BodyLimit("10M"))
	asset.GET("/config", assetHandler.Config)
	asset.POST("/action", assetHandler.Action, ExtractToken)
	asset.GET("/:id/history", assetHandler.History, ExtractToken)
	/*
		Asset Domain IPAddress Group
	*/
	assetDomainIPAddress := asset.Group("/domain-ipaddress")
	assetDomainIPAddress.POST("/search", assetDomainIPAddressHandler.Search)
	assetDomainIPAddress.GET("/statistic", assetDomainIPAddressHandler.Statistic)
	assetDomainIPAddress.GET("/tags", assetDomainIPAddressHandler.GetTags)
	assetDomainIPAddress.POST("", assetDomainIPAddressHandler.Create, ExtractToken)
	assetDomainIPAddress.POST("/owner", assetDomainIPAddressHandler.Owner)
	assetDomainIPAddress.POST("/validate", assetDomainIPAddressHandler.Validate)
	assetDomainIPAddress.PUT("/:id", assetDomainIPAddressHandler.Edit, ExtractToken)
	assetDomainIPAddress.POST("/exist", assetDomainIPAddressHandler.Exist)
	assetDomainIPAddress.POST("/delete", assetDomainIPAddressHandler.Delete, ExtractToken)
	/*
		Asset Product Group
	*/
	assetProduct := asset.Group("/product", middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(100)))
	assetProduct.POST("/search", assetProductHandler.Search)
	assetProduct.GET("/statistic", assetProductHandler.Statistic)
	assetProduct.POST("", assetProductHandler.Create, ExtractToken)
	assetProduct.PUT("/:id", assetProductHandler.Edit, ExtractToken)
	assetProduct.POST("/delete", assetProductHandler.Delete, ExtractToken)
	assetProduct.POST("/upload", assetProductHandler.Upload, ExtractToken)
	assetProduct.POST("/import", assetProductHandler.Import, ExtractToken)
	assetProduct.POST("/exist", assetProductHandler.Exist, ExtractToken)
	//assetProduct.GET("/synchronize", assetProductHandler.Synchronize)
	assetProduct.GET("/report/:id", assetProductHandler.DownloadReport, ExtractToken)
	assetProduct.POST("/bulk_by_report/:id", assetProductHandler.BulkByImportRequestID, ExtractToken)
	assetProduct.File("/static/template_asset.xlsx", "./static/template_asset.xlsx")
	/*
		Manager User Group
	*/
	mgUser := rootApi.Group("/op/users")
	mgUser.POST("/list", managerUserHandler.List)
	mgUser.POST("/statistic", managerUserHandler.StatisticV3)
	mgUser.PUT("/change-status/:id", managerUserHandler.ChangeStatus, ExtractToken)
	mgUser.POST("/detail/:id", managerUserHandler.Detail)
	mgUser.POST("/create", managerUserHandler.CreatePublicUser, ExtractToken)
	mgUser.DELETE("/delete/:id", managerUserHandler.DeletePublicUser, ExtractToken)
	mgUser.PUT("/update/:id", managerUserHandler.UpdatePublicUser, ExtractToken)
	mgUser.GET("/history/:id", managerUserHandler.ListUserHistory)
	mgUser.GET("/history/detail/:id", managerUserHandler.GetUserHistoryDetail)
	mgUser.GET("/positions", managerUserHandler.GetPositionJobs)
	mgUser.GET("/countries", managerUserHandler.GetCountries)
	mgUser.GET("/alert-config/:id", managerUserHandler.GetAlertConfig, ExtractToken)
	// ======================================================================================
	/*
		Organization Group
	*/
	organization := rootApi.Group("/organization/v2")
	organization.POST("/search", organizationHandler.SearchOrganizations)
	organization.GET("/list", organizationHandler.ListOrganizations)
	organization.POST("/statistics", organizationHandler.Statistics)
	organization.GET("/industry/list", organizationHandler.ListIndustry)
	organization.GET("/:id", organizationHandler.DetailOrganization)
	organization.POST("/create", organizationHandler.CreateOrganizations, ExtractToken)
	organization.POST("/update/:id", organizationHandler.UpdateOrganization, ExtractToken)
	organization.POST("/change-status", organizationHandler.ChangeStatus, ExtractToken)
	organization.POST("/:org_id/histories", organizationHandler.GetHistories)
	organization.GET("/history/:id", organizationHandler.GetHistoryDetail)
	// ======================================================================================
	// Run
	e.Logger.Fatal(e.Start(conf.App.Address))
}
