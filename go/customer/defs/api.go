package defs

import (
	"strings"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
)

const (
	DefaultApiTimeout   = clock.Second * 30
	UriSearchCPEPopular = "%s/vulnerability/cpe/popular/search"
	UriCreateUserPublic = "%s/public/user/create"
)

type StatusCode int

const StatusCode_badRequest StatusCode = 400

const PP_USER_INFO_CTX = "pp_userinfo"

const ContextUserCurrent = "CURRENT_USER"

const (
	OrgIdHeader        = "X-PP-OrganizationId"
	OrgNameHeader      = "X-PP-OrganizationName"
	UserIdHeader       = "X-PP-UserId"
	UserFullnameHeader = "X-PP-UserFullName"
)

func ToUpperFirstLetter(s string) string {
	if s == "" {
		return s
	}

	return strings.ToUpper(s[:1]) + s[1:]
}
