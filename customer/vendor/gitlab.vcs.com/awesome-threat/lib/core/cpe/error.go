package cpe

import "fmt"

type cpeErr struct {
	reason string
	attr   []interface{}
}

var (
	errInvalidType         = "\"%#v\" is not valid as %v attribute."
	errInvalidAttributeStr = "invalid attribute string."
	errInvalidWfn          = "invalid wfn string."
)

func (e cpeErr) Error() string {
	return fmt.Sprintf("cpe:"+e.reason, e.attr...)
}
