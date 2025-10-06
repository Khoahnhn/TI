package cpe

import (
	"regexp"
	"strings"
)

type (
	Attribute interface {
		wfnEncoded() string
		urlEncoded() string
		fmtString() string
		String() string
		IsEmpty() bool
		IsValid() bool
		Comparison(dest Attribute, custom bool) Relation
	}
	PartAttr   rune
	StringAttr struct {
		raw  string
		isNa bool
	}
)

var (
	Application             = PartAttr('a')
	OperationSystem         = PartAttr('o')
	Hardware                = PartAttr('h')
	PartNotSet              = PartAttr(0x00)
	Any                     = StringAttr{}
	Na                      = StringAttr{isNa: true}
	stringAttrIsValidRegExp = regexp.MustCompile("\\A(\\*|\\?+)?[a-zA-Z0-9\\-_!\"#$%&'()+,./:;<=>@\\[\\]^`{}|~\\\\]+(\\*|\\?+)?$")
)

func newPartAttrFromWfnEncoded(str string) PartAttr {
	if len(str) != 3 {
		return PartNotSet
	}
	switch PartAttr(str[1]) {
	case Application:
		return Application
	case OperationSystem:
		return OperationSystem
	case Hardware:
		return Hardware
	}
	return PartNotSet
}

func newPartAttrFromUriEncoded(str string) PartAttr {
	if len(str) != 1 {
		return PartNotSet
	}
	switch PartAttr(str[0]) {
	case Application:
		return Application
	case OperationSystem:
		return OperationSystem
	case Hardware:
		return Hardware
	}
	return PartNotSet
}

func newPartAttrFromFmtEncoded(str string) PartAttr {
	if len(str) != 1 {
		return PartNotSet
	}
	switch PartAttr(str[0]) {
	case Application:
		return Application
	case OperationSystem:
		return OperationSystem
	case Hardware:
		return Hardware
	}
	return PartNotSet
}

func (m PartAttr) String() string {
	if m.IsValid() {
		return string(m)
	} else {
		panic("\"%v\" is not valid as part attribute")
	}
}

func (m PartAttr) wfnEncoded() string {
	// Success
	return "\"" + m.String() + "\""
}

func (m PartAttr) fmtString() string {
	// Success
	return m.String()
}

func (m PartAttr) urlEncoded() string {
	// Success
	return m.String()
}

func (m PartAttr) IsValid() bool {
	switch m {
	case Application, OperationSystem, Hardware:
		return true
	default:
		return false
	}
}

func (m PartAttr) IsEmpty() bool {
	// Success
	return m == PartNotSet
}

func (m PartAttr) Comparison(dest Attribute, _ bool) Relation {
	destPart, ok := dest.(PartAttr)
	if !ok {
		return Undefined
	}
	if !m.IsValid() || !destPart.IsValid() {
		return Undefined
	}
	if m == destPart {
		return Equal
	}
	return Disjoint
}

func NewStringAttr(str string) StringAttr {
	// Success
	return StringAttr{
		raw: str,
	}
}

func newStringAttrFromWfnEncoded(str string) StringAttr {
	if str == "NA" {
		return Na
	} else if str == "ANY" {
		return Any
	}
	// Success
	return StringAttr{
		raw: wfnEncoder.Decode(strings.TrimPrefix(strings.TrimSuffix(str, "\""), "\"")),
	}
}

func newStringAttrFromUriEncoded(str string) StringAttr {
	if str == "-" {
		return Na
	} else if str == "" || str == "*" {
		return Any
	}
	// Success
	return StringAttr{
		raw: urlEncoder.Decode(str),
	}
}

func newStringAttrFromFmtEncoded(str string) StringAttr {
	if str == "-" {
		return Na
	} else if str == "*" {
		return Any
	}
	// Success
	return StringAttr{
		raw: fmtEncoder.Decode(str),
	}
}

func (s StringAttr) String() string {
	if s.isNa {
		return "-"
	} else if len(s.raw) == 0 {
		return "*"
	}
	// Success
	return s.raw
}

func (s StringAttr) wfnEncoded() string {
	if s.isNa {
		return "NA"
	} else if len(s.raw) == 0 {
		return "ANY"
	}
	// Success
	return "\"" + wfnEncoder.Encode(s.raw) + "\""
}

func (s StringAttr) fmtString() string {
	if s.isNa {
		return "-"
	} else if len(s.raw) == 0 {
		return "*"
	}
	// Success
	return fmtEncoder.Encode(s.raw)
}

func (s StringAttr) urlEncoded() string {
	if s.IsEmpty() {
		return "" // *
	} else if s.isNa {
		return "-"
	}
	// Success
	return urlEncoder.Encode(s.raw)
}

func (s StringAttr) IsEmpty() bool {
	// Success
	return s.raw == "" && !s.isNa
}

func (s StringAttr) IsValid() bool {
	if s.isNa && len(s.raw) != 0 {
		return false
	}
	if stringAttrIsValidRegExp.FindString(s.raw) != s.raw {
		return false
	}
	// Success
	return true
}

func (s StringAttr) Comparison(dest Attribute, custom bool) Relation {
	destStr, ok := dest.(StringAttr)
	if !ok {
		return Undefined
	}
	if !s.IsValid() || !destStr.IsValid() {
		return Undefined
	}
	if s == Any {
		if destStr == Any {
			return Equal
		} else if destStr == Na {
			return Superset
		} else if !destStr.withWildCard() {
			return Superset
		}
		if custom && destStr.withWildCard() {
			return Superset
		}
		return Undefined
	}
	if s == Na {
		if destStr == Any {
			return Subset
		} else if destStr == Na {
			return Equal
		} else if !destStr.withWildCard() {
			return Disjoint
		}
		return Undefined
	}
	if s.withWildCard() {
		if destStr == Any {
			return Subset
		} else if destStr == Na {
			return Disjoint
		} else if destStr.withWildCard() {
			if custom && s.raw == destStr.raw {
				return Equal
			}
			return Undefined
		} else if matchWildcard(s.raw, destStr.raw) {
			return Superset
		}
		return Disjoint
	} else {
		if destStr == Any {
			return Subset
		} else if destStr == Na {
			return Disjoint
		} else if destStr.withWildCard() {
			return Undefined
		} else if destStr.raw == s.raw {
			return Equal
		}
		if custom && destStr.withWildCard() {
			if matchWildcard(destStr.raw, s.raw) {
				return Subset
			}
		}
		return Disjoint
	}
}

func (s StringAttr) withWildCard() bool {
	prefix, suffix := s.raw[0], s.raw[len(s.raw)-1]
	return prefix == '*' || prefix == '?' || suffix == '*' || suffix == '?'
}

func matchWildcard(src, trg string) bool {
	sufw, sufq, prew, preq := 0, 0, 0, 0
	if strings.HasPrefix(src, "?") {
		before := len(src)
		src = strings.TrimLeft(src, "?")
		preq = before - len(src)
	}
	if strings.HasPrefix(src, "*") {
		src = strings.TrimPrefix(src, "*")
		prew = 1
	}
	if strings.HasSuffix(src, "?") {
		before := len(src)
		src = strings.TrimRight(src, "?")
		sufq = before - len(src)
	}
	if strings.HasSuffix(src, "*") {
		src = strings.TrimSuffix(src, "*")
		sufw = 1
	}
	i := strings.Index(trg, src)
	if prew != 0 {
		if i != len(trg)-len(src)-sufq && sufw == 0 {
			return false
		}
	}
	if sufw != 0 {
		if i != preq && prew == 0 {
			return false
		}
	}
	if preq != 0 {
		if i != preq || (i != len(trg)-len(src)-sufq && sufw == 0) {
			return false
		}
	}
	if sufq != 0 {
		if i != len(trg)-sufq-len(src) || (i != preq && prew == 0) {
			return false
		}
	}
	// Success
	return true
}
