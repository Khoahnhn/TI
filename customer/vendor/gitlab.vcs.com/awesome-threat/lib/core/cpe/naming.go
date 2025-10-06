package cpe

import (
	"strings"
)

type Item struct {
	part      PartAttr
	vendor    StringAttr
	product   StringAttr
	version   StringAttr
	update    StringAttr
	edition   StringAttr
	language  StringAttr
	swEdition StringAttr
	targetSw  StringAttr
	targetHw  StringAttr
	other     StringAttr
}

var goCpeOriginalDelim = "[goCpeOriginalDelim]"

func NewItem() *Item {
	return &Item{
		part:      PartNotSet,
		vendor:    Any,
		product:   Any,
		version:   Any,
		update:    Any,
		edition:   Any,
		language:  Any,
		swEdition: Any,
		targetSw:  Any,
		targetHw:  Any,
		other:     Any,
	}
}

func NewItemFromWfn(wfn string) (*Item, error) {
	if strings.HasPrefix(wfn, "wfn:[") {
		wfn = strings.TrimPrefix(wfn, "wfn:[")
	} else {
		return nil, cpeErr{reason: errInvalidWfn}
	}

	if strings.HasSuffix(wfn, "]") {
		wfn = strings.TrimSuffix(wfn, "]")
	} else {
		return nil, cpeErr{reason: errInvalidWfn}
	}
	item := NewItem()
	for _, attr := range strings.Split(wfn, ",") {
		sepAttr := strings.Split(attr, "=")
		if len(sepAttr) != 2 {
			return nil, cpeErr{reason: errInvalidWfn}
		}
		n, v := sepAttr[0], sepAttr[1]
		switch n {
		case "part":
			item.part = newPartAttrFromWfnEncoded(v)
		case "vendor":
			item.vendor = newStringAttrFromWfnEncoded(v)
		case "product":
			item.product = newStringAttrFromWfnEncoded(v)
		case "version":
			item.version = newStringAttrFromWfnEncoded(v)
		case "update":
			item.update = newStringAttrFromWfnEncoded(v)
		case "edition":
			item.edition = newStringAttrFromWfnEncoded(v)
		case "language":
			item.language = newStringAttrFromWfnEncoded(v)
		case "sw_edition":
			item.swEdition = newStringAttrFromWfnEncoded(v)
		case "target_sw":
			item.targetSw = newStringAttrFromWfnEncoded(v)
		case "target_hw":
			item.targetHw = newStringAttrFromWfnEncoded(v)
		case "other":
			item.other = newStringAttrFromWfnEncoded(v)
		}
	}
	// Success
	return item, nil
}

func NewItemFromUri(uri string) (*Item, error) {
	if strings.HasPrefix(uri, "cpe:/") {
		uri = strings.TrimPrefix(uri, "cpe:/")
	} else {
		return nil, cpeErr{reason: errInvalidWfn}
	}
	item := NewItem()
	for i, attr := range strings.Split(uri, ":") {
		switch i {
		case 0:
			item.part = newPartAttrFromUriEncoded(attr)
		case 1:
			item.vendor = newStringAttrFromUriEncoded(attr)
		case 2:
			item.product = newStringAttrFromUriEncoded(attr)
		case 3:
			item.version = newStringAttrFromUriEncoded(attr)
		case 4:
			item.update = newStringAttrFromUriEncoded(attr)
		case 5:
			editions := strings.Split(attr, "~")
			if len(editions) == 1 {
				item.edition = newStringAttrFromUriEncoded(editions[0])
			} else if len(editions) == 6 {
				item.edition = newStringAttrFromUriEncoded(editions[1])
				item.swEdition = newStringAttrFromUriEncoded(editions[2])
				item.targetSw = newStringAttrFromUriEncoded(editions[3])
				item.targetHw = newStringAttrFromUriEncoded(editions[4])
				item.other = newStringAttrFromUriEncoded(editions[5])
			} else {
				return nil, cpeErr{reason: errInvalidWfn}
			}
		}
	}
	// Success
	return item, nil
}

func NewItemFromFormattedString(str string) (*Item, error) {
	if strings.HasPrefix(str, "cpe:2.3:") {
		str = replaceToDelim(strings.TrimPrefix(str, "cpe:2.3:"))
	} else {
		return nil, cpeErr{reason: errInvalidWfn}
	}
	attrs := strings.Split(str, ":")
	if len(attrs) != 11 {
		return nil, cpeErr{reason: errInvalidWfn}
	}
	item := NewItem()
	for i, attr := range attrs {
		switch i {
		case 0:
			item.part = newPartAttrFromFmtEncoded(replaceFromDelim(attr))
		case 1:
			item.vendor = newStringAttrFromFmtEncoded(replaceFromDelim(attr))
		case 2:
			item.product = newStringAttrFromFmtEncoded(replaceFromDelim(attr))
		case 3:
			item.version = newStringAttrFromFmtEncoded(replaceFromDelim(attr))
		case 4:
			item.update = newStringAttrFromFmtEncoded(replaceFromDelim(attr))
		case 5:
			item.edition = newStringAttrFromFmtEncoded(replaceFromDelim(attr))
		case 6:
			item.language = newStringAttrFromFmtEncoded(replaceFromDelim(attr))
		case 7:
			item.swEdition = newStringAttrFromFmtEncoded(replaceFromDelim(attr))
		case 8:
			item.targetSw = newStringAttrFromFmtEncoded(replaceFromDelim(attr))
		case 9:
			item.targetHw = newStringAttrFromFmtEncoded(replaceFromDelim(attr))
		case 10:
			item.other = newStringAttrFromFmtEncoded(replaceFromDelim(attr))
		}
	}
	// Success
	return item, nil
}

func (m *Item) Wfn() string {
	wfn := "wfn:["
	first := true
	for _, it := range []struct {
		name string
		attr Attribute
	}{
		{"part", m.part},
		{"vendor", m.vendor},
		{"product", m.product},
		{"version", m.version},
		{"update", m.update},
		{"edition", m.edition},
		{"language", m.language},
		{"sw_edition", m.swEdition},
		{"target_sw", m.targetSw},
		{"target_hw", m.targetHw},
		{"other", m.other},
	} {
		if !it.attr.IsEmpty() {
			if first {
				first = false
			} else {
				wfn += ","
			}
			wfn += it.name + "=" + it.attr.wfnEncoded()
		}
	}
	wfn += "]"
	// Success
	return wfn
}

func (m *Item) Uri() string {
	uri := "cpe:/"
	l := []struct {
		name string
		attr Attribute
	}{
		{"part", m.part},
		{"vendor", m.vendor},
		{"product", m.product},
		{"version", m.version},
		{"update", m.update},
	}
	for c, it := range l {
		if !it.attr.IsEmpty() {
			uri += it.attr.urlEncoded()
		}
		if c+1 != len(l) {
			uri += ":"
		}
	}
	if m.targetHw.urlEncoded() != "" ||
		m.targetSw.urlEncoded() != "" ||
		m.swEdition.urlEncoded() != "" ||
		m.other.urlEncoded() != "" {
		uri += ":~" + m.edition.urlEncoded()
		uri += "~" + m.swEdition.urlEncoded()
		uri += "~" + m.targetSw.urlEncoded()
		uri += "~" + m.targetHw.urlEncoded()
		uri += "~" + m.other.urlEncoded()
	} else {
		uri += ":" + m.edition.urlEncoded()
	}
	uri += ":" + m.language.urlEncoded()
	// Success
	return strings.TrimRight(uri, ":*")
}

func (m *Item) Formatted() string {
	format := "cpe:2.3"
	for _, it := range []Attribute{
		m.part, m.vendor, m.product, m.version, m.update, m.edition, m.language, m.swEdition, m.targetSw, m.targetHw, m.other,
	} {
		if !it.IsEmpty() {
			format += ":" + it.fmtString()
		} else {
			format += ":*"

		}
	}
	// Success
	return format
}

func (m *Item) SetPart(p PartAttr) error {
	if !p.IsValid() {
		return cpeErr{reason: errInvalidType, attr: []interface{}{p, "part"}}
	}
	m.part = p
	// Success
	return nil
}

func (m *Item) Part() PartAttr {
	// Success
	return m.part
}

func (m *Item) SetVendor(s StringAttr) error {
	if !s.IsValid() {
		return cpeErr{reason: errInvalidAttributeStr}
	}
	m.vendor = s
	// Success
	return nil
}

func (m *Item) Vendor() StringAttr {
	// Success
	return m.vendor
}

func (m *Item) SetProduct(s StringAttr) error {
	if !s.IsValid() {
		return cpeErr{reason: errInvalidAttributeStr}
	}
	m.product = s
	// Success
	return nil
}

func (m *Item) Product() StringAttr {
	// Success
	return m.product
}

func (m *Item) SetVersion(s StringAttr) error {
	if !s.IsValid() {
		return cpeErr{reason: errInvalidAttributeStr}
	}
	m.version = s
	// Success
	return nil
}

func (m *Item) Version() StringAttr {
	// Success
	return m.version
}

func (m *Item) SetUpdate(s StringAttr) error {
	if !s.IsValid() {
		return cpeErr{reason: errInvalidAttributeStr}
	}
	m.update = s
	// Success
	return nil
}

func (m *Item) Update() StringAttr {
	// Success
	return m.update
}

func (m *Item) SetEdition(s StringAttr) error {
	if !s.IsValid() {
		return cpeErr{reason: errInvalidAttributeStr}
	}
	m.edition = s
	// Success
	return nil
}

func (m *Item) Edition() StringAttr {
	// Success
	return m.edition
}

func (m *Item) SetLanguage(s StringAttr) error {
	if !s.IsValid() {
		return cpeErr{reason: errInvalidAttributeStr}
	}
	m.language = s
	// Success
	return nil
}

func (m *Item) Language() StringAttr {
	// Success
	return m.language
}

func (m *Item) SetSwEdition(s StringAttr) error {
	if !s.IsValid() {
		return cpeErr{reason: errInvalidAttributeStr}
	}
	m.swEdition = s
	// Success
	return nil
}

func (m *Item) SwEdition() StringAttr {
	// Success
	return m.swEdition
}

func (m *Item) SetTargetSw(s StringAttr) error {
	if !s.IsValid() {
		return cpeErr{reason: errInvalidAttributeStr}
	}
	m.targetSw = s
	// Success
	return nil
}

func (m *Item) TargetSw() StringAttr {
	// Success
	return m.targetSw
}

func (m *Item) SetTargetHw(s StringAttr) error {
	if !s.IsValid() {
		return cpeErr{reason: errInvalidAttributeStr}
	}
	m.targetHw = s
	// Success
	return nil
}

func (m *Item) TargetHw() StringAttr {
	// Success
	return m.targetHw
}

func (m *Item) SetOther(s StringAttr) error {
	if !s.IsValid() {
		return cpeErr{reason: errInvalidAttributeStr}
	}
	m.other = s
	// Success
	return nil
}

func (m *Item) Other() StringAttr {
	// Success
	return m.other
}

func replaceToDelim(str string) string {
	// Success
	return strings.Replace(str, "\\:", goCpeOriginalDelim, -1)
}

func replaceFromDelim(str string) string {
	// Success
	return strings.Replace(str, goCpeOriginalDelim, "\\:", -1)
}
