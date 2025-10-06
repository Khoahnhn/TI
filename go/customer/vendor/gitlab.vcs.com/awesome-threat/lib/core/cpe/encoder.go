package cpe

import (
	"strings"
)

type (
	charEncoder []encodeTable
	encodeTable struct {
		raw     string
		encoded string
	}
)

var (
	urlEncoder = charEncoder{
		{"%", "%25"},
		{"!", "%21"},
		{"\"", "%22"},
		{"#", "%23"},
		{"$", "%24"},
		{"&", "%26"},
		{"'", "%27"},
		{"(", "%28"},
		{")", "%29"},
		{"+", "%2b"},
		{",", "%2c"},
		{"-", "-"},
		{".", "."},
		{"/", "%2f"},
		{":", "%3a"},
		{";", "%3b"},
		{"<", "%3c"},
		{"=", "%3d"},
		{">", "%3e"},
		{"@", "%40"},
		{"[", "%5b"},
		{"\\", "%5c"},
		{"]", "%5d"},
		{"^", "%5e"},
		{"`", "%60"},
		{"{", "%7b"},
		{"|", "%7c"},
		{"}", "%7d"},
		{"~", "%7e"},
		{"?", "%01"},
		{"*", "%02"},
	}

	wfnEncoder = charEncoder{
		{"\\", "\\\\"},
		{"-", "\\-"},
		{"#", "\\#"},
		{"$", "\\$"},
		{"%", "\\%"},
		{"&", "\\&"},
		{"'", "\\'"},
		{"(", "\\("},
		{")", "\\)"},
		{"+", "\\+"},
		{",", "\\,"},
		{".", "\\."},
		{"/", "\\/"},
		{":", "\\:"},
		{";", "\\;"},
		{"<", "\\<"},
		{"=", "\\="},
		{">", "\\>"},
		{"@", "\\@"},
		{"!", "\\!"},
		{"\"", "\\\""},
		{"[", "\\["},
		{"]", "\\]"},
		{"^", "\\^"},
		{"`", "\\`"},
		{"{", "\\{"},
		{"}", "\\}"},
		{"|", "\\|"},
		{"~", "\\~"},
	}

	fmtEncoder = charEncoder{
		{"\\", "\\\\"},
		{"#", "\\#"},
		{"$", "\\$"},
		{"%", "\\%"},
		{"&", "\\&"},
		{"'", "\\'"},
		{"(", "\\("},
		{")", "\\)"},
		{"+", "\\+"},
		{",", "\\,"},
		{"/", "\\/"},
		{":", "\\:"},
		{";", "\\;"},
		{"<", "\\<"},
		{"=", "\\="},
		{">", "\\>"},
		{"@", "\\@"},
		{"!", "\\!"},
		{"\"", "\\\""},
		{"[", "\\["},
		{"]", "\\]"},
		{"^", "\\^"},
		{"`", "\\`"},
		{"{", "\\{"},
		{"}", "\\}"},
		{"|", "\\|"},
		{"~", "\\~"},
	}
)

func (t charEncoder) Encode(str string) string {
	for _, it := range t {
		str = it.Encode(str)
	}
	// Success
	return str
}

func (t charEncoder) Decode(str string) string {
	for _, it := range t {
		str = it.Decode(str)
	}
	// Success
	return str
}

func (t encodeTable) Encode(str string) string {
	// Success
	return strings.Replace(str, t.raw, t.encoded, -1)
}

func (t encodeTable) Decode(str string) string {
	// Success
	return strings.Replace(str, t.encoded, t.raw, -1)
}
