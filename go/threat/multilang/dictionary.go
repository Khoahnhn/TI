package multilang

import "gitlab.viettelcyber.com/ti-micro/ws-threat/defs"

type M map[string]string

func (t M) Get(k string) string {
	if v, ok := t[k]; ok {
		return v
	}
	return ""
}

func Get(lang, key string) string {
	switch lang {
	case defs.LangEN:
		return en.Get(key)
	case defs.LangVI:
		return vi.Get(key)
	default:
		return ""
	}
}
