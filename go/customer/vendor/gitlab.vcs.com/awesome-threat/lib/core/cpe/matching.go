package cpe

type Relation int

const (
	Disjoint = Relation(iota)
	Equal
	Subset
	Superset
	Undefined
)

func CheckDisjoint(src, dest *Item, custom bool) bool {
	type obj struct {
		src  Attribute
		dest Attribute
	}
	for _, v := range []obj{
		{src.part, dest.part},
		{src.vendor, dest.vendor},
		{src.product, dest.product},
		{src.version, dest.version},
		{src.update, dest.update},
		{src.edition, dest.edition},
		{src.language, dest.language},
		{src.swEdition, dest.swEdition},
		{src.targetSw, dest.targetSw},
		{src.targetHw, dest.targetHw},
		{src.other, dest.other},
	} {
		switch v.src.Comparison(v.dest, custom) {
		case Disjoint:
			return true
		}
	}
	return false
}

func CheckEqual(src, dest *Item, custom bool) bool {
	type obj struct {
		src  Attribute
		dest Attribute
	}
	for _, v := range []obj{
		{src.part, dest.part},
		{src.vendor, dest.vendor},
		{src.product, dest.product},
		{src.version, dest.version},
		{src.update, dest.update},
		{src.edition, dest.edition},
		{src.language, dest.language},
		{src.swEdition, dest.swEdition},
		{src.targetSw, dest.targetSw},
		{src.targetHw, dest.targetHw},
		{src.other, dest.other},
	} {
		switch v.src.Comparison(v.dest, custom) {
		case Equal:
		default:
			return false
		}
	}
	return true
}

func CheckSubset(src, dest *Item, custom bool) bool {
	type obj struct {
		src  Attribute
		dest Attribute
	}
	for _, v := range []obj{
		{src.part, dest.part},
		{src.vendor, dest.vendor},
		{src.product, dest.product},
		{src.version, dest.version},
		{src.update, dest.update},
		{src.edition, dest.edition},
		{src.language, dest.language},
		{src.swEdition, dest.swEdition},
		{src.targetSw, dest.targetSw},
		{src.targetHw, dest.targetHw},
		{src.other, dest.other},
	} {
		switch v.src.Comparison(v.dest, custom) {
		case Subset, Equal:
		default:
			return false
		}
	}
	return true
}

func CheckSuperset(src, dest *Item, custom bool) bool {
	type obj struct {
		src  Attribute
		dest Attribute
	}
	for _, v := range []obj{
		{src.part, dest.part},
		{src.vendor, dest.vendor},
		{src.product, dest.product},
		{src.version, dest.version},
		{src.update, dest.update},
		{src.edition, dest.edition},
		{src.language, dest.language},
		{src.swEdition, dest.swEdition},
		{src.targetSw, dest.targetSw},
		{src.targetHw, dest.targetHw},
		{src.other, dest.other},
	} {
		switch v.src.Comparison(v.dest, custom) {
		case Superset, Equal:
		default:
			return false
		}
	}
	return true
}
