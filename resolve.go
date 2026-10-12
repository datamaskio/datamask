package datamask

// restrictiveness ranks transforms by how little of the original data they
// leave visible (ADR-0028). It is a library privacy policy, not a statement
// about cryptographic strength.
func restrictiveness(t Transform) int {
	switch t {
	case TransformRedact:
		return 3
	case TransformTokenize:
		return 2
	case TransformHash:
		return 1
	default: // TransformPartial
		return 0
	}
}

// moreRestrictive returns whichever of a and b leaves less data visible.
// Ties (equal transforms) return a.
func moreRestrictive(a, b Transform) Transform {
	if restrictiveness(b) > restrictiveness(a) {
		return b
	}
	return a
}

// resolveTransform returns the transform to apply to a tagged field: the
// tag's transform, raised to the policy's rule for the field's data type if
// that rule is more restrictive. The tag is the floor; a policy never lowers
// it. Maskable fields never reach this function (Mask() always wins).
func resolveTransform(tag Transform, p Policy, dt DataType) Transform {
	if rule, ok := p.rules[dt]; ok {
		return moreRestrictive(tag, rule)
	}
	return tag
}
