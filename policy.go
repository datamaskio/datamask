package datamask

import (
	"fmt"
	"sort"
	"strings"
)

// Policy is an immutable set of rules that raise the protection of tagged
// fields: "for data type X, use at least transform T" (ADR-0028). It is not a
// function over values; rules never see field values or each other's output.
//
// The zero value is a valid policy with no rules. Build policies with
// ForDataType and Compose, or use the Masker presets RedactPII and
// HashEmails. A Policy is safe for concurrent use and can be shared.
//
// Resolution for a tagged field is deterministic and order-independent:
//
//   - Maskable always wins (the field's own Mask() runs).
//   - The tag's transform is the floor; a policy can only raise it.
//   - Among the tag and every matching rule, the most restrictive transform
//     wins: Redact > Tokenize > Hash > Partial.
//
// Fields without a mask tag are never selected: a policy raises protection on
// declared fields, it does not discover new ones.
type Policy struct {
	rules map[DataType]Transform
	err   error // first construction error; reported by Apply
}

// ForDataType returns a Policy that requires fields of data type dt to use at
// least transform t. An unknown data type or transform yields a Policy whose
// use in Apply returns an error wrapping ErrInvalidInput, so a typo can never
// silently weaken protection.
func ForDataType(dt DataType, t Transform) Policy {
	switch {
	case dt < DataTypeEmail || dt > DataTypeJWT:
		return Policy{err: fmt.Errorf("%w: ForDataType(%d): %w", ErrInvalidInput, dt, ErrUnknownDataType)}
	case t > TransformPartial:
		return Policy{err: fmt.Errorf("%w: ForDataType(%v, %d): %w", ErrInvalidInput, dt, t, ErrUnknownTransform)}
	}
	return Policy{rules: map[DataType]Transform{dt: t}}
}

// Compose merges rule sets into one. When two rules name the same data type
// the more restrictive transform is kept, so the result does not depend on
// argument order. Compose never modifies its arguments.
func Compose(policies ...Policy) Policy {
	var out Policy
	for _, p := range policies {
		if p.err != nil && out.err == nil {
			out.err = p.err
		}
		for dt, t := range p.rules {
			if out.rules == nil {
				out.rules = make(map[DataType]Transform, len(p.rules))
			}
			if cur, ok := out.rules[dt]; ok {
				t = moreRestrictive(cur, t)
			}
			out.rules[dt] = t
		}
	}
	return out
}

// RedactPII returns a Policy that redacts email, phone, ssn and credit-card
// fields.
func (m *Masker) RedactPII() Policy {
	return Compose(
		ForDataType(DataTypeEmail, TransformRedact),
		ForDataType(DataTypePhone, TransformRedact),
		ForDataType(DataTypeSSN, TransformRedact),
		ForDataType(DataTypeCreditCard, TransformRedact),
	)
}

// HashEmails returns a Policy that hashes email fields. A field tagged
// mask:"email" stays redacted, because the tag is the floor and redact is more
// restrictive than hash. Apply fails with ErrInvalidSchema if the Masker has
// no HashKey.
func (m *Masker) HashEmails() Policy {
	return ForDataType(DataTypeEmail, TransformHash)
}

// String lists the rules in a stable order, e.g. "email=hash, phone=redact".
// The zero Policy is "(no rules)".
func (p Policy) String() string {
	if len(p.rules) == 0 {
		return "(no rules)"
	}
	dts := make([]DataType, 0, len(p.rules))
	for dt := range p.rules {
		dts = append(dts, dt)
	}
	sort.Slice(dts, func(i, j int) bool { return dts[i] < dts[j] })
	parts := make([]string, len(dts))
	for i, dt := range dts {
		parts[i] = dt.String() + "=" + p.rules[dt].String()
	}
	return strings.Join(parts, ", ")
}

// check reports whether p can be applied by m: it must have been built
// without errors, and rules that need a key require the Masker to have one.
func (p Policy) check(m *Masker) error {
	if p.err != nil {
		return p.err
	}
	for dt, t := range p.rules {
		switch {
		case t == TransformHash && m.cfg.HashKey == "":
			return fmt.Errorf("%w: policy rule %v=hash requires a key; configure WithHashKey", ErrInvalidSchema, dt)
		case t == TransformTokenize && m.cfg.TokenizeKey == "":
			return fmt.Errorf("%w: policy rule %v=tokenize requires a key; configure WithTokenizeKey", ErrInvalidSchema, dt)
		}
	}
	return nil
}
