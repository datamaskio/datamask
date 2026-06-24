package datamask

// Policy is a transformation that can be applied to any value.
// It receives a value and returns a transformed copy (or the original
// if no transformation is applicable). Policies must not mutate their
// input.
//
// A Policy is a plain function — callers can define custom policies
// inline or use Compose to chain built-in ones.
type Policy func(v any) (any, error)

// Identity is a policy that returns its input unchanged.
func Identity() Policy {
	return func(v any) (any, error) {
		return v, nil
	}
}

// Compose chains policies left-to-right. The output of each policy
// becomes the input of the next. If any policy returns an error, the
// chain stops and the error is returned.
//
// Compose with no arguments returns the Identity policy.
func Compose(policies ...Policy) Policy {
	if len(policies) == 0 {
		return Identity()
	}
	if len(policies) == 1 {
		return policies[0]
	}
	return func(v any) (any, error) {
		var err error
		for _, p := range policies {
			v, err = p(v)
			if err != nil {
				return v, err
			}
		}
		return v, nil
	}
}
