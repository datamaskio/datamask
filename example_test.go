package datamask_test

import (
	"errors"
	"fmt"
	"strings"

	"github.com/datamaskio/datamask"
)

type Customer struct {
	Name  string
	Email string `mask:"email"`
	Phone string `mask:"phone,partial"`
	SSN   string `mask:"ssn"`
}

func ExampleRedact() {
	masker := datamask.New()
	customer := Customer{Name: "Ann", Email: "ann@example.com", Phone: "+1-555-1234", SSN: "123-45-6789"}

	// Redact returns a masked copy; customer is never modified.
	masked, err := datamask.Redact(masker, customer)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", masked)
	fmt.Println(customer.Email)
	// Output:
	// {Name:Ann Email:[REDACTED] Phone:+*-***-1234 SSN:[REDACTED]}
	// ann@example.com
}

func ExampleMasker_RedactInPlace() {
	masker := datamask.New()
	customer := &Customer{Name: "Ann", Email: "ann@example.com", Phone: "+1-555-1234", SSN: "123-45-6789"}

	// RedactInPlace mutates the value: use it on hot paths with data you own.
	if err := masker.RedactInPlace(customer); err != nil {
		panic(err)
	}
	fmt.Println(customer.Email, customer.SSN)
	// Output: [REDACTED] [REDACTED]
}

func ExampleCompile() {
	masker := datamask.New()

	// Compile parses tags once; reuse the Schema across calls.
	schema, err := datamask.Compile[Customer](masker)
	if err != nil {
		panic(err)
	}
	masked, _ := schema.Redact(Customer{Name: "Ann", Email: "ann@example.com"})
	fmt.Println(masked.Name, masked.Email)
	// Output: Ann [REDACTED]
}

func ExampleSchema_Explain() {
	masker := datamask.New(datamask.WithHashKey("example-key"))
	type Account struct {
		Email string `mask:"email"`
		Token string `mask:"secret,hash"`
	}
	fmt.Print(datamask.MustCompile[Account](masker).Explain())
	// Output:
	// Schema: Account
	//
	//   Email (string)
	//     data type: email
	//     transform: redact
	//
	//   Token (string)
	//     data type: secret
	//     transform: hash
}

func ExampleSchema_Warnings() {
	type Event struct {
		Name    string
		Payload any // dynamic contents cannot be verified at compile time
	}
	schema := datamask.MustCompile[Event](datamask.New())
	for _, w := range schema.Warnings() {
		fmt.Printf("%s: %s\n", w.FieldPath, w.Reason)
	}
	// Output: Event.Payload: interface-typed field; dynamic contents are not verified
}

func ExampleCompile_errors() {
	masker := datamask.New()

	// A transform-only tag is a clean-break error, caught at Compile.
	type Old struct {
		Token string `mask:"hash"`
	}
	_, err := datamask.Compile[Old](masker)
	fmt.Println(errors.Is(err, datamask.ErrUnknownDataType))

	// hash and tokenize need a key, so a missing one fails at startup.
	type Hashed struct {
		Token string `mask:"secret,hash"`
	}
	_, err = datamask.Compile[Hashed](masker)
	fmt.Println(errors.Is(err, datamask.ErrInvalidSchema))
	// Output:
	// true
	// true
}

func ExampleApply() {
	masker := datamask.New(datamask.WithHashKey("example-key"))
	type Profile struct {
		Email string `mask:"email,partial"`
		Phone string `mask:"phone,partial"`
	}
	profile := Profile{Email: "ann@example.com", Phone: "+1-555-1234"}

	// The policy raises protection on tagged fields; the tag is the floor.
	masked, err := datamask.Apply(masker, profile, masker.RedactPII())
	if err != nil {
		panic(err)
	}
	fmt.Println(masked.Email, masked.Phone)
	// Output: [REDACTED] [REDACTED]
}

func ExampleCompose() {
	masker := datamask.New(datamask.WithHashKey("example-key"))

	// Rules merge; the most restrictive transform wins, in any order.
	a := datamask.Compose(masker.HashEmails(), masker.RedactPII())
	b := datamask.Compose(masker.RedactPII(), masker.HashEmails())
	fmt.Println(a)
	fmt.Println(b)
	// Output:
	// email=redact, phone=redact, ssn=redact, credit-card=redact
	// email=redact, phone=redact, ssn=redact, credit-card=redact
}

func ExampleForDataType() {
	masker := datamask.New(datamask.WithHashKey("example-key"))
	type Login struct {
		Email string `mask:"email,partial"`
	}
	hashed, _ := datamask.Apply(masker, Login{Email: "ann@example.com"},
		datamask.ForDataType(datamask.DataTypeEmail, datamask.TransformHash))
	fmt.Println(strings.HasPrefix(hashed.Email, "tok:"))
	// Output: true
}

// LastFour is a custom type that controls its own masking. Mask must return
// the same type; returning an error makes Redact fail closed.
type LastFour string

func (c LastFour) Mask() (any, error) {
	if len(c) < 4 {
		return nil, errors.New("value too short")
	}
	return LastFour("****" + c[len(c)-4:]), nil
}

func ExampleMaskable() {
	masker := datamask.New()
	type Payment struct {
		Card LastFour // no tag needed: the Maskable contract is enough
	}

	masked, err := datamask.Redact(masker, Payment{Card: "4111111111111111"})
	fmt.Println(masked.Card, err)

	// A failing Mask() never leaks: Redact returns the zero value and the error.
	masked, err = datamask.Redact(masker, Payment{Card: "123"})
	fmt.Printf("%q %v\n", masked.Card, errors.Is(err, datamask.ErrMaskFailed))
	// Output:
	// ****1111 <nil>
	// "" true
}

func ExampleRedact_nested() {
	masker := datamask.New()
	type Profile struct {
		Avatar string
		Email  string `mask:"email"`
	}
	type User struct {
		Name    string
		Profile *Profile
		Orders  []Profile
		Meta    map[string]any
	}
	user := User{
		Name:    "Ann",
		Profile: &Profile{Avatar: "a.png", Email: "ann@example.com"},
		Orders:  []Profile{{Email: "o1@example.com"}},
		Meta:    map[string]any{"billing": Profile{Email: "bill@example.com"}},
	}

	masked, _ := datamask.Redact(masker, user)
	fmt.Println(masked.Profile.Email, masked.Orders[0].Email, masked.Meta["billing"].(Profile).Email)
	fmt.Println(user.Profile.Email) // the original is untouched
	// Output:
	// [REDACTED] [REDACTED] [REDACTED]
	// ann@example.com
}

func ExampleRedact_cycle() {
	masker := datamask.New()
	type Node struct {
		Secret string `mask:"secret"`
		Next   *Node
	}
	n := &Node{Secret: "s"}
	n.Next = n

	_, err := datamask.Redact(masker, n)
	fmt.Println(errors.Is(err, datamask.ErrCyclicReference))
	// Output: true
}
