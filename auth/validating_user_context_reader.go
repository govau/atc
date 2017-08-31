package auth

//go:generate counterfeiter . ValidatingUserContextReader

// ValidatingUserContextReader validates a token and tells you about its context
type ValidatingUserContextReader interface {
	Validator
	UserContextReader
}
