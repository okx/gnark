package schema

import (
	"math/big"
	"reflect"
)

// LeafInfo stores the leaf visibility (always set to Secret or Public)
// and the fully qualified name of the path to reach the leaf in the circuit struct.
type LeafInfo struct {
	Visibility Visibility
	FullName   func() string // in most instances, we don't need to actually evaluate the name.
	name       string
}

// LeafCount stores the number of secret and public interface of type target(reflect.Type)
// found by the walker.
type LeafCount struct {
	Secret int
	Public int
}

// LeafHandler is the handler function that will be called when Walk reaches leafs of the struct
type LeafHandler func(field LeafInfo, tValue reflect.Value) error

// Initializable is an object which knows how to initialize itself when parsed at
// compile time.
//
// This allows to define new primitive circuit variable types which may require
// allocations and by using this interface the circuit user doesn't need to
// explicitly initialize these types themselves.
//
// The Initialize method can be called multiple times during different parsing
// and compilation steps, so the implementation should be idempotent.
type Initializable interface {
	// Initialize initializes the object. It receives as an argument the native field
	// that will be used to compile the circuit.
	//
	// NB! This method can be called multiple times, so the implementation should
	// be idempotent.
	Initialize(field *big.Int)
}
