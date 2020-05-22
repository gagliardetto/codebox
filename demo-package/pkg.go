package somepackage

import (
	"io"
	"strconv"

	"github.com/gogo/protobuf/jsonpb"
)

// Doc of SomeFunc
func SomeFunc(in0 string, w io.Writer, s strconv.NumError, gh jsonpb.AnyResolver, st SomeStruct) (out0 string) {
	return ""
}

func unexportedFunc() (out0 string) {
	return ""
}

// This is interface doc.
type SomeInterface interface {
	// a method documentation
	AMethod0(in string) bool
	// other comments
	// a lot of other comments
	AMethod1(in string) bool
}

// Doc of SomeStruct
type SomeStruct struct {
}

// doc on pointer method
func (st *SomeStruct) SomePtrMethod(methodInput0 string, r io.Reader) string {
	return ""
}

// doc on val method
func (st SomeStruct) SomeValMethod(methodInput0 string, r io.Reader) string {
	return ""
}

type SomeType int

// Pointer method on TypeMethod
func (st *SomeType) TypePtrMethod(b bool) string {
	return ""
}

// Value method on TypeMethod with pointer param
func (st SomeType) TypeValueMethod(b *bool) string {
	return ""
}
