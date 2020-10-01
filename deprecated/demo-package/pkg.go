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
func SomeFunc1a(in0 chan bool, in1 chan *int, in2 *SomeStruct, in3 chan jsonpb.AnyResolver) (out0 string) {
	return ""
}
func SomeFunc1b(pings <-chan string, pongs chan<- string) (out0 string) {
	return ""
}
func SomeFunc1c(pings <-chan *SomeStruct, pongs chan<- *SomeStruct) (out0 string) {
	return ""
}
func SomeFunc1d(pings <-chan jsonpb.AnyResolver, pongs chan<- jsonpb.AnyResolver) (out0 string) {
	return ""
}
func SomeFunc2a(in0 int, in1 int8, in2 int16, in3 int32, in4 int64) (out0 string) {
	return ""
}
func SomeFunc2b(in0 *int, in1 *int8, in2 *int16, in3 *int32, in4 *int64) (out0 string) {
	return ""
}
func SomeFunc3(in0 uint, in1 uint8, in2 uint16, in3 uint32, in4 uint64) (out0 string) {
	return ""
}
func SomeFunc4(in0 *uint, in1 *uint8, in2 *uint16, in3 *uint32, in4 *uint64) (out0 string) {
	return ""
}
func SomeFunc5(in0 uintptr, in1 *uintptr) (out0 string) {
	return ""
}
func SomeFunc6(in0 float32, in1 float64, in2 *float32, in3 *float64) (out0 string) {
	return ""
}
func SomeFunc7(in0 rune, in1 *rune, in2 string, in3 *string) (out0 string) {
	return ""
}
func SomeFunc8(in0 complex64, in1 complex128, in2 *complex64, in3 *complex128) (out0 string) {
	return ""
}
func SomeFunc9a(in0 []SomeStruct, in1 []*SomeStruct) (out0 string) {
	return ""
}
func SomeFunc9b(in0 []SomeInterface, in1 []*SomeInterface) (out0 string) {
	return ""
}

//TODO (anonymous struct)
func SomeFunc10(in0 struct{}) (out0 string) {
	return ""
}

type FuncAlias func(string) string

func SomeFunc11(in0 func(bool) int, in1 FuncAlias) (out0 string) {
	return ""
}

//TODO (map of qualified)
func SomeFunc12(in0 map[string]string, in1 map[string]FuncAlias) (out0 string) {
	return ""
}
func SomeFunc13(in0 interface{}, in1 []interface{}) (out0 string) {
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

// variadic function
func Options(opts ...string) (string, string) {
	return "", ""
}
