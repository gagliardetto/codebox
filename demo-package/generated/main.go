package main

import (
	"io"
	"strconv"

	somepackage "github.com/gagliardetto/codebox/demo-package"
)

func sink(v interface{}) {

}
func main() {

}
func TaintStepTest_SomeFunc(sourceCQL interface{}) {
	{
		// The flow is from `st` into `w`.

		// Assume that `sourceCQL` has the underlying type of `st`:
		st := sourceCQL.(somepackage.SomeStruct)

		// Declare `into` variable:
		var w io.Writer

		// Call medium method that transfers the taint
		// from the parameter `st` to parameter `w`;
		// `w` is now tainted.
		somepackage.SomeFunc("", w, strconv.NumError{}, nil, st)

		// Sink the tainted `into`:
		sink(w)
	}
}

func TaintStepTest_Copy(source interface{}) {
	{
		// The flow is from `src` into `dst`
		// Assert type of `from`:
		src := source.(io.Reader)

		// Declare `into` variable:
		var dst io.Writer

		// Call medium method that transfers the taint
		// from the parameter `from` to another parameter
		// (`into` is now tainted).
		io.Copy(dst, src)

		// Sink the tainted `into`:
		sink(dst)
	}
}
