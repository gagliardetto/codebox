package main

import (
	"io"
	"strconv"

	somepackage "github.com/gagliardetto/codebox/demo-package"
)

func main()              {}
func sink(v interface{}) {}

func TaintStepTest_SomeFunc(sourceCQL interface{}) {
	{
		// The flow is from `in0` into `s`.

		// Assume that `sourceCQL` has the underlying type of `in0`:
		in0 := sourceCQL.(string)

		// Declare `s` variable:
		var s strconv.NumError

		// Call medium method that transfers the taint
		// from the parameter `in0` to parameter `s`;
		// `s` is now tainted.
		somepackage.SomeFunc(in0, nil, s, nil, somepackage.SomeStruct{})

		// Sink the tainted `s`:
		sink(s)
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
