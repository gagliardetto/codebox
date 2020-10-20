package main

import (
	"io"
	"strconv"

	somepackage "github.com/gagliardetto/codebox/deprecated/demo-package"
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
func TaintStepTest_SomeFuncA(sourceCQL interface{}) {
	{
		// The flow is from `in0` into `st`.

		// Assume that `sourceCQL` has the underlying type of `in0`:
		in0 := sourceCQL.(string)

		// Declare `st` variable:
		var st somepackage.SomeStruct

		// Call medium method that transfers the taint
		// from the parameter `in0` to parameter `st`;
		// `st` is now tainted.
		somepackage.SomeFunc(in0, nil, strconv.NumError{}, nil, st)

		// Sink the tainted `st`:
		sink(st)
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
func TaintStepTest_SomeFunc1B(sourceCQL interface{}) {
	{
		// The flow is from `pings` into `pongs`.

		// Assume that `sourceCQL` has the underlying type of `pings`:
		pings := sourceCQL.(<-chan string)

		// Declare `pongs` variable:
		var pongs chan<- string

		// Call medium method that transfers the taint
		// from the parameter `pings` to parameter `pongs`;
		// `pongs` is now tainted.
		somepackage.SomeFunc1b(pings, pongs)

		// Sink the tainted `pongs`:
		sink(pongs)
	}
}
