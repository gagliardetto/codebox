package main

import (
	"fmt"

	. "github.com/dave/jennifer/jen"
)

// TODO:
// -  generate ad-hoc medium types.
func main() {
	// store[kind("func","method","interface")][qualified_name][array_of:{in:{elem:"",index:0},out:{elem:"",index:0}}]
	if false {
		f := NewFile("main")
		f.Func().Id("main").Params().Block(
			Qual("fmt", "Println").Call(Lit("Hello, world")),
		)
		fmt.Printf("%#v", f)
	}
	if false {
		c := List(Id("a"), Err()).Op(":=").Id("b").Call(Nil(), Err())
		fmt.Printf("%#v", c)
	}
	if false {
		code := Func().Id("TaintStepTestIoCopy").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("source").Interface())
				}).
			BlockFunc(
				func(group *Group) {
					group.BlockFunc(
						func(groupCase *Group) {
							groupCase.Comment("this is a comment")
							groupCase.Id("from").Op(":=").Id("source").Assert(Qual("io", "Reader"))
							groupCase.Var().Id("into").Qual("io", "Writer")
							groupCase.Qual("io", "Copy").Call(Id("into"), Id("from"))
							groupCase.Id("sink").Call(Id("into"))
						})
				})
		fmt.Printf("%#v", code.Line())
	}
	{
		// sink function:
		code := Func().Id("sink").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("v").Interface())
				}).
			Block()
		fmt.Printf("%#v", code.Line())
	}
	///////////////////////////////////////////////////////////////////////////////////////////////
	{ //OK
		// from: receiver
		// medium: method (when there is a receiver, then it must be a method medium)
		// into: param
		code := Func().Id("TaintStepTest_ReceMethPara").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("source").Interface())
				}).
			BlockFunc(
				func(group *Group) {
					group.BlockFunc(
						func(groupCase *Group) {
							groupCase.Comment("Assert type of `from`:")
							groupCase.Id("from").Op(":=").Id("source").Assert(Qual("pkg", "Type"))

							groupCase.Line().Comment("Declare `into` variable:")
							groupCase.Var().Id("into").Qual("io", "Writer")

							groupCase.
								Line().Comment("Call medium method that transfers the taint").
								Line().Comment("from the receiver `from` to the argument").
								Line().Comment("(`into` is now tainted).")
							groupCase.Id("from").Dot("WriteTo").Call(Id("into"))

							groupCase.Line().Comment("Sink the tainted `into`:")
							groupCase.Id("sink").Call(Id("into"))
						})
				})
		fmt.Printf("%#v", code.Line())
	}
	///////////////////////////////////////////////////////////////////////////////////////////////
	{ //OK
		// from: receiver
		// medium: method (when there is a receiver, then it must be a method medium)
		// into: result
		code := Func().Id("TaintStepTest_ReceMethResu").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("source").Interface())
				}).
			BlockFunc(
				func(group *Group) {
					group.BlockFunc(
						func(groupCase *Group) {
							groupCase.Comment("Assert type of `from`:")
							groupCase.Id("from").Op(":=").Id("source").Assert(Qual("pkg", "Type"))

							groupCase.
								Line().Comment("Call medium method that transfers the taint").
								Line().Comment("from the receiver `from` to the result").
								Line().Comment("(`into` is now tainted).")
							groupCase.List(Id("into"), Id("_")).Op(":=").Id("from").Dot("GetSomething").Call()

							groupCase.Line().Comment("Sink the tainted `into`:")
							groupCase.Id("sink").Call(Id("into"))
						})
				})
		fmt.Printf("%#v", code.Line())
	}

	///////////////////////////////////////////////////////////////////////////////////////////////
	{ //OK
		// from: param
		// medium: func
		// into: param
		code := Func().Id("TaintStepTest_ParaFuncPara").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("source").Interface())
				}).
			BlockFunc(
				func(group *Group) {
					group.BlockFunc(
						func(groupCase *Group) {
							groupCase.Comment("Assert type of `from`:")
							groupCase.Id("from").Op(":=").Id("source").Assert(Qual("pkg", "Type"))

							groupCase.Line().Comment("Declare `into` variable:")
							groupCase.Var().Id("into").Qual("io", "Writer")

							groupCase.
								Line().Comment("Call medium method that transfers the taint").
								Line().Comment("from the parameter `from` to another parameter").
								Line().Comment("(`into` is now tainted).")
							groupCase.Qual("io", "Copy").Call(Id("into"), Id("from"))

							groupCase.Line().Comment("Sink the tainted `into`:")
							groupCase.Id("sink").Call(Id("into"))
						})
				})
		fmt.Printf("%#v", code.Line())
	}
	///////////////////////////////////////////////////////////////////////////////////////////////
	{ //OK
		// from: param
		// medium: func
		// into: result
		code := Func().Id("TaintStepTest_ParaFuncResu").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("source").Interface())
				}).
			BlockFunc(
				func(group *Group) {
					group.BlockFunc(
						func(groupCase *Group) {
							groupCase.Comment("Assert type of `from`:")
							groupCase.Id("from").Op(":=").Id("source").Assert(Qual("pkg", "Type"))

							groupCase.
								Line().Comment("Call medium method that transfers the taint").
								Line().Comment("from the parameter `from` to result").
								Line().Comment("(`into` is now tainted).")
							groupCase.List(Id("into"), Id("_")).Op(":=").Qual("strings", "Clean").Call(Id("from"))

							groupCase.Line().Comment("Sink the tainted `into`:")
							groupCase.Id("sink").Call(Id("into"))
						})
				})
		fmt.Printf("%#v", code.Line())
	}
	///////////////////////////////////////////////////////////////////////////////////////////////
	{ //OK
		// from: param
		// medium: method (when there is a receiver, then it must be a method medium)
		// into: receiver
		code := Func().Id("TaintStepTest_ParaMethRece").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("source").Interface())
				}).
			BlockFunc(
				func(group *Group) {
					group.BlockFunc(
						func(groupCase *Group) {
							groupCase.Comment("Assert type of `from`:")
							groupCase.Id("from").Op(":=").Id("source").Assert(Qual("pkg", "Type"))

							groupCase.Line().Comment("Declare `into` variable:")
							groupCase.Var().Id("into").Qual("io", "Writer")

							groupCase.
								Line().Comment("Call medium method that transfers the taint").
								Line().Comment("from the parameter `from` to the receiver").
								Line().Comment("(`into` is now tainted).")
							groupCase.Id("into").Dot("Write").Call(Id("from"))

							groupCase.Line().Comment("Sink the tainted `into`:")
							groupCase.Id("sink").Call(Id("into"))
						})
				})
		fmt.Printf("%#v", code.Line())
	}
	///////////////////////////////////////////////////////////////////////////////////////////////
	{ //OK
		// from: param
		// medium: method (when there is a receiver, then it must be a method medium)
		// into: param
		code := Func().Id("TaintStepTest_ParaMethPara").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("source").Interface())
				}).
			BlockFunc(
				func(group *Group) {
					group.BlockFunc(
						func(groupCase *Group) {
							groupCase.Comment("Assert type of `from`:")
							groupCase.Id("from").Op(":=").Id("source").Assert(Qual("pkg", "Type"))

							groupCase.Line().Comment("Declare `into` variable:")
							groupCase.Var().Id("into").Qual("io", "Writer")

							groupCase.Line().Comment("Declare medium object/interface:")
							groupCase.Var().Id("mediumObj").Qual("io", "Transcoder")

							groupCase.
								Line().Comment("Call medium method that transfers the taint").
								Line().Comment("from the parameter `from` to another parameter").
								Line().Comment("(`into` is now tainted).")
							groupCase.Id("mediumObj").Dot("Transcode").Call(Id("into"), Id("from"))

							groupCase.Line().Comment("Sink the tainted `into`:")
							groupCase.Id("sink").Call(Id("into"))
						})
				})
		fmt.Printf("%#v", code.Line())
	}
	///////////////////////////////////////////////////////////////////////////////////////////////
	{ //OK
		// from: param
		// medium: method (when there is a receiver, then it must be a method medium)
		// into: result
		code := Func().Id("TaintStepTest_ParaMethResu").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("source").Interface())
				}).
			BlockFunc(
				func(group *Group) {
					group.BlockFunc(
						func(groupCase *Group) {
							groupCase.Comment("Assert type of `from`:")
							groupCase.Id("from").Op(":=").Id("source").Assert(Qual("pkg", "Type"))

							groupCase.Line().Comment("Declare `into` variable:")
							groupCase.Var().Id("into").Qual("io", "Writer")

							groupCase.Line().Comment("Declare medium object/interface:")
							groupCase.Var().Id("mediumObj").Qual("io", "Linter")

							groupCase.
								Line().Comment("Call medium method that transfers the taint").
								Line().Comment("from the parameter `from` to the result").
								Line().Comment("(`into` is now tainted).")
							groupCase.Id("into").Op(":=").Id("mediumObj").Dot("Lint").Call(Id("from"))

							groupCase.Line().Comment("Sink the tainted `into`:")
							groupCase.Id("sink").Call(Id("into"))
						})
				})
		fmt.Printf("%#v", code.Line())
	}
	///////////////////////////////////////////////////////////////////////////////////////////////
	{ //OK
		// from: result
		// medium: func
		// into: param
		// NOTE: does this actually happen? It needs extra steps, right?
		code := Func().Id("TaintStepTest_ResuFuncPara").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("source").Interface())
				}).
			BlockFunc(
				func(group *Group) {
					group.BlockFunc(
						func(groupCase *Group) {
							groupCase.Comment("Assert type of `from`:")
							groupCase.Id("from0").Op(":=").Id("source").Assert(Qual("pkg", "Type"))

							groupCase.Line().Comment("Declare `into` variable:")
							groupCase.Var().Id("into").Qual("io", "Writer")

							groupCase.
								Line().Comment("Call medium func that transfers the taint").
								Line().Comment("from the result `from` to parameter:")
							groupCase.List(Id("from1"), Id("_")).Op(":=").Qual("io", "CreateWriterFor").Call(Id("into"))

							groupCase.Line().Comment("Extra step (`from0` taints `from1`, which taints `into`:")
							groupCase.Id("from0").Dot("WriteTo").Call(Id("from1"))

							groupCase.Line().Comment("Sink the tainted `into`:")
							groupCase.Id("sink").Call(Id("into"))
						})
				})
		fmt.Printf("%#v", code.Line())
	}
	///////////////////////////////////////////////////////////////////////////////////////////////
	{ //OK
		// from: result
		// medium: func
		// into: result
		code := Func().Id("TaintStepTest_ResuFuncResu").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("source").Interface())
				}).
			BlockFunc(
				func(group *Group) {
					group.BlockFunc(
						func(groupCase *Group) {
							groupCase.Comment("Assert type of `from`:")
							groupCase.Id("from0").Op(":=").Id("source").Assert(Qual("pkg", "Type"))

							groupCase.Line().Comment("Declare `into` variable:")
							groupCase.Var().Id("into").Qual("io", "Writer")

							groupCase.
								Line().Comment("Call medium func that transfers the taint").
								Line().Comment("from the result `from1` to result `into`").
								Line().Comment("(extra steps needed)")
							groupCase.List(Id("into"), Id("from1")).Op(":=").Qual("io", "Pipe").Call()

							groupCase.Line().Comment("Extra step (`from0` taints `from1`, which taints `into`:")
							groupCase.Id("from0").Dot("WriteTo").Call(Id("from1"))

							groupCase.Line().Comment("Sink the tainted `into`:")
							groupCase.Id("sink").Call(Id("into"))
						})
				})
		fmt.Printf("%#v", code.Line())
	}
	///////////////////////////////////////////////////////////////////////////////////////////////
	{ //OK
		// from: result
		// medium: method
		// into: receiver
		code := Func().Id("TaintStepTest_ResuMethRece").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("source").Interface())
				}).
			BlockFunc(
				func(group *Group) {
					group.BlockFunc(
						func(groupCase *Group) {
							groupCase.Comment("Assert type of `from`:")
							groupCase.Id("from0").Op(":=").Id("source").Assert(Qual("pkg", "Type"))

							groupCase.Line().Comment("Declare `into` variable:")
							groupCase.Var().Id("into").Qual("framework", "Connection")

							groupCase.
								Line().Comment("Call medium method that transfers the taint").
								Line().Comment("from the result `from1` to the receiver `into`").
								Line().Comment("(`into` is now tainted).")
							groupCase.Id("from1").Op(":=").Id("into").Dot("NewWriter").Call()

							groupCase.Line().Comment("Extra step (`from0` taints `from1`, which taints `into`:")
							groupCase.Id("from0").Dot("WriteTo").Call(Id("from1"))

							groupCase.Line().Comment("Sink the tainted `into`:")
							groupCase.Id("sink").Call(Id("into"))
						})
				})
		fmt.Printf("%#v", code.Line())
	}
	///////////////////////////////////////////////////////////////////////////////////////////////
	{ //OK
		// from: result
		// medium: method
		// into: parameter
		code := Func().Id("TaintStepTest_ResuMethPara").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("source").Interface())
				}).
			BlockFunc(
				func(group *Group) {
					group.BlockFunc(
						func(groupCase *Group) {
							groupCase.Comment("Assert type of `from`:")
							groupCase.Id("from0").Op(":=").Id("source").Assert(Qual("pkg", "Type"))

							groupCase.Line().Comment("Declare `into` variable:")
							groupCase.Var().Id("into").Qual("so", "Something")

							groupCase.Line().Comment("Declare medium object/interface:")
							groupCase.Var().Id("mediumObj").Qual("io", "Linter")

							groupCase.
								Line().Comment("Call medium method that transfers the taint").
								Line().Comment("from the result `from1` to the parameter `into`.")
							groupCase.Id("from1").Op(":=").Id("mediumObj").Dot("CreateNewWriterFor").Call(Id("into"))

							groupCase.Line().Comment("Extra step (`from0` taints `from1`, which taints `into`:")
							groupCase.Id("from0").Dot("WriteTo").Call(Id("from1"))

							groupCase.Line().Comment("Sink the tainted `into`:")
							groupCase.Id("sink").Call(Id("into"))
						})
				})
		fmt.Printf("%#v", code.Line())
	}
	///////////////////////////////////////////////////////////////////////////////////////////////
	{ //OK
		// from: result
		// medium: method
		// into: result
		code := Func().Id("TaintStepTest_ResuMethResu").
			ParamsFunc(
				func(group *Group) {
					group.Add(Id("source").Interface())
				}).
			BlockFunc(
				func(group *Group) {
					group.BlockFunc(
						func(groupCase *Group) {
							groupCase.Comment("Assert type of `from`:")
							groupCase.Id("from0").Op(":=").Id("source").Assert(Qual("pkg", "Type"))

							groupCase.Line().Comment("Declare `into` variable:")
							groupCase.Var().Id("into").Qual("so", "Something")

							groupCase.Line().Comment("Declare medium object/interface:")
							groupCase.Var().Id("mediumObj").Qual("io", "PipePool")

							groupCase.
								Line().Comment("Call medium method that transfers the taint").
								Line().Comment("from the result `from1` to the result `into`.")
							groupCase.List(Id("from1"), Id("into")).Op(":=").Id("mediumObj").Dot("NewPipe").Call()

							groupCase.Line().Comment("Extra step (`from0` taints `from1`, which taints `into`:")
							groupCase.Id("from0").Dot("WriteTo").Call(Id("from1"))

							groupCase.Line().Comment("Sink the tainted `into`:")
							groupCase.Id("sink").Call(Id("into"))
						})
				})
		fmt.Printf("%#v", code.Line())
	}
}
