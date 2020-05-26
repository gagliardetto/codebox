package main

import (
	"errors"
	"flag"
	"fmt"
	"go/types"
	"sort"
	"strings"
	"sync"

	. "github.com/dave/jennifer/jen"
	"github.com/gagliardetto/codebox/scanner"
	. "github.com/gagliardetto/utils"
	"github.com/gin-gonic/gin"
	"github.com/iancoleman/strcase"
)

var (
	mu = &sync.RWMutex{}
)

type IndexItem struct {
	original interface{}
}

//
func NewIndexItem(v interface{}) *IndexItem {
	item := &IndexItem{}
	item.Set(v)
	return item
}

//
func (item *IndexItem) Set(v interface{}) {
	item.original = v
}

//
func (item *IndexItem) IsNil() bool {
	return item.original == nil
}

//
func (item *IndexItem) GetFEFunc() *FEFunc {
	fe, ok := item.original.(*FEFunc)
	if !ok {
		return nil
	}
	return fe
}

//
func (item *IndexItem) GetFETypeMethod() *FETypeMethod {
	fe, ok := item.original.(*FETypeMethod)
	if !ok {
		return nil
	}
	return fe
}

//
func (item *IndexItem) GetFEInterfaceMethod() *FEInterfaceMethod {
	fe, ok := item.original.(*FEInterfaceMethod)
	if !ok {
		return nil
	}
	return fe
}

type Index struct {
	mu     *sync.RWMutex
	values map[string]*IndexItem
}

func NewIndex() *Index {
	return &Index{
		mu:     &sync.RWMutex{},
		values: make(map[string]*IndexItem),
	}
}
func (index *Index) GetBySignature(signature string) *IndexItem {
	index.mu.RLock()
	defer index.mu.RUnlock()

	val, ok := index.values[signature]
	if !ok {
		return nil
	}
	return val
}

func (index *Index) Set(signature string, v interface{}) {
	index.mu.Lock()
	defer index.mu.Unlock()

	index.values[signature] = NewIndexItem(v)
}
func (index *Index) MustSetUnique(signature string, v interface{}) {

	existing := index.GetBySignature(signature)
	if existing != nil {
		panic(Sf("%q already in the index"))
	}

	index.Set(signature, v)
}

// TODO:
// - reject invalid cases (e.g. from receiver to receiver)
// - look for name collisions
func main() {
	var pkg string
	var runServer bool
	flag.StringVar(&pkg, "pkg", "", "package you want to scan and convert to goa types")
	flag.BoolVar(&runServer, "http", false, "run http server")
	flag.Parse()

	// One package at a time:
	sc, err := scanner.New(pkg)
	if err != nil {
		panic(err)
	}

	pks, err := sc.Scan()
	if err != nil {
		panic(err)
	}

	feModule := &FEModule{
		Funcs:            make([]*FEFunc, 0),
		TypeMethods:      make([]*FETypeMethod, 0),
		InterfaceMethods: make([]*FEInterfaceMethod, 0),
	}

	pk := pks[0]
	{
		feModule.Name = pk.Name
		feModule.FEName = pk.Path
		feModule.PkgPath = scanner.RemoveGoSrcClonePath(pk.Path)
		feModule.PkgName = pk.Name

		for _, fn := range pk.Funcs {
			if fn.Receiver == nil {
				f := getFEFunc(fn)
				// TODO: what to do with aliases???
				f.PkgPath = feModule.PkgPath
				feModule.Funcs = append(feModule.Funcs, f)
			}
		}
		for _, mt := range pk.Methods {
			meth := getFETypeMethod(mt, pk.Funcs)
			if meth != nil {
				feModule.TypeMethods = append(feModule.TypeMethods, meth)
			}
		}
		for _, it := range pk.Interfaces {
			feModule.InterfaceMethods = append(feModule.InterfaceMethods, getAllFEInterfaceMethods(it)...)
		}
	}

	// Sort methods by receiver:
	sort.Slice(feModule.TypeMethods, func(i, j int) bool {
		// If same receiver...
		if feModule.TypeMethods[i].Receiver.QualifiedName == feModule.TypeMethods[j].Receiver.QualifiedName {
			// ... sort by func name:
			return feModule.TypeMethods[i].Func.Name < feModule.TypeMethods[j].Func.Name
		}
		return feModule.TypeMethods[i].Receiver.QualifiedName < feModule.TypeMethods[j].Receiver.QualifiedName
	})
	// Sort funcs by name:
	sort.Slice(feModule.Funcs, func(i, j int) bool {
		return feModule.Funcs[i].Name < feModule.Funcs[j].Name
	})

	//Q(feModule)
	Sfln(
		"package %q has %v funcs, %v methods, and %v interfaces",
		pk.Name,
		len(feModule.Funcs),
		len(feModule.TypeMethods),
		len(feModule.InterfaceMethods),
	)

	// Create index, and load values to it:
	index := NewIndex()
	{
		for _, v := range feModule.Funcs {
			index.MustSetUnique(v.Signature, v)
		}
		for _, v := range feModule.TypeMethods {
			index.MustSetUnique(v.Func.Signature, v)
		}
		for _, v := range feModule.InterfaceMethods {
			index.MustSetUnique(v.Func.Signature, v)
		}
	}
	if runServer {
		r := gin.Default()
		r.StaticFile("", "./index.html")
		r.Static("/static", "./static")

		r.GET("/api/source", func(c *gin.Context) {
			c.IndentedJSON(200, feModule)
		})
		r.POST("/api/pointers", func(c *gin.Context) {
			var req PayloadSetPointers
			err := c.BindJSON(&req)
			if err != nil {
				Errorf("error binding JSON: %s", err)
				c.Status(400)
				return
			}
			Q(req)

			if err := req.Validate(); err != nil {
				Errorf("invalid request: %s", err)
				c.Status(400)
				return
			}

			mu.Lock()
			defer mu.Unlock()

			stored := index.GetBySignature(req.Signature)
			if stored == nil {
				Errorf("not found: %q", req.Signature)
				c.Status(404)
				return
			}

			file := NewFile("main")
			{
				// main function:
				file.Func().Id("main").Params().Block()
			}
			{
				// sink function:
				code := Func().
					Id("sink").
					Params(Id("v").Interface()).
					Block()
				file.Add(code.Line())
			}
			{
				// link function (Used in tests to transmit taint from param 0 into param 1):
				code := Func().
					Id("link").
					Params(Id("from").Interface(), Id("into").Interface()).
					Block()
				file.Add(code.Line())
			}
			switch stored.original.(type) {
			case *FEFunc:
				{
					fe := stored.GetFEFunc()
					{
						// validate Inp:
						switch req.Pointers.Inp.Element {
						case ElementParameter:
							if req.Pointers.Inp.Index > len(fe.Parameters)-1 {
								Errorf(
									"Inp index is %v, but func has only %v %ss",
									req.Pointers.Inp.Index,
									len(fe.Parameters),
									req.Pointers.Inp.Element,
								)
								c.Status(400)
								return
							}
						case ElementResult:
							if req.Pointers.Inp.Index > len(fe.Results)-1 {
								Errorf(
									"Inp index is %v, but func has only %v %ss",
									req.Pointers.Inp.Index,
									len(fe.Results),
									req.Pointers.Inp.Element,
								)
								c.Status(400)
								return
							}
						default:
							Errorf("unsupported Element for Inp: %q", req.Pointers.Inp.Element)
							c.Status(400)
							return
						}
						// validate Outp:
						switch req.Pointers.Outp.Element {
						case ElementParameter:
							if req.Pointers.Outp.Index > len(fe.Parameters)-1 {
								Errorf(
									"Outp index is %v, but func has only %v %ss",
									req.Pointers.Outp.Index,
									len(fe.Parameters),
									req.Pointers.Outp.Element,
								)
								c.Status(400)
								return
							}
						case ElementResult:
							if req.Pointers.Outp.Index > len(fe.Results)-1 {
								Errorf(
									"Outp index is %v, but func has only %v %ss",
									req.Pointers.Outp.Index,
									len(fe.Results),
									req.Pointers.Outp.Element,
								)
								c.Status(400)
								return
							}
						default:
							Errorf("unsupported Element for Outp: %q", req.Pointers.Outp.Element)
							c.Status(400)
							return
						}
						// TODO: if Inp and Outp are the same, is that an error?
					}
					fe.CodeQL.Pointers = req.Pointers
					// TODO: bind UI with fe.CodeQL.Pointers
					fe.CodeQL.IsEnabled = true

					code := generate_Func(
						file,
						stored,
						req.Pointers.Inp.Element,
						req.Pointers.Outp.Element,
					)
					if code != nil {
						// TODO: save `code` inside `fe` (add all to the file only at program exit).
						file.Add(code.Line())
					} else {
						Warnf("NOTHING GENERATED")
					}

				}
			case *FETypeMethod:
				{
					fe := stored.GetFETypeMethod()
					{
						// validate Inp:
						switch req.Pointers.Inp.Element {
						case ElementParameter:
							if req.Pointers.Inp.Index > len(fe.Func.Parameters)-1 {
								Errorf(
									"Inp index is %v, but func has only %v %ss",
									req.Pointers.Inp.Index,
									len(fe.Func.Parameters),
									req.Pointers.Inp.Element,
								)
								c.Status(400)
								return
							}
						case ElementResult:
							if req.Pointers.Inp.Index > len(fe.Func.Results)-1 {
								Errorf(
									"Inp index is %v, but func has only %v %ss",
									req.Pointers.Inp.Index,
									len(fe.Func.Results),
									req.Pointers.Inp.Element,
								)
								c.Status(400)
								return
							}
						case ElementReceiver:
							// TODO
						default:
							Errorf("unsupported Element for Inp: %q", req.Pointers.Inp.Element)
							c.Status(400)
							return
						}
						// validate Outp:
						switch req.Pointers.Outp.Element {
						case ElementParameter:
							if req.Pointers.Outp.Index > len(fe.Func.Parameters)-1 {
								Errorf(
									"Outp index is %v, but func has only %v %ss",
									req.Pointers.Outp.Index,
									len(fe.Func.Parameters),
									req.Pointers.Outp.Element,
								)
								c.Status(400)
								return
							}
						case ElementResult:
							if req.Pointers.Outp.Index > len(fe.Func.Results)-1 {
								Errorf(
									"Outp index is %v, but func has only %v %ss",
									req.Pointers.Outp.Index,
									len(fe.Func.Results),
									req.Pointers.Outp.Element,
								)
								c.Status(400)
								return
							}
						case ElementReceiver:
							// TODO
						default:
							Errorf("unsupported Element for Outp: %q", req.Pointers.Outp.Element)
							c.Status(400)
							return
						}
						// TODO: if Inp and Outp are the same, is that an error?
					}
					fe.CodeQL.Pointers = req.Pointers
					// TODO: bind UI with fe.CodeQL.Pointers
					fe.CodeQL.IsEnabled = true

					code := generate_Method(
						file,
						stored,
						req.Pointers.Inp.Element,
						req.Pointers.Outp.Element,
					)
					if code != nil {
						// TODO: save `code` inside `fe` (add all to the file only at program exit).
						file.Add(code.Line())
					} else {
						Warnf("NOTHING GENERATED")
					}
				}
			case *FEInterfaceMethod:
				{
					fe := stored.GetFEInterfaceMethod()
					fe.CodeQL.Pointers = req.Pointers
				}
			default:
				panic(Sf("unknown type for %v", stored.original))
			}
			fmt.Printf("%#v", file)
			c.Status(200)
		})

		r.Run() // listen and serve on 0.0.0.0:8080
	}
}

// ShouldUseAlias tells whether the package name and the base
// of the backage path are the same; if they are not,
// then the package should use an alias in the import.
func ShouldUseAlias(pkgPath string, pkgName string) bool {
	lastSlashAt := strings.LastIndex(pkgPath, "/")
	if lastSlashAt == -1 {
		return pkgPath != pkgName
	}
	return pkgPath[lastSlashAt:] != pkgName
}

func generate_Func(file *File, item *IndexItem, from Element, into Element) *Statement {
	Parameter := ElementParameter
	Result := ElementResult

	switch {
	case from == Parameter && into == Parameter:
		return generate_ParaFuncPara(file, item)
	case from == Parameter && into == Result:
		return generate_ParaFuncResu(file, item)
	case from == Result && into == Parameter:
		return generate_ResuFuncPara(file, item)
	case from == Result && into == Result:
		return generate_ResuFuncResu(file, item)
	default:
		panic(Sf("unhandled case: from %v, into %v", from, into))
	}

	return nil
}

func generate_Method(file *File, item *IndexItem, from Element, into Element) *Statement {
	Receiver := ElementReceiver
	Parameter := ElementParameter
	Result := ElementResult

	switch {
	case from == Receiver && into == Parameter:
		return generate_ReceMethPara(file, item)
	case from == Receiver && into == Result:
		return generate_ReceMethResu(file, item)
	case from == Parameter && into == Receiver:
		return generate_ParaMethRece(file, item)
	case from == Parameter && into == Parameter:
		return generate_ParaMethPara(file, item)
	case from == Parameter && into == Result:
		return generate_ParaMethResu(file, item)
	case from == Result && into == Receiver:
		return generate_ResuMethRece(file, item)
	case from == Result && into == Parameter:
		return generate_ResuMethPara(file, item)
	case from == Result && into == Result:
		return generate_ResuMethResu(file, item)
	default:
		panic(Sf("unhandled case: from %v, into %v", from, into))
	}

	return nil
}

func generate_ReceMethPara(file *File, item *IndexItem) *Statement {
	// from: receiver
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: param
	fe := item.GetFETypeMethod()

	indexIn := fe.CodeQL.Pointers.Inp.Index
	indexOut := fe.CodeQL.Pointers.Outp.Index
	_ = indexIn
	_ = indexOut

	in := fe.Receiver
	out := fe.Func.Parameters[indexOut]

	in.VarName = MustVarNameWithDefaultPrefix(in.VarName, "from")
	out.VarName = MustVarNameWithDefaultPrefix(out.VarName, "into")

	inVarName := in.VarName
	outVarName := out.VarName

	code := Func().Id("TaintStepTest_" + FormatCodeQlName(fe.ClassName)).
		ParamsFunc(
			func(group *Group) {
				group.Add(Id("source").Interface())
			}).
		BlockFunc(
			func(group *Group) {
				group.BlockFunc(
					func(groupCase *Group) {
						groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

						groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
						composeTypeAssertion(file, groupCase, in.VarName, in.original)

						groupCase.Line().Comment(Sf("Declare `%s` variable:", outVarName))
						composeVarDeclaration(file, groupCase, out.VarName, out.original.GetType())

						groupCase.
							Line().Comment("Call medium method that transfers the taint").
							Line().Comment(Sf("from the receiver `%s` to the argument `%s`", in.VarName, out.VarName)).
							Line().Comment(Sf("(`%s` is now tainted).", out.VarName))

						importPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

						groupCase.Id(in.VarName).Dot(fe.Func.Name).CallFunc(
							func(call *Group) {

								tpFun := fe.Func.original.GetType().(*types.Signature)

								zeroVals := scanTupleOfZeroValues(file, tpFun.Params())

								for i, zero := range zeroVals {
									isConsidered := i == indexOut
									if isConsidered {
										call.Id(fe.Func.Parameters[i].VarName)
									} else {
										call.Add(zero)
									}
								}

							},
						)

						groupCase.Line().Comment(Sf("Sink the tainted `%s`:", outVarName))
						groupCase.Id("sink").Call(Id(out.VarName))
					})
			})
	return code.Line()
}
func generate_ReceMethResu(file *File, item *IndexItem) *Statement {
	// from: receiver
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: result
	fe := item.GetFETypeMethod()

	indexIn := fe.CodeQL.Pointers.Inp.Index
	indexOut := fe.CodeQL.Pointers.Outp.Index
	_ = indexIn

	in := fe.Receiver
	out := fe.Func.Results[indexOut]

	in.VarName = MustVarNameWithDefaultPrefix(in.VarName, "from")
	out.VarName = MustVarNameWithDefaultPrefix(out.VarName, "into")

	inVarName := in.VarName
	outVarName := out.VarName

	code := Func().Id("TaintStepTest_" + FormatCodeQlName(fe.ClassName)).
		ParamsFunc(
			func(group *Group) {
				group.Add(Id("source").Interface())
			}).
		BlockFunc(
			func(group *Group) {
				group.BlockFunc(
					func(groupCase *Group) {
						groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

						groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
						composeTypeAssertion(file, groupCase, in.VarName, in.original)

						groupCase.
							Line().Comment("Call medium method that transfers the taint").
							Line().Comment(Sf("from the receiver `%s` to the result `%s`", in.VarName, out.VarName)).
							Line().Comment(Sf("(`%s` is now tainted).", out.VarName))

						importPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

						groupCase.ListFunc(func(resGroup *Group) {
							for i, v := range fe.Func.Results {
								if i == indexOut {
									resGroup.Id(v.VarName)
								} else {
									resGroup.Id("_")
								}
							}
						}).Op(":=").Id(in.VarName).Dot(fe.Func.Name).CallFunc(
							func(call *Group) {

								tpFun := fe.Func.original.GetType().(*types.Signature)

								zeroVals := scanTupleOfZeroValues(file, tpFun.Params())

								for _, zero := range zeroVals {
									call.Add(zero)
								}

							},
						)

						groupCase.Line().Comment(Sf("Sink the tainted `%s`:", outVarName))
						groupCase.Id("sink").Call(Id(out.VarName))
					})
			})
	return code.Line()
}
func generate_ParaMethRece(file *File, item *IndexItem) *Statement {
	// from: param
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: receiver
	fe := item.GetFETypeMethod()

	indexIn := fe.CodeQL.Pointers.Inp.Index
	indexOut := fe.CodeQL.Pointers.Outp.Index
	_ = indexOut

	in := fe.Func.Parameters[indexIn]
	out := fe.Receiver

	in.VarName = MustVarNameWithDefaultPrefix(in.VarName, "from")
	out.VarName = MustVarNameWithDefaultPrefix(out.VarName, "into")

	inVarName := in.VarName
	outVarName := out.VarName

	code := Func().Id("TaintStepTest_" + FormatCodeQlName(fe.ClassName)).
		ParamsFunc(
			func(group *Group) {
				group.Add(Id("source").Interface())
			}).
		BlockFunc(
			func(group *Group) {
				group.BlockFunc(
					func(groupCase *Group) {
						groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

						groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
						composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

						groupCase.Line().Comment(Sf("Declare `%s` variable:", outVarName))
						composeVarDeclaration(file, groupCase, out.VarName, out.original)

						groupCase.
							Line().Comment("Call medium method that transfers the taint").
							Line().Comment(Sf("from the parameter `%s` to the receiver `%s`", in.VarName, out.VarName)).
							Line().Comment(Sf("(`%s` is now tainted).", out.VarName))

						importPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

						groupCase.Id(out.VarName).Dot(fe.Func.Name).CallFunc(
							func(call *Group) {

								tpFun := fe.original.(*types.Signature)

								zeroVals := scanTupleOfZeroValues(file, tpFun.Params())

								for i, zero := range zeroVals {
									isConsidered := i == indexIn
									if isConsidered {
										call.Id(fe.Func.Parameters[i].VarName)
									} else {
										call.Add(zero)
									}
								}

							},
						)

						groupCase.Line().Comment(Sf("Sink the tainted `%s`:", outVarName))
						groupCase.Id("sink").Call(Id(out.VarName))
					})
			})
	return code.Line()
}
func generate_ParaMethPara(file *File, item *IndexItem) *Statement {
	// from: param
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: param
	fe := item.GetFETypeMethod()

	indexIn := fe.CodeQL.Pointers.Inp.Index
	indexOut := fe.CodeQL.Pointers.Outp.Index

	in := fe.Func.Parameters[indexIn]
	out := fe.Func.Parameters[indexOut]

	in.VarName = MustVarNameWithDefaultPrefix(in.VarName, "from")
	out.VarName = MustVarNameWithDefaultPrefix(out.VarName, "into")

	inVarName := in.VarName
	outVarName := out.VarName

	code := Func().Id("TaintStepTest_" + FormatCodeQlName(fe.ClassName)).
		ParamsFunc(
			func(group *Group) {
				group.Add(Id("source").Interface())
			}).
		BlockFunc(
			func(group *Group) {
				group.BlockFunc(
					func(groupCase *Group) {
						groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

						groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
						composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

						groupCase.Line().Comment(Sf("Declare `%s` variable:", outVarName))
						composeVarDeclaration(file, groupCase, out.VarName, out.original.GetType())

						groupCase.Line().Comment("Declare medium object/interface:")
						groupCase.Var().Id("mediumObj").Qual(fe.Receiver.PkgPath, fe.Receiver.TypeName)

						groupCase.
							Line().Comment("Call medium method that transfers the taint").
							Line().Comment(Sf("from the parameter `%s` to the parameter `%s`", in.VarName, out.VarName)).
							Line().Comment(Sf("(`%s` is now tainted).", out.VarName))

						importPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

						groupCase.Id("mediumObj").Dot(fe.Func.Name).CallFunc(
							func(call *Group) {

								tpFun := fe.Func.original.GetType().(*types.Signature)

								zeroVals := scanTupleOfZeroValues(file, tpFun.Params())

								for i, zero := range zeroVals {
									isConsidered := i == indexIn || i == indexOut
									if isConsidered {
										call.Id(fe.Func.Parameters[i].VarName)
									} else {
										call.Add(zero)
									}
								}

							},
						)

						groupCase.Line().Comment(Sf("Sink the tainted `%s`:", outVarName))
						groupCase.Id("sink").Call(Id(out.VarName))
					})
			})
	return code.Line()
}
func generate_ParaMethResu(file *File, item *IndexItem) *Statement {
	// from: param
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: result
	fe := item.GetFETypeMethod()

	indexIn := fe.CodeQL.Pointers.Inp.Index
	indexOut := fe.CodeQL.Pointers.Outp.Index

	in := fe.Func.Parameters[indexIn]
	out := fe.Func.Results[indexOut]

	in.VarName = MustVarNameWithDefaultPrefix(in.VarName, "from")
	out.VarName = MustVarNameWithDefaultPrefix(out.VarName, "into")

	inVarName := in.VarName
	outVarName := out.VarName

	code := Func().Id("TaintStepTest_" + FormatCodeQlName(fe.ClassName)).
		ParamsFunc(
			func(group *Group) {
				group.Add(Id("source").Interface())
			}).
		BlockFunc(
			func(group *Group) {
				group.BlockFunc(
					func(groupCase *Group) {
						groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

						groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
						composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

						groupCase.Line().Comment(Sf("Declare `%s` variable:", outVarName))
						composeVarDeclaration(file, groupCase, out.VarName, out.original.GetType())

						groupCase.Line().Comment("Declare medium object/interface:")
						groupCase.Var().Id("mediumObj").Qual(fe.Receiver.PkgPath, fe.Receiver.TypeName)

						groupCase.
							Line().Comment("Call medium method that transfers the taint").
							Line().Comment(Sf("from the parameter `%s` to the result `%s`", in.VarName, out.VarName)).
							Line().Comment(Sf("(`%s` is now tainted).", out.VarName))

						importPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

						groupCase.ListFunc(func(resGroup *Group) {
							for i, v := range fe.Func.Results {
								if i == indexOut {
									resGroup.Id(v.VarName)
								} else {
									resGroup.Id("_")
								}
							}
						}).Op(":=").Id("mediumObj").Dot(fe.Func.Name).CallFunc(
							func(call *Group) {

								tpFun := fe.Func.original.GetType().(*types.Signature)

								zeroVals := scanTupleOfZeroValues(file, tpFun.Params())

								for i, zero := range zeroVals {
									isConsidered := i == indexIn
									if isConsidered {
										call.Id(fe.Func.Parameters[i].VarName)
									} else {
										call.Add(zero)
									}
								}

							},
						)

						groupCase.Line().Comment(Sf("Sink the tainted `%s`:", outVarName))
						groupCase.Id("sink").Call(Id(out.VarName))
					})
			})
	return code.Line()
}
func generate_ResuMethRece(file *File, item *IndexItem) *Statement {
	// from: result
	// medium: method
	// into: receiver
	fe := item.GetFETypeMethod()

	indexIn := fe.CodeQL.Pointers.Inp.Index
	indexOut := fe.CodeQL.Pointers.Outp.Index
	_ = indexOut

	in := fe.Func.Results[indexIn]
	out := fe.Receiver

	in.VarName = MustVarNameWithDefaultPrefix(in.VarName, "from")
	out.VarName = MustVarNameWithDefaultPrefix(out.VarName, "into")

	inVarName := in.VarName
	outVarName := out.VarName

	code := Func().Id("TaintStepTest_" + FormatCodeQlName(fe.ClassName)).
		ParamsFunc(
			func(group *Group) {
				group.Add(Id("source").Interface())
			}).
		BlockFunc(
			func(group *Group) {
				group.BlockFunc(
					func(groupCase *Group) {
						groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

						groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
						composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

						groupCase.Line().Comment(Sf("Declare `%s` variable:", outVarName))
						composeVarDeclaration(file, groupCase, out.VarName, out.original)

						groupCase.
							Line().Comment("Call medium method that will transfer the taint").
							Line().Comment(Sf("from the result `intermediateCQL` to receiver `%s`:", outVarName))
						groupCase.ListFunc(func(resGroup *Group) {
							for i, _ := range fe.Func.Results {
								if i == indexIn {
									resGroup.Id("intermediateCQL")
								} else {
									resGroup.Id("_")
								}
							}
						}).Op(":=").Id(out.VarName).Dot(fe.Func.Name).CallFunc(
							func(call *Group) {

								tpFun := fe.Func.original.GetType().(*types.Signature)

								zeroVals := scanTupleOfZeroValues(file, tpFun.Params())

								for _, zero := range zeroVals {
									call.Add(zero)
								}

							},
						)

						groupCase.
							Line().Comment(Sf(
							"Extra step (`%s` taints `intermediateCQL`, which taints `%s`:",
							in.VarName,
							out.VarName,
						))
						groupCase.Id("link").Call(Id(in.VarName), Id("intermediateCQL"))

						groupCase.Line().Comment(Sf("Sink the tainted `%s`:", out.VarName))
						groupCase.Id("sink").Call(Id(out.VarName))

					})
			})
	return code.Line()
}
func generate_ResuMethPara(file *File, item *IndexItem) *Statement {
	// from: result
	// medium: method
	// into: parameter
	fe := item.GetFETypeMethod()

	indexIn := fe.CodeQL.Pointers.Inp.Index
	indexOut := fe.CodeQL.Pointers.Outp.Index

	in := fe.Func.Results[indexIn]
	out := fe.Func.Parameters[indexOut]

	in.VarName = MustVarNameWithDefaultPrefix(in.VarName, "from")
	out.VarName = MustVarNameWithDefaultPrefix(out.VarName, "into")

	inVarName := in.VarName
	outVarName := out.VarName

	code := Func().Id("TaintStepTest_" + FormatCodeQlName(fe.ClassName)).
		ParamsFunc(
			func(group *Group) {
				group.Add(Id("source").Interface())
			}).
		BlockFunc(
			func(group *Group) {
				group.BlockFunc(
					func(groupCase *Group) {
						groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

						groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
						composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

						groupCase.Line().Comment(Sf("Declare `%s` variable:", outVarName))
						composeVarDeclaration(file, groupCase, out.VarName, out.original.GetType())

						groupCase.Line().Comment("Declare medium object/interface:")
						groupCase.Var().Id("mediumObj").Qual(fe.Receiver.PkgPath, fe.Receiver.TypeName)

						groupCase.
							Line().Comment("Call medium method that transfers the taint").
							Line().Comment(Sf("from the result `%s` to the parameter `%s`", in.VarName, out.VarName)).
							Line().Comment(Sf("(`%s` is now tainted).", out.VarName))

						importPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

						groupCase.ListFunc(func(resGroup *Group) {
							for i, _ := range fe.Func.Results {
								if i == indexIn {
									resGroup.Id("intermediateCQL")
								} else {
									resGroup.Id("_")
								}
							}
						}).Op(":=").Id("mediumObj").Dot(fe.Func.Name).CallFunc(
							func(call *Group) {

								tpFun := fe.Func.original.GetType().(*types.Signature)

								zeroVals := scanTupleOfZeroValues(file, tpFun.Params())

								for i, zero := range zeroVals {
									isConsidered := i == indexOut
									if isConsidered {
										call.Id(fe.Func.Parameters[i].VarName)
									} else {
										call.Add(zero)
									}
								}

							},
						)
						groupCase.
							Line().Comment(Sf(
							"Extra step (`%s` taints `intermediateCQL`, which taints `%s`:",
							in.VarName,
							out.VarName,
						))
						groupCase.Id("link").Call(Id(in.VarName), Id("intermediateCQL"))

						groupCase.Line().Comment(Sf("Sink the tainted `%s`:", out.VarName))
						groupCase.Id("sink").Call(Id(out.VarName))
					})
			})
	return code.Line()
}
func generate_ResuMethResu(file *File, item *IndexItem) *Statement {
	// from: result
	// medium: method
	// into: result
	fe := item.GetFETypeMethod()

	indexIn := fe.CodeQL.Pointers.Inp.Index
	indexOut := fe.CodeQL.Pointers.Outp.Index

	in := fe.Func.Results[indexIn]
	out := fe.Func.Results[indexOut]

	in.VarName = MustVarNameWithDefaultPrefix(in.VarName, "from")
	out.VarName = MustVarNameWithDefaultPrefix(out.VarName, "into")

	inVarName := in.VarName
	outVarName := out.VarName

	code := Func().Id("TaintStepTest_" + FormatCodeQlName(fe.ClassName)).
		ParamsFunc(
			func(group *Group) {
				group.Add(Id("source").Interface())
			}).
		BlockFunc(
			func(group *Group) {
				group.BlockFunc(
					func(groupCase *Group) {
						groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

						groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
						composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

						groupCase.Line().Comment("Declare medium object/interface:")
						groupCase.Var().Id("mediumObj").Qual(fe.Receiver.PkgPath, fe.Receiver.TypeName)

						groupCase.
							Line().Comment("Call medium method that transfers the taint").
							Line().Comment(Sf("from the result `%s` to the result `%s`", in.VarName, out.VarName)).
							Line().Comment(Sf("(`%s` is now tainted).", out.VarName))

						importPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

						groupCase.ListFunc(func(resGroup *Group) {
							for i, v := range fe.Func.Results {
								if i == indexIn || i == indexOut {
									if i == indexIn {
										resGroup.Id("intermediateCQL")
									} else {
										resGroup.Id(v.VarName)
									}
								} else {
									resGroup.Id("_")
								}
							}
						}).Op(":=").Id("mediumObj").Dot(fe.Func.Name).CallFunc(
							func(call *Group) {

								tpFun := fe.Func.original.GetType().(*types.Signature)

								zeroVals := scanTupleOfZeroValues(file, tpFun.Params())

								for _, zero := range zeroVals {
									call.Add(zero)
								}

							},
						)
						groupCase.
							Line().Comment(Sf(
							"Extra step (`%s` taints `intermediateCQL`, which taints `%s`:",
							in.VarName,
							out.VarName,
						))
						groupCase.Id("link").Call(Id(in.VarName), Id("intermediateCQL"))

						groupCase.Line().Comment(Sf("Sink the tainted `%s`:", out.VarName))
						groupCase.Id("sink").Call(Id(out.VarName))
					})
			})
	return code.Line()
}

func MustVarName(name string) string {
	return MustVarNameWithDefaultPrefix(name, "variable")
}
func MustVarNameWithDefaultPrefix(name string, prefix string) string {
	if prefix == "" {
		prefix = "var"
	}
	if name == "" {
		return Sf("%s%v", prefix, RandomIntRange(111, 999))
	}

	return name
}
func generate_ParaFuncPara(file *File, item *IndexItem) *Statement {
	// from: param
	// medium: func
	// into: param
	fe := item.GetFEFunc()

	indexIn := fe.CodeQL.Pointers.Inp.Index
	indexOut := fe.CodeQL.Pointers.Outp.Index

	in := fe.Parameters[indexIn]
	out := fe.Parameters[indexOut]

	in.VarName = MustVarNameWithDefaultPrefix(in.VarName, "from")
	out.VarName = MustVarNameWithDefaultPrefix(out.VarName, "into")

	inVarName := in.VarName
	outVarName := out.VarName

	code := Func().Id("TaintStepTest_" + FormatCodeQlName(fe.Name)).
		ParamsFunc(
			func(group *Group) {
				group.Add(Id("sourceCQL").Interface())
			}).
		BlockFunc(
			func(group *Group) {
				group.BlockFunc(
					func(groupCase *Group) {
						groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

						groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
						composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

						groupCase.Line().Comment(Sf("Declare `%s` variable:", outVarName))
						composeVarDeclaration(file, groupCase, out.VarName, out.original.GetType())

						groupCase.
							Line().Comment("Call medium method that transfers the taint").
							Line().Comment(Sf("from the parameter `%s` to parameter `%s`;", inVarName, outVarName)).
							Line().Comment(Sf("`%s` is now tainted.", outVarName))

						importPackage(file, fe.PkgPath, fe.PkgName)

						groupCase.Qual(fe.PkgPath, fe.Name).CallFunc(
							func(call *Group) {

								tpFun := fe.original.GetType().(*types.Signature)

								zeroVals := scanTupleOfZeroValues(file, tpFun.Params())

								for i, zero := range zeroVals {
									isConsidered := i == indexIn || i == indexOut
									if isConsidered {
										call.Id(fe.Parameters[i].VarName)
									} else {
										call.Add(zero)
									}
								}

							},
						)

						groupCase.Line().Comment(Sf("Sink the tainted `%s`:", outVarName))
						groupCase.Id("sink").Call(Id(out.VarName))
					})
			})

	return code.Line()
}

func generate_ParaFuncResu(file *File, item *IndexItem) *Statement {
	// from: param
	// medium: func
	// into: result
	fe := item.GetFEFunc()

	indexIn := fe.CodeQL.Pointers.Inp.Index
	indexOut := fe.CodeQL.Pointers.Outp.Index

	in := fe.Parameters[indexIn]
	out := fe.Results[indexOut]

	in.VarName = MustVarNameWithDefaultPrefix(in.VarName, "from")
	out.VarName = MustVarNameWithDefaultPrefix(out.VarName, "into")

	inVarName := in.VarName
	outVarName := out.VarName

	code := Func().Id("TaintStepTest_" + FormatCodeQlName(fe.Name)).
		ParamsFunc(
			func(group *Group) {
				group.Add(Id("sourceCQL").Interface())
			}).
		BlockFunc(
			func(group *Group) {
				group.BlockFunc(
					func(groupCase *Group) {
						groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

						groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
						if in.original.IsVariadic() {
							switch singleType := in.original.GetType().(type) {
							case *types.Slice:
								composeTypeAssertion(file, groupCase, in.VarName, singleType.Elem())
							case *types.Array:
								composeTypeAssertion(file, groupCase, in.VarName, singleType.Elem())
							default:
								panic(Sf("unknown variadic type %v", in.original))
							}
						} else {
							composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())
						}

						groupCase.
							Line().Comment("Call medium method that transfers the taint").
							Line().Comment(Sf("from the parameter `%s` to result `%s`", inVarName, outVarName)).
							Line().Comment(Sf("(`%s` is now tainted).", outVarName))
						groupCase.ListFunc(func(resGroup *Group) {
							for i, v := range fe.Results {
								if i == indexOut {
									resGroup.Id(v.VarName)
								} else {
									resGroup.Id("_")
								}
							}
						}).Op(":=").Qual(fe.PkgPath, fe.Name).CallFunc(
							func(call *Group) {

								tpFun := fe.original.GetType().(*types.Signature)

								zeroVals := scanTupleOfZeroValues(file, tpFun.Params())

								for i, zero := range zeroVals {
									isConsidered := i == indexIn
									if isConsidered {
										call.Id(fe.Parameters[i].VarName)
									} else {
										call.Add(zero)
									}
								}

							},
						)

						groupCase.Line().Comment(Sf("Sink the tainted `%s`:", outVarName))
						groupCase.Id("sink").Call(Id(out.VarName))
					})
			})
	return code.Line()
}
func generate_ResuFuncPara(file *File, item *IndexItem) *Statement {
	// from: result
	// medium: func
	// into: param
	// NOTE: does this actually happen? It needs extra steps, right?

	fe := item.GetFEFunc()

	indexIn := fe.CodeQL.Pointers.Inp.Index
	indexOut := fe.CodeQL.Pointers.Outp.Index

	in := fe.Results[indexIn]
	out := fe.Parameters[indexOut]

	in.VarName = MustVarNameWithDefaultPrefix(in.VarName, "from")
	out.VarName = MustVarNameWithDefaultPrefix(out.VarName, "into")

	inVarName := in.VarName
	outVarName := out.VarName

	code := Func().Id("TaintStepTest_" + FormatCodeQlName(fe.Name)).
		ParamsFunc(
			func(group *Group) {
				group.Add(Id("sourceCQL").Interface())
			}).
		BlockFunc(
			func(group *Group) {
				group.BlockFunc(
					func(groupCase *Group) {
						groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

						groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
						composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

						groupCase.Line().Comment(Sf("Declare `%s` variable:", out.VarName))
						groupCase.Var().Id(out.VarName).Qual(out.PkgPath, out.TypeName)
						importPackage(file, out.PkgPath, out.PkgName)

						groupCase.
							Line().Comment("Call medium method that will transfer the taint").
							Line().Comment(Sf("from the result `intermediateCQL` to parameter `%s`:", outVarName))
						groupCase.ListFunc(func(resGroup *Group) {
							for i, _ := range fe.Results {
								if i == indexIn {
									resGroup.Id("intermediateCQL")
								} else {
									resGroup.Id("_")
								}
							}
						}).Op(":=").Qual(fe.PkgPath, fe.Name).CallFunc(
							func(call *Group) {

								tpFun := fe.original.GetType().(*types.Signature)

								zeroVals := scanTupleOfZeroValues(file, tpFun.Params())

								for i, zero := range zeroVals {
									isConsidered := i == indexOut
									if isConsidered {
										call.Id(fe.Parameters[i].VarName)
									} else {
										call.Add(zero)
									}
								}

							},
						)

						groupCase.
							Line().Comment(Sf(
							"Extra step (`%s` taints `intermediateCQL`, which taints `%s`:",
							in.VarName,
							out.VarName,
						))
						groupCase.Id("link").Call(Id(in.VarName), Id("intermediateCQL"))

						groupCase.Line().Comment(Sf("Sink the tainted `%s`:", out.VarName))
						groupCase.Id("sink").Call(Id(out.VarName))
					})
			})
	return code.Line()
}
func generate_ResuFuncResu(file *File, item *IndexItem) *Statement {
	// from: result
	// medium: func
	// into: result
	fe := item.GetFEFunc()

	indexIn := fe.CodeQL.Pointers.Inp.Index
	indexOut := fe.CodeQL.Pointers.Outp.Index

	in := fe.Results[indexIn]
	out := fe.Results[indexOut]

	in.VarName = MustVarNameWithDefaultPrefix(in.VarName, "from")
	out.VarName = MustVarNameWithDefaultPrefix(out.VarName, "into")

	inVarName := in.VarName
	outVarName := out.VarName

	code := Func().Id("TaintStepTest_" + FormatCodeQlName(fe.Name)).
		ParamsFunc(
			func(group *Group) {
				group.Add(Id("source").Interface())
			}).
		BlockFunc(
			func(group *Group) {
				group.BlockFunc(
					func(groupCase *Group) {
						groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

						groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
						composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

						groupCase.Line().Comment(Sf("Declare `%s` variable:", out.VarName))
						groupCase.Var().Id(out.VarName).Qual(out.PkgPath, out.TypeName)
						importPackage(file, out.PkgPath, out.PkgName)

						groupCase.
							Line().Comment("Call medium func that transfers the taint").
							Line().Comment(Sf("from the result `%s` to result `%s`", inVarName, outVarName)).
							Line().Comment("(extra steps needed)")
						groupCase.ListFunc(func(resGroup *Group) {
							for i, v := range fe.Results {
								if i == indexIn || i == indexOut {
									if i == indexIn {
										resGroup.Id("intermediateCQL")
									} else {
										resGroup.Id(v.VarName)
									}
								} else {
									resGroup.Id("_")
								}
							}
						}).Op(":=").Qual(fe.PkgPath, fe.Name).CallFunc(
							func(call *Group) {

								tpFun := fe.original.GetType().(*types.Signature)

								zeroVals := scanTupleOfZeroValues(file, tpFun.Params())

								for _, zero := range zeroVals {
									call.Add(zero)
								}

							},
						)

						groupCase.
							Line().Comment(Sf(
							"Extra step (`%s` taints `intermediateCQL`, which taints `%s`:",
							in.VarName,
							out.VarName,
						))
						groupCase.Id("link").Call(Id(in.VarName), Id("intermediateCQL"))

						groupCase.Line().Comment(Sf("Sink the tainted `%s`:", out.VarName))
						groupCase.Id("sink").Call(Id(out.VarName))

					})
			})
	return code.Line()
}

func scanTupleOfZeroValues(file *File, tuple *types.Tuple) []Code {

	result := make([]Code, 0)

	for i := 0; i < tuple.Len(); i++ {
		tp := newStatement()

		if tp != nil {
			composeZeroDeclaration(file, tp, tuple.At(i).Type())
			result = append(result, tp)
		}
	}

	return result
}
func composeZeroDeclaration(file *File, stat *Statement, typ types.Type) {
	switch t := typ.(type) {
	case *types.Basic:
		{
			switch t.Name() {
			case "bool":
				{
					stat.Lit(false)
				}
			case "string":
				{
					stat.Lit("")
				}
			case "int", "int8", "int16", "int32", "int64",
				"uint", "uint8", "uint16", "uint32", "uint64",
				"uintptr":
				{
					stat.Lit(0)
				}
			case "float32", "float64":
				{
					stat.Lit(0.0)
				}
			case "byte":
				{
					stat.Lit(0)
				}
			case "rune":
				{
					stat.Lit(0)
				}
			case "complex64", "complex128":
				{
					stat.Lit(0)
				}
			default:
				Errorf("unknown typeName: %q of kind %q", t.String(), t.Kind())
			}
		}
	case *types.Array:
		{
			stat.Nil()
		}
	case *types.Slice:
		{
			stat.Nil()
		}
	case *types.Struct:
		{
			fields := make([]Code, 0)
			for i := 0; i < t.NumFields(); i++ {
				field := t.Field(i)
				fldStm := newStatement()
				fldStm.Id(field.Name())

				importPackage(file, scanner.RemoveGoPath(field.Pkg()), field.Pkg().Name())

				composeZeroDeclaration(file, fldStm, field.Type())
				fields = append(fields, fldStm)
			}
			stat.Struct(fields...).Block()
		}
	case *types.Pointer:
		{
			stat.Nil()
		}
	case *types.Tuple:
		{
			// TODO
			stat.Nil()
		}
	case *types.Signature:
		{
			stat.Nil()
		}
	case *types.Interface:
		{
			stat.Nil()
		}
	case *types.Map:
		{
			stat.Nil()
		}
	case *types.Chan:
		{
			stat.Nil()
		}
	case *types.Named:
		{
			if t.Obj() != nil && t.Obj().Pkg() != nil {
				importPackage(file, scanner.RemoveGoPath(t.Obj().Pkg()), t.Obj().Pkg().Name())
			}

			switch named := t.Underlying().(type) {
			case *types.Basic:
				{
					composeZeroDeclaration(file, stat, named)
				}
			case *types.Array:
				{
					composeZeroDeclaration(file, stat, named)
				}
			case *types.Slice:
				{
					composeZeroDeclaration(file, stat, named)
				}
			case *types.Struct:
				{
					stat.Qual(scanner.RemoveGoPath(t.Obj().Pkg()), t.Obj().Name()).Block()
				}
			case *types.Pointer:
				{
					composeZeroDeclaration(file, stat, named)
				}
			case *types.Tuple:
				{
					composeZeroDeclaration(file, stat, named)
				}
			case *types.Signature:
				{
					composeZeroDeclaration(file, stat, named)
				}
			case *types.Interface:
				{
					composeZeroDeclaration(file, stat, named)
				}
			case *types.Map:
				{
					composeZeroDeclaration(file, stat, named)
				}
			case *types.Chan:
				{
					composeZeroDeclaration(file, stat, named)
				}
			case *types.Named:
				{
					composeZeroDeclaration(file, stat, named)
				}

			}
		}
	}

}

// declare `name := sourceCQL.(Type)`
func composeTypeAssertion(file *File, group *Group, varName string, typ types.Type) {
	assertContent := newStatement()
	composeTypeDeclaration(file, assertContent, typ)
	group.Id(varName).Op(":=").Id("sourceCQL").Assert(assertContent)
}

// declare `var name Type`
func composeVarDeclaration(file *File, group *Group, varName string, typ types.Type) {
	composeTypeDeclaration(file, group.Var().Id(varName), typ)
}
func newStatement() *Statement {
	return &Statement{}
}

func importPackage(file *File, pkgPath string, pkgName string) {
	if pkgPath == "" || pkgName == "" {
		return
	}
	if ShouldUseAlias(pkgPath, pkgName) {
		file.ImportAlias(pkgPath, pkgName)
	} else {
		file.ImportName(pkgPath, pkgName)
	}
}

// composeTypeDeclaration adds the `Type` inside `var name Type`
func composeTypeDeclaration(file *File, stat *Statement, typ types.Type) {
	switch t := typ.(type) {
	case *types.Basic:
		{
			stat.Qual("", t.Name())
		}
	case *types.Array:
		{
			if t.Len() > 0 {
				stat.Index(Lit(t.Len()))
			} else {
				stat.Index()
			}
			composeTypeDeclaration(file, stat, t.Elem())
		}
	case *types.Slice:
		{
			stat.Index()
			composeTypeDeclaration(file, stat, t.Elem())
		}
	case *types.Struct:
		{
			fields := make([]Code, 0)
			for i := 0; i < t.NumFields(); i++ {
				field := t.Field(i)
				fldStm := newStatement()
				fldStm.Id(field.Name())

				importPackage(file, scanner.RemoveGoPath(field.Pkg()), field.Pkg().Name())

				composeTypeDeclaration(file, fldStm, field.Type())
				fields = append(fields, fldStm)
			}
			stat.Struct(fields...)
		}
	case *types.Pointer:
		{
			stat.Op("*")
			composeTypeDeclaration(file, stat, t.Elem())
		}
	case *types.Tuple:
		{
			// TODO
			tuple := scanTupleOfTypes(file, t, false)
			stat.Add(tuple...)
		}
	case *types.Signature:
		{
			paramsTuple := scanTupleOfTypes(file, t.Params(), t.Variadic())
			resultsTuple := scanTupleOfTypes(file, t.Results(), false)

			stat.Func().Params(paramsTuple...).List(resultsTuple...)
		}
	case *types.Interface:
		{
			if t.String() == "error" {
				stat.Qual("", "error")
			} else {
				if t.Empty() {
					stat.Interface()
				} else {
					// TODO
					methods := make([]Code, 0)
					for i := 0; i < t.NumMethods(); i++ {
						meth := t.Method(i)
						fn := newStatement()
						composeTypeDeclaration(file, fn, meth.Type())
						methods = append(methods, fn)
					}
					stat.Interface(methods...)
				}
			}
		}
	case *types.Map:
		{
			mapKey := newStatement()
			composeTypeDeclaration(file, mapKey, t.Key())
			stat.Map(mapKey)
			composeTypeDeclaration(file, stat, t.Elem())
		}
	case *types.Chan:
		{

			switch t.Dir() {
			case types.SendRecv:
				stat.Chan()
			case types.RecvOnly:
				stat.Op("<-").Chan()
			case types.SendOnly:
				stat.Chan().Op("<-")
			}

			composeTypeDeclaration(file, stat, t.Elem())
		}
	case *types.Named:
		{
			if t.Obj().Name() == "error" {
				stat.Error()
			} else {
				if t.Obj() != nil && t.Obj().Pkg() != nil {
					importPackage(file, scanner.RemoveGoPath(t.Obj().Pkg()), t.Obj().Pkg().Name())
					stat.Qual(scanner.RemoveGoPath(t.Obj().Pkg()), t.Obj().Name())
				}
			}
		}
	default:
		panic(typ)
	}

}

func scanTupleOfTypes(file *File, tuple *types.Tuple, isVariadic bool) []Code {

	result := make([]Code, 0)

	for i := 0; i < tuple.Len(); i++ {
		tp := newStatement()

		if tp != nil {
			// If this is the last element,
			// and the function is variadic,
			// then set it to true:
			isLast := i == tuple.Len()-1
			if isLast && isVariadic {
				tp.Op("...")

				switch singleType := tuple.At(i).Type().(type) {
				case *types.Slice:
					composeTypeDeclaration(file, tp, singleType.Elem())
				case *types.Array:
					composeTypeDeclaration(file, tp, singleType.Elem())
				}
			} else {
				composeTypeDeclaration(file, tp, tuple.At(i).Type())
			}
			result = append(result, tp)
		}
	}

	return result
}

type Medium string

const (
	MediumFunc   Medium = "function"
	MediumMethod Medium = "method" // either TypeMethod or InterfaceMethod
)

type PayloadSetPointers struct {
	Signature string
	Pointers  *CodeQLPointers
}

//
func (req *PayloadSetPointers) Validate() error {
	if req.Signature == "" {
		return errors.New("req.Signature is not set")
	}
	if req.Pointers == nil {
		return errors.New("req.Pointers is not set")
	}

	if err := req.Pointers.Validate(); err != nil {
		return err
	}

	return nil
}

func ToCamel(s string) string {
	return strcase.ToCamel(s)
}
func FormatCodeQlName(name string) string {
	return ToCamel(strings.ReplaceAll(name, "\"", ""))
}

const TODO = "TODO"

type CodeQLPointers struct {
	Inp  *Identity
	Outp *Identity
}

func (obj *CodeQLPointers) Validate() error {
	if obj.Inp == nil {
		return errors.New("obj.Inp is not set")
	}
	if obj.Outp == nil {
		return errors.New("obj.Outp is not set")
	}

	if err := obj.Inp.Validate(); err != nil {
		return err
	}
	if err := obj.Outp.Validate(); err != nil {
		return err
	}

	return nil
}
func (obj *Identity) Validate() error {
	if obj.Element == "" || obj.Element == TODO || !IsValidElementName(obj.Element) {
		return errors.New("obj.Element is not set")
	}

	// the Index can be non-valid only for the receiver:
	if obj.Index < 0 && obj.Element != ElementReceiver {
		return errors.New("obj.Index is not set")
	}
	return nil
}

var ValidElementNames = []string{
	string(ElementReceiver),
	string(ElementParameter),
	string(ElementResult),
}

func IsValidElementName(name Element) bool {
	return IsAnyOf(
		string(name),
		ValidElementNames...,
	)
}

func NewCodeQlFinalVals() *CodeQlFinalVals {
	return &CodeQlFinalVals{
		Inp:  TODO,
		Outp: TODO,
		Pointers: &CodeQLPointers{
			Inp: &Identity{
				Element: TODO,
				Index:   -1,
			},
			Outp: &Identity{
				Element: TODO,
				Index:   -1,
			},
		},
	}
}

type CodeQlFinalVals struct {
	Inp       string // string representation of the CodeQlIdentity.Placeholder
	Outp      string // string representation of the CodeQlIdentity.Placeholder
	IsEnabled bool
	Pointers  *CodeQLPointers // Pointers is where the current pointers will be stored
}

type Identity struct {
	Element Element
	Index   int
}
type CodeQlIdentity struct {
	Placeholder string
	Identity
}
type FEModule struct {
	Name             string
	PkgPath          string
	PkgName          string
	FEName           string
	Funcs            []*FEFunc
	TypeMethods      []*FETypeMethod
	InterfaceMethods []*FEInterfaceMethod
}

type FEFunc struct {
	CodeQL    *CodeQlFinalVals
	Signature string
	FEName    string
	Docs      []string
	Name      string
	PkgPath   string
	PkgName   string

	Parameters []*FEType
	Results    []*FEType
	original   *scanner.Func
}

func DocsWithDefault(docs []string) []string {
	if docs == nil {
		docs = make([]string, 0)
	}
	return docs
}

type Element string

const (
	ElementReceiver  Element = "receiver"
	ElementParameter Element = "parameter"
	ElementResult    Element = "result"
)

func getFEFunc(fn *scanner.Func) *FEFunc {
	var fe FEFunc
	fe.original = fn
	fe.CodeQL = NewCodeQlFinalVals()
	fe.Name = fn.Name
	fe.PkgName = fn.PkgName
	fe.FEName = FormatCodeQlName(fn.Name)
	fe.Docs = DocsWithDefault(fn.Doc)
	fe.Signature = RemoveThisPackagePathFromSignature(fn.Signature, fn.PkgPath)
	fe.PkgPath = fn.PkgPath
	for i, in := range fn.Input {
		v := getFEType(in)

		placeholder := Sf("isParameter(%v)", i)
		if v.IsVariadic {
			if len(fn.Input) == 1 {
				placeholder = "isParameter(_)"
			} else {
				placeholder = Sf("isParameter(any(int i | i >= %v))", i)
			}
		}
		isNotLast := i != len(fn.Input)-1
		if v.IsVariadic && isNotLast {
			panic(Sf("parameter %v is variadic but is NOT the last parameter", v))
		}
		v.Identity = CodeQlIdentity{
			Placeholder: placeholder,
			Identity: Identity{
				Element: ElementParameter,
				Index:   i,
			},
		}
		fe.Parameters = append(fe.Parameters, v)
	}
	for i, out := range fn.Output {
		v := getFEType(out)

		if len(fn.Output) == 1 {
			v.Identity = CodeQlIdentity{
				Placeholder: "isResult()",
				Identity: Identity{
					Element: ElementResult,
					Index:   i,
				},
			}
		} else {
			v.Identity = CodeQlIdentity{
				Placeholder: Sf("isResult(%v)", i),
				Identity: Identity{
					Element: ElementResult,
					Index:   i,
				},
			}
		}
		fe.Results = append(fe.Results, v)
	}
	return &fe
}
func RemoveThisPackagePathFromSignature(signature string, pkgPath string) string {
	clean := strings.Replace(signature, pkgPath+".", "", -1)
	return clean
}

type FEType struct {
	Identity      CodeQlIdentity
	VarName       string
	TypeName      string
	PkgName       string
	PkgPath       string
	QualifiedName string
	IsPtr         bool
	IsBasic       bool
	IsVariadic    bool
	IsNullable    bool
	IsStruct      bool
	IsRepeated    bool
	original      scanner.Type
}

func getFEType(tp scanner.Type) *FEType {
	var fe FEType
	fe.original = tp
	varName := tp.GetTypesVar().Name()
	if varName != "" {
		fe.VarName = varName
	}
	fe.IsVariadic = tp.IsVariadic()
	fe.IsNullable = tp.IsNullable()
	fe.IsPtr = tp.IsPtr()
	fe.IsStruct = tp.IsStruct()
	fe.IsBasic = tp.IsBasic()
	fe.IsRepeated = tp.IsRepeated()

	finalType := tp.GetTypesVar().Type()
	{
		slice, ok := tp.GetTypesVar().Type().(*types.Slice)
		if ok {
			finalType = slice.Elem()
		}
	}
	{
		array, ok := tp.GetTypesVar().Type().(*types.Array)
		if ok {
			finalType = array.Elem()
		}
	}
	// Check if pointer:
	{
		pointer, ok := finalType.(*types.Pointer)
		if ok {
			finalType = pointer.Elem()
		}
	}

	{
		named, ok := finalType.(*types.Named)
		if ok {
			fe.TypeName = named.Obj().Name()
			if pkg := named.Obj().Pkg(); pkg != nil {
				fe.QualifiedName = scanner.StringRemoveGoPath(pkg.Path()) + "." + named.Obj().Name()
				fe.PkgPath = scanner.RemoveGoPath(named.Obj().Pkg())
				fe.PkgName = named.Obj().Pkg().Name()
			}
		} else {
			fe.TypeName = tp.TypeString()
		}
	}

	return &fe
}

func getFETypeMethod(mt *types.Selection, allFuncs []*scanner.Func) *FETypeMethod {
	var fe FETypeMethod

	fe.CodeQL = NewCodeQlFinalVals()
	fe.Docs = make([]string, 0)

	fe.Receiver = &FEReceiver{}
	fe.Receiver.Identity = CodeQlIdentity{
		Placeholder: "isReceiver()",
		Identity: Identity{
			Element: ElementReceiver,
			Index:   -1,
		},
	}

	{
		var named *types.Named
		ptr, isPtr := mt.Recv().(*types.Pointer)
		if isPtr {
			named = ptr.Elem().(*types.Named)
		} else {
			named = mt.Recv().(*types.Named)
		}
		fe.Receiver.original = named
		fe.Receiver.TypeName = named.Obj().Name()
		fe.Receiver.QualifiedName = scanner.RemoveGoPath(named.Obj().Pkg()) + "." + named.Obj().Name()
		fe.Receiver.PkgPath = scanner.RemoveGoPath(named.Obj().Pkg())
		//fe.Receiver.VarName =
	}

	fe.Func = &FEFunc{}
	methodFuncName := mt.Obj().Name()

	{
		// Check if the method is on a pointer of a value:
		_, isPtr := mt.Obj().Type().(*types.Signature).Recv().Type().(*types.Pointer)
		if isPtr {
			fe.IsOnPtr = true
		}
	}
	{
		findCorrespondingFunc := func() bool {
			for _, mtFn := range allFuncs {
				if mtFn.Receiver != nil {

					sameReceiverType := fe.Receiver.QualifiedName == mtFn.Receiver.TypeString()
					sameFuncName := methodFuncName == mtFn.Name

					if sameReceiverType && sameFuncName {
						fe.Docs = DocsWithDefault(mtFn.Doc)
						fe.Func = getFEFunc(mtFn)
						fe.original = mtFn.GetType()
						return true
					}
				}
			}
			return false
		}

		found := findCorrespondingFunc()
		if !found {
			return nil
		}
	}

	fe.FEName = fe.Receiver.TypeName + "-" + methodFuncName
	fe.ClassName = FormatCodeQlName(fe.Receiver.TypeName + "-" + methodFuncName)
	return &fe
}

type FETypeMethod struct {
	CodeQL    *CodeQlFinalVals
	ClassName string
	Docs      []string
	IsOnPtr   bool
	Receiver  *FEReceiver
	FEName    string
	Func      *FEFunc
	original  types.Type
}
type FEInterfaceMethod FETypeMethod

type FEReceiver struct {
	FEType
	original *types.Named
}

func getFEInterfaceMethod(it *scanner.Interface, methodFunc *scanner.Func) *FETypeMethod {
	var fe FETypeMethod
	fe.original = it.GetType()

	fe.CodeQL = NewCodeQlFinalVals()

	fe.Receiver = &FEReceiver{}
	fe.Receiver.Identity = CodeQlIdentity{
		Placeholder: "isReceiver()",
		Identity: Identity{
			Element: ElementReceiver,
			Index:   -1,
		},
	}

	feFunc := getFEFunc(methodFunc)
	{

		fe.Receiver.TypeName = it.Name
		fe.Receiver.QualifiedName = scanner.StringRemoveGoPath(feFunc.PkgPath) + "." + feFunc.Name
		fe.Receiver.PkgPath = scanner.StringRemoveGoPath(feFunc.PkgPath)
	}

	fe.Func = &FEFunc{}
	methodFuncName := feFunc.Name

	{
		// Check if the method is on a pointer of a value:
		fe.IsOnPtr = true
	}
	{
		fe.Docs = DocsWithDefault(methodFunc.Doc)
		fe.Func = feFunc
	}

	fe.FEName = fe.Receiver.TypeName + "-" + methodFuncName
	fe.ClassName = FormatCodeQlName(fe.Receiver.TypeName + "-" + methodFuncName)
	return &fe
}
func getAllFEInterfaceMethods(it *scanner.Interface) []*FEInterfaceMethod {

	feInterfaces := make([]*FEInterfaceMethod, 0)
	for _, mt := range it.Methods {

		feMethod := getFEInterfaceMethod(it, mt)
		converted := FEInterfaceMethod(*feMethod)
		feInterfaces = append(feInterfaces, &converted)
	}
	return feInterfaces
}
