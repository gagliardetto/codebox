package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/types"

	"github.com/gagliardetto/codebox/scanner"
	. "github.com/gagliardetto/utils"
)

func main() {
	var pkg string
	flag.StringVar(&pkg, "pkg", "", "package you want to scan and convert to goa types")
	flag.Parse()

	sc, err := scanner.New(pkg)
	if err != nil {
		panic(err)
	}

	pks, err := sc.Scan()
	if err != nil {
		panic(err)
	}

	for _, pk := range pks {
		Sfln(
			"package %q has %v funcs, %v methods, and %v interfaces",
			pk.Name,
			len(pk.Funcs),
			len(pk.Methods),
			len(pk.Interfaces),
		)
		for _, fn := range pk.Funcs {
			if fn.Receiver == nil {
				Q(getFEFunc(fn))
			}
		}
		Ln("----")
		for _, mt := range pk.Methods {
			Q(getFEMethod(mt, pk.Funcs))
		}
		Ln("----")
		for _, it := range pk.Interfaces {
			Q(getFEInterface(it))
		}
	}
}
func debugMethod(mt *types.Selection) {
	Ln(mt.String())
	Ln(mt.Obj().String())
	Ln(mt.Recv().String())
	Ln(mt.Type().String())

	Ln("selection:", SelectionString(mt, nil))
}

func getFEMethod(mt *types.Selection, allFuncs []*scanner.Func) *FEMethod {
	var fe FEMethod

	fe.Receiver = &FEReceiver{}
	{
		var named *types.Named
		ptr, isPtr := mt.Recv().(*types.Pointer)
		if isPtr {
			named = ptr.Elem().(*types.Named)
		} else {
			named = mt.Recv().(*types.Named)
		}
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
		for _, mtFn := range allFuncs {
			if mtFn.Receiver != nil {

				sameReceiverType := fe.Receiver.QualifiedName == mtFn.Receiver.TypeString()
				sameFuncName := methodFuncName == mtFn.Name

				if sameReceiverType && sameFuncName {
					fe.Docs = mtFn.Doc
					fe.Func = getFEFunc(mtFn)
				}
			}
		}
	}

	return &fe
}

func getFEFunc(fn *scanner.Func) *FEFunc {
	var fe FEFunc
	fe.Name = fn.Name
	fe.Docs = fn.Doc
	for _, in := range fn.Input {
		fe.In = append(fe.In, getFETypeVar(in))
	}
	for _, out := range fn.Output {
		fe.Out = append(fe.Out, getFETypeVar(out))
	}
	return &fe
}
func getFETypeVar(tp scanner.Type) *FEType {
	var fe FEType
	varName := tp.GetTypesVar().Name()
	if varName != "" {
		fe.VarName = varName
	}

	{
		// Check if type is a pointer:
		var typFinal types.Type
		ptr, isPtr := tp.GetTypesVar().Type().(*types.Pointer)
		if isPtr {
			fe.IsPtr = true
			typFinal = ptr.Elem()
		} else {
			typFinal = tp.GetTypesVar().Type()
		}

		_, isBasic := typFinal.(*types.Basic)
		if isBasic {
			fe.IsBasic = true
		}
	}

	named, ok := tp.GetTypesVar().Type().(*types.Named)
	if ok {
		fe.TypeName = named.Obj().Name()
		if pkg := named.Obj().Pkg(); pkg != nil {
			fe.QualifiedName = pkg.Path() + "." + named.Obj().Name()
			fe.PkgPath = scanner.RemoveGoPath(named.Obj().Pkg())
		}
	} else {
		fe.TypeName = tp.TypeString()
	}

	return &fe
}

func getFEInterface(it *scanner.Interface) *FEInterface {
	var fe FEInterface
	fe.Name = it.Name
	fe.Docs = it.Doc
	for _, mt := range it.Methods {
		fe.Methods = append(fe.Methods, getFEFunc(mt))
	}
	return &fe
}

type FEInterface struct {
	Docs    []string
	Name    string
	Methods []*FEFunc
}
type FEMethod struct {
	Docs     []string
	IsOnPtr  bool
	Receiver *FEReceiver
	Func     *FEFunc
}

type FEFunc struct {
	Docs []string
	Name string
	In   []*FEType
	Out  []*FEType
}

type FEReceiver struct {
	FEType
}

type FEType struct {
	VarName       string
	TypeName      string
	PkgPath       string
	QualifiedName string
	IsPtr         bool
	IsBasic       bool
}

func SelectionString(s *types.Selection, qf types.Qualifier) string {
	var k string
	switch s.Kind() {
	case types.FieldVal:
		k = "field "
	case types.MethodVal:
		k = "method "
	case types.MethodExpr:
		k = "method expr "
	default:
		panic("unreachable()")
	}
	var buf bytes.Buffer
	buf.WriteString(k)
	buf.WriteByte('(')
	types.WriteType(&buf, s.Recv(), qf)
	fmt.Fprintf(&buf, ") %s", s.Obj().Name())
	if T := s.Type(); s.Kind() == types.FieldVal {
		buf.WriteByte(' ')
		types.WriteType(&buf, T, qf)
	} else {
		types.WriteSignature(&buf, T.(*types.Signature), qf)
	}
	return buf.String()
}

func debugTypeAsVar(tp scanner.Type) {
	varName := tp.GetTypesVar().Name()
	if varName != "" {
		Ln(PurpleBG(varName))
	} else {
		Ln(PurpleBG("UNNAMED"))
	}

	named, ok := tp.GetTypesVar().Type().(*types.Named)
	if ok {
		Q("named package:", named.Obj().Pkg().Name())
		Q("named package:", named.Obj().Pkg().Path())
		Q("named package:", named.Obj().Pkg().Scope().Names())
	} else {
		Ln("NOT NAMED PACKAGE")
	}
	Ln(" ", tp.TypeString())
}
