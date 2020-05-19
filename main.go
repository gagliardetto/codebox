package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/types"
	"sort"
	"strings"

	"github.com/gagliardetto/codebox/scanner"
	. "github.com/gagliardetto/utils"
	"github.com/gin-gonic/gin"
	"github.com/iancoleman/strcase"
)

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
		Funcs:      make([]*FEFunc, 0),
		Methods:    make([]*FEMethod, 0),
		Interfaces: make([]*FEInterface, 0),
	}

	pk := pks[0]
	{
		feModule.Name = pk.Name
		feModule.FEName = FormatCodeQlName(pk.Name)
		feModule.PkgPath = scanner.TrimThisPath(pk.Path)

		for _, fn := range pk.Funcs {
			if fn.Receiver == nil {
				f := getFEFunc(fn)
				// TODO: what to do with aliases???
				f.PkgPath = feModule.PkgPath
				feModule.Funcs = append(feModule.Funcs, f)
			}
		}
		for _, mt := range pk.Methods {
			feModule.Methods = append(feModule.Methods, getFEMethod(mt, pk.Funcs))
		}
		for _, it := range pk.Interfaces {
			feModule.Interfaces = append(feModule.Interfaces, getFEInterface(it, feModule.PkgPath))
		}
	}

	// Sort methods by receiver:
	sort.Slice(feModule.Methods, func(i, j int) bool {
		// If same receiver...
		if feModule.Methods[i].Receiver.QualifiedName == feModule.Methods[j].Receiver.QualifiedName {
			// ... sort by func name:
			return feModule.Methods[i].Func.Name < feModule.Methods[j].Func.Name
		}
		return feModule.Methods[i].Receiver.QualifiedName < feModule.Methods[j].Receiver.QualifiedName
	})
	// Sort funcs by name:
	sort.Slice(feModule.Funcs, func(i, j int) bool {
		return feModule.Funcs[i].Name < feModule.Funcs[j].Name
	})

	Q(feModule)
	Sfln(
		"package %q has %v funcs, %v methods, and %v interfaces",
		pk.Name,
		len(pk.Funcs),
		len(pk.Methods),
		len(pk.Interfaces),
	)
	if runServer {
		r := gin.Default()
		r.StaticFile("", "./index.html")
		r.Static("/static", "./static")

		r.GET("/api/source", func(c *gin.Context) {
			c.JSON(200, feModule)
		})

		r.Run() // listen and serve on 0.0.0.0:8080
	}
}

func ToCamel(s string) string {
	return strcase.ToCamel(s)
}
func FormatCodeQlName(name string) string {
	return ToCamel(strings.ReplaceAll(name, "\"", ""))
}

type CodeQlFinalVals struct {
	Inp   string
	Outp  string
	IsUse bool
}
type CodeQlPlaceholder struct {
	Val string
}
type FEModule struct {
	Name       string
	PkgPath    string
	FEName     string
	Funcs      []*FEFunc
	Methods    []*FEMethod
	Interfaces []*FEInterface
}

type FEFunc struct {
	CodeQL    *CodeQlFinalVals
	Signature string
	FEName    string
	Docs      []string
	Name      string
	PkgPath   string
	In        []*FEType
	Out       []*FEType
}

type FEType struct {
	Placeholder   CodeQlPlaceholder
	VarName       string
	TypeName      string
	PkgPath       string
	QualifiedName string
	IsPtr         bool
	IsBasic       bool
}

func getFEFunc(fn *scanner.Func) *FEFunc {
	var fe FEFunc
	fe.CodeQL = &CodeQlFinalVals{
		Inp:  "TODO",
		Outp: "TODO",
	}
	fe.Name = fn.Name
	fe.FEName = FormatCodeQlName(fn.Name)
	fe.Docs = fn.Doc
	fe.Signature = RemoveThisPackagePathFromSignature(fn.Signature, fn.PkgPath)
	fe.PkgPath = fn.PkgPath
	for i, in := range fn.Input {
		v := getFETypeVar(in)
		v.Placeholder.Val = Sf("isParameter(%v)", i)
		fe.In = append(fe.In, v)
	}
	for i, out := range fn.Output {
		v := getFETypeVar(out)

		if len(fn.Output) == 1 {
			v.Placeholder.Val = "isResult()"
		} else {
			v.Placeholder.Val = Sf("isResult(%v)", i)
		}
		fe.Out = append(fe.Out, v)
	}
	return &fe
}
func RemoveThisPackagePathFromSignature(signature string, pkgPath string) string {
	clean := strings.Replace(signature, pkgPath+".", "", -1)
	return clean
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
			fe.QualifiedName = scanner.StringRemoveGoPath(pkg.Path()) + "." + named.Obj().Name()
			fe.PkgPath = scanner.RemoveGoPath(named.Obj().Pkg())
		}
	} else {
		fe.TypeName = tp.TypeString()
	}

	return &fe
}

func getFEMethod(mt *types.Selection, allFuncs []*scanner.Func) *FEMethod {
	var fe FEMethod

	fe.CodeQL = &CodeQlFinalVals{
		Inp:  "TODO",
		Outp: "TODO",
	}

	fe.Receiver = &FEReceiver{}
	fe.Receiver.Placeholder.Val = "isReceiver()"
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

	fe.FEName = fe.Receiver.TypeName + "-" + methodFuncName
	fe.ClassName = FormatCodeQlName(fe.Receiver.TypeName + "-" + methodFuncName)
	return &fe
}

type FEMethod struct {
	CodeQL    *CodeQlFinalVals
	ClassName string
	Docs      []string
	IsOnPtr   bool
	Receiver  *FEReceiver
	FEName    string
	Func      *FEFunc
}
type FEInterface struct {
	Docs          []string
	Name          string
	PkgPath       string
	QualifiedName string
	Methods       []*FEMethod
}

type FEReceiver struct {
	FEType
}

func getFEInterfaceMethod(it *scanner.Interface, methodFunc *scanner.Func, pkgPath string) *FEMethod {
	var fe FEMethod

	fe.CodeQL = &CodeQlFinalVals{
		Inp:  "TODO",
		Outp: "TODO",
	}

	fe.Receiver = &FEReceiver{}
	fe.Receiver.Placeholder.Val = "isReceiver()"

	feFunc := getFEFunc(methodFunc)
	feFunc.PkgPath = pkgPath
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
		fe.Docs = methodFunc.Doc
		fe.Func = feFunc
	}

	fe.FEName = fe.Receiver.TypeName + "-" + methodFuncName
	fe.ClassName = FormatCodeQlName(fe.Receiver.TypeName + "-" + methodFuncName)
	return &fe
}
func getFEInterface(it *scanner.Interface, pkgPath string) *FEInterface {
	var fe FEInterface
	pkgPath = scanner.StringRemoveGoPath(pkgPath)

	fe.Name = it.Name
	fe.Docs = it.Doc
	fe.PkgPath = pkgPath
	fe.QualifiedName = scanner.StringRemoveGoPath(pkgPath) + "." + it.Name
	fe.PkgPath = scanner.StringRemoveGoPath(pkgPath)
	for _, mt := range it.Methods {
		fe.Methods = append(fe.Methods, getFEInterfaceMethod(it, mt, pkgPath))
	}
	return &fe
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
