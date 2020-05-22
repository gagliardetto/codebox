package main

import (
	"flag"
	"go/types"
	"sort"
	"strings"

	"github.com/gagliardetto/codebox/scanner"
	. "github.com/gagliardetto/utils"
	"github.com/gin-gonic/gin"
	"github.com/iancoleman/strcase"
)

type StorageItem struct {
	originalFunc      *FEFunc
	originalMethod    *FETypeMethod
	originalInterface *FEInterfaceMethod
}
type Storage struct {
	values map[string]*StorageItem
}

func NewStorage() *Storage {
	return &Storage{
		values: make(map[string]*StorageItem),
	}
}

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
			feModule.InterfaceMethods = append(feModule.InterfaceMethods, getAllFEInterfaceMethods(it, feModule.PkgPath)...)
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

	Q(feModule)
	Sfln(
		"package %q has %v funcs, %v methods, and %v interfaces",
		pk.Name,
		len(feModule.Funcs),
		len(feModule.TypeMethods),
		len(feModule.InterfaceMethods),
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
	Name             string
	PkgPath          string
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

	Parameters []*FEType
	Results    []*FEType
}

func DocsWithDefault(docs []string) []string {
	if docs == nil {
		docs = make([]string, 0)
	}
	return docs
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
	fe.Docs = DocsWithDefault(fn.Doc)
	fe.Signature = RemoveThisPackagePathFromSignature(fn.Signature, fn.PkgPath)
	fe.PkgPath = fn.PkgPath
	for i, in := range fn.Input {
		v := getFETypeVar(in)
		v.Placeholder.Val = Sf("isParameter(%v)", i)
		fe.Parameters = append(fe.Parameters, v)
	}
	for i, out := range fn.Output {
		v := getFETypeVar(out)

		if len(fn.Output) == 1 {
			v.Placeholder.Val = "isResult()"
		} else {
			v.Placeholder.Val = Sf("isResult(%v)", i)
		}
		fe.Results = append(fe.Results, v)
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

func getFETypeMethod(mt *types.Selection, allFuncs []*scanner.Func) *FETypeMethod {
	var fe FETypeMethod

	fe.CodeQL = &CodeQlFinalVals{
		Inp:  "TODO",
		Outp: "TODO",
	}
	fe.Docs = make([]string, 0)

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
		findCorrespondingFunc := func() bool {
			for _, mtFn := range allFuncs {
				if mtFn.Receiver != nil {

					sameReceiverType := fe.Receiver.QualifiedName == mtFn.Receiver.TypeString()
					sameFuncName := methodFuncName == mtFn.Name

					if sameReceiverType && sameFuncName {
						fe.Docs = DocsWithDefault(mtFn.Doc)
						fe.Func = getFEFunc(mtFn)
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
}
type FEInterfaceMethod struct {
	FETypeMethod
}

type FEReceiver struct {
	FEType
}

func getFEInterfaceMethod(it *scanner.Interface, methodFunc *scanner.Func, pkgPath string) *FETypeMethod {
	var fe FETypeMethod

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
		fe.Docs = DocsWithDefault(methodFunc.Doc)
		fe.Func = feFunc
	}

	fe.FEName = fe.Receiver.TypeName + "-" + methodFuncName
	fe.ClassName = FormatCodeQlName(fe.Receiver.TypeName + "-" + methodFuncName)
	return &fe
}
func getAllFEInterfaceMethods(it *scanner.Interface, pkgPath string) []*FEInterfaceMethod {
	pkgPath = scanner.StringRemoveGoPath(pkgPath)

	feInterfaces := make([]*FEInterfaceMethod, 0)
	for _, mt := range it.Methods {

		feMethod := getFEInterfaceMethod(it, mt, pkgPath)
		feInterfaces = append(feInterfaces, &FEInterfaceMethod{*feMethod})
	}
	return feInterfaces
}
