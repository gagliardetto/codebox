package main

import (
	"errors"
	"flag"
	"go/types"
	"sort"
	"strings"
	"sync"

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
				return
			}
			Q(req)

			if err := req.Validate(); err != nil {
				Errorf("invalid request: %s", err)
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

			switch stored.original.(type) {
			case *FEFunc:
				fe := stored.GetFEFunc()
				fe.CodeQL.Pointers = req.Pointers
			case *FETypeMethod:
				fe := stored.GetFETypeMethod()
				fe.CodeQL.Pointers = req.Pointers
			case *FEInterfaceMethod:
				fe := stored.GetFEInterfaceMethod()
				fe.CodeQL.Pointers = req.Pointers
			default:
				panic(Sf("unknown type for %v", stored.original))
			}
			c.Status(200)
		})

		r.Run() // listen and serve on 0.0.0.0:8080
	}
}

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
	if obj.Element == "" || obj.Element == TODO {
		return errors.New("obj.Element is not set")
	}

	// the Index can remain the default value only for the receiver:
	if obj.Index == -1 && obj.Element != ElementReceiver {
		return errors.New("obj.Index is not set")
	}
	return nil
}

var ValidElementNames = []string{
	ElementReceiver,
	ElementParameter,
	ElementResult,
}

func IsValidElementName(name string) bool {
	return IsAnyOf(
		name,
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
	Element string
	Index   int
}
type CodeQlIdentity struct {
	Placeholder string
	Identity
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
	Identity      CodeQlIdentity
	VarName       string
	TypeName      string
	PkgPath       string
	QualifiedName string
	IsPtr         bool
	IsBasic       bool
	IsVariadic    bool
}

const (
	ElementReceiver  = "receiver"
	ElementParameter = "parameter"
	ElementResult    = "result"
)

func getFEFunc(fn *scanner.Func) *FEFunc {
	var fe FEFunc
	fe.CodeQL = NewCodeQlFinalVals()
	fe.Name = fn.Name
	fe.FEName = FormatCodeQlName(fn.Name)
	fe.Docs = DocsWithDefault(fn.Doc)
	fe.Signature = RemoveThisPackagePathFromSignature(fn.Signature, fn.PkgPath)
	fe.PkgPath = fn.PkgPath
	for i, in := range fn.Input {
		v := getFETypeVar(in)

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
		v := getFETypeVar(out)

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
func getFETypeVar(tp scanner.Type) *FEType {
	var fe FEType
	varName := tp.GetTypesVar().Name()
	if varName != "" {
		fe.VarName = varName
	}
	fe.IsVariadic = tp.IsVariadic()

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
