// Extracted from: gopkg.in/src-d/proteus.v1/scanner
package scanner

import (
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	pkgerrors "github.com/pkg/errors"
	"golang.org/x/tools/go/packages"
	"gopkg.in/src-d/proteus.v1/report"

	parseutil "gopkg.in/src-d/go-parse-utils.v1"
)

var goPath = os.Getenv("GOPATH")

// Scanner scans packages looking for Go source files to parse
// and extract types and structs from.
type Scanner struct {
	packages []string
	importer *parseutil.Importer
}

// ErrNoGoPathSet is the error returned when the GOPATH variable is not
// set.
var ErrNoGoPathSet = errors.New("GOPATH environment variable is not set")

// New creates a new Scanner that will look for types and structs
// only in the given packages.
func New(addGoPath bool, packages ...string) (*Scanner, error) {
	if goPath == "" {
		return nil, ErrNoGoPathSet
	}

	for _, pkg := range packages {
		p := pkg
		if addGoPath {
			p = filepath.Join(goPath, "src", pkg)
		}
		fi, err := os.Stat(p)
		switch {
		case err != nil:
			return nil, err
		case !fi.IsDir():
			return nil, fmt.Errorf("path is not directory: %s", p)
		}
	}

	return &Scanner{
		packages: packages,
		importer: parseutil.NewImporter(),
	}, nil
}

// Scan retrieves the scanned packages containing the extracted
// go types and structs.
func (s *Scanner) Scan() ([]*Package, error) {
	var (
		pkgs   = make([]*Package, len(s.packages))
		errors errorList
		mut    sync.Mutex
		wg     = new(sync.WaitGroup)
	)

	wg.Add(len(s.packages))
	for i, p := range s.packages {
		go func(p string, i int) {
			defer wg.Done()

			pkg, err := s.scanPackage(p)
			mut.Lock()
			defer mut.Unlock()
			if err != nil {
				errors.add(fmt.Errorf("error scanning package %q: %s", p, err))
				return
			}

			pkgs[i] = pkg
		}(p, i)
	}

	wg.Wait()
	if len(errors) > 0 {
		return nil, errors.err()
	}

	return pkgs, nil
}

func scanPackage(path string) (*packages.Package, error) {
	// NEW way of parsing a go package:
	//path = "/usr/local/go/src/net"
	fmt.Println(path)

	config := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedExportsFile |
			packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedTypesSizes,
		//Dir:  path,
	}
	pkgs, err := packages.Load(config, path)
	if err != nil {
		return nil, pkgerrors.Wrapf(err, "Error loading package %s", path)
	}

	return pkgs[0], nil
}
func (s *Scanner) scanPackage(p string) (*Package, error) {
	pkg, err := scanPackage(p)
	if err != nil {
		return nil, fmt.Errorf("error while scanPackage: %s", err)
	}

	ctx, err := newContext(pkg.Syntax)
	if err != nil {
		return nil, err
	}

	return buildPackage(ctx, pkg.Types)
}

func buildPackage(ctx *context, gopkg *types.Package) (*Package, error) {
	objs := objectsInScope(gopkg.Scope())

	pkg := &Package{
		Path:    RemoveGoPath(gopkg),
		Name:    gopkg.Name(),
		Aliases: make(map[string]Type),
	}

	pkg.Methods = methodsInScope(gopkg.Scope())

	for _, o := range objs {
		if err := pkg.scanObject(ctx, o); err != nil {
			return nil, err
		}
	}

	pkg.collectEnums(ctx)
	return pkg, nil
}

func (p *Package) scanObject(ctx *context, o types.Object) error {
	if !o.Exported() {
		return nil
	}

	// Scan interface types:
	switch t := o.Type().Underlying().(type) {
	case *types.Interface:

		if !token.IsExported(NameForType(o.Type())) {
			break
		}

		it := scanInterface(&Interface{Name: NameForType(o.Type())}, t, ctx.trySetDocsForInterfaceMethod)
		ctx.trySetDocs(NameForType(o.Type()), it)

		it.SetType(o.Type())
		p.Interfaces = append(p.Interfaces, it)
	}

	// Scan other types:
	switch t := o.Type().(type) {

	case *types.Named:
		hasStringMethod, err := isStringer(t)
		if err != nil {
			return err
		}
		switch o.(type) {
		case *types.Const:
			if _, ok := t.Underlying().(*types.Basic); ok {
				scanEnumValue(ctx, o.Name(), t, hasStringMethod)
			}
		case *types.TypeName:
			if s, ok := t.Underlying().(*types.Struct); ok {

				st := scanStruct(
					&Struct{
						Name:       o.Name(),
						Generate:   ctx.shouldGenerateType(o.Name()),
						IsStringer: hasStringMethod,
						Methods:    methodsForNamed(t),
						Type:       t,
					},
					s,
				)

				ctx.trySetDocs(o.Name(), st)
				p.Structs = append(p.Structs, st)
				return nil
			}

			p.Aliases[objName(t.Obj())] = scanType(t.Underlying())
		}
	case *types.Signature:
		if o.Exported() {
			fn := scanFunc(&Func{Name: o.Name()}, t)
			fn.Signature = StringRemoveGoPath(o.String())
			fn.PkgPath = RemoveGoPath(o.Pkg())
			if o.Pkg() != nil {
				fn.PkgName = o.Pkg().Name()
			}
			ctx.trySetDocs(nameForFunc(o), fn)
			p.Funcs = append(p.Funcs, fn)
		}

	}

	return nil
}

func isStringer(t *types.Named) (bool, error) {
	for i := 0; i < t.NumMethods(); i++ {
		m := t.Method(i)
		if m.Name() != "String" {
			continue
		}

		sign := m.Type().(*types.Signature)
		if sign.Params().Len() != 0 {
			return false, fmt.Errorf("type %s implements a String method that does not satisfy fmt.Stringer (wrong number of parameters)", t.Obj().Name())
		}

		results := sign.Results()
		if results == nil || results.Len() != 1 {
			return false, fmt.Errorf("type %s implements a String method that does not satisfy fmt.Stringer (wrong number of results)", t.Obj().Name())
		}

		if returnType, ok := results.At(0).Type().(*types.Basic); ok {
			if returnType.Name() == "string" {
				return true, nil
			}
			return false, fmt.Errorf("type %s implements a String method that does not satisfy fmt.Stringer (wrong type of result)", t.Obj().Name())
		}
	}

	return false, nil
}

// IsValidatable tells whether a type has a
// Validate() error
// method.
func IsValidatable(t *types.Named) (bool, error) {
	for i := 0; i < t.NumMethods(); i++ {
		m := t.Method(i)
		if m.Name() != "Validate" {
			continue
		}

		sign := m.Type().(*types.Signature)
		if sign.Params().Len() != 0 {
			return false, fmt.Errorf("type %s implements a Validate method that does not satisfy Validate (wrong number of parameters)", t.Obj().Name())
		}

		results := sign.Results()
		if results == nil || results.Len() != 1 {
			return false, fmt.Errorf("type %s implements a Validate method that does not satisfy Validate (wrong number of results)", t.Obj().Name())
		}

		if results.At(0).Type().String() == "error" {
			return true, nil
		} else {
			return false, fmt.Errorf("type %s implements a Validate method that does not satisfy Validate (wrong type of result)", t.Obj().Name())
		}
	}

	return false, nil
}

func methodsForNamed(t *types.Named) []*types.Func {
	methods := make([]*types.Func, 0)
	for i := 0; i < t.NumMethods(); i++ {
		meth := t.Method(i)
		if !meth.Exported() {
			continue
		}
		methods = append(methods, meth)
	}
	return methods
}

func nameForFunc(o types.Object) (name string) {
	s := o.Type().(*types.Signature)

	if s.Recv() != nil {
		name = NameForType(s.Recv().Type()) + "."
	}

	name = name + o.Name()

	return
}

func NameForType(o types.Type) (name string) {
	name = o.String()
	i := strings.LastIndex(name, ".")
	name = name[i+1:]

	return
}

func setTypeParameters(typ types.Type, t Type) {
	switch typ.(type) {
	case *types.Basic:
		{
			t.SetIsBasic(true)
		}
	case *types.Array:
		{
			t.SetNullable(true)
		}
	case *types.Slice:
		{
			t.SetNullable(true)
		}
	case *types.Struct:
		{
			t.SetIsStruct(true)
		}
	case *types.Pointer:
		{
			t.SetNullable(true)
		}
	case *types.Tuple:
		{
			// TODO
			t.SetNullable(true)
		}
	case *types.Signature:
		{
			t.SetNullable(true)
		}
	case *types.Interface:
		{
			t.SetNullable(true)
		}
	case *types.Map:
		{
			t.SetNullable(true)
		}
	case *types.Chan:
		{
			t.SetNullable(true)
		}
	case *types.Named:
		{
			// TODO
			setTypeParameters(typ.Underlying(), t)
		}
	}
}
func scanType(typ types.Type) (t Type) {
	// Basic
	// Array
	// Slice
	// Struct
	// Pointer
	// Tuple //TODO
	// Signature
	// Interface
	// Map
	// Chan
	// Named
	switch u := typ.(type) {
	case *types.Basic:
		t = NewBasic(u.Name())
	case *types.Named:
		t = NewNamed(
			RemoveGoPath(u.Obj().Pkg()),
			u.Obj().Name(),
		)

		// TODO: use in other switch case, too:
		setTypeParameters(typ.Underlying(), t)

	case *types.Struct:
		st := &Struct{}
		st.BaseType = newBaseType()
		st.AnonymousType = u
		t = scanStruct(st, u)
		t.SetNullable(false)
		//t.SetIsPtr(false) //TODO: see note for *types.Array
		t.SetIsStruct(true)
	case *types.Slice:
		t = scanType(u.Elem())
		t.SetNullable(true)
		//t.SetIsPtr(false) //TODO: see note for *types.Array
		t.SetIsStruct(false)
	case *types.Array:
		t = scanType(u.Elem())
		t.SetNullable(true)
		//t.SetIsPtr(false) // TODO: what if *[]*SomeType or *[]SomeType ???
		t.SetIsStruct(false)
	case *types.Pointer:
		t = scanType(u.Elem())
		t.SetNullable(true)
		t.SetIsPtr(true)
	case *types.Chan:
		t = NewChan(u)
		t.SetNullable(true)
		t.SetIsPtr(false)
		t.SetIsStruct(false)
	case *types.Interface:
		it := scanInterface(&Interface{Name: u.String()}, u, nil)
		t = Type(it)
		t.SetNullable(true)
		t.SetIsPtr(false)
		t.SetIsStruct(false)
	case *types.Signature:

		neF := &Func{
			BaseType: newBaseType(),
		}
		fn := scanFunc(
			neF,
			u,
		)
		fn.Signature = StringRemoveGoPath(u.String())
		//fn.PkgPath = RemoveGoPath(u.Pkg())
		//fn.PkgName = u.Pkg().Name()
		t = Type(fn)
		t.SetNullable(true)
		t.SetIsPtr(false)
		t.SetIsStruct(false)
	case *types.Map:
		key := scanType(u.Key())
		val := scanType(u.Elem())
		if val == nil {
			report.Warn("ignoring map with value type %s", typ.String())
			return nil
		}
		t = NewMap(key, val)
		t.SetNullable(true)
	default:
		report.Warn("ignoring type %s", typ.String())
		return nil
	}

	t.SetType(typ)

	return
}

func scanEnumValue(ctx *context, name string, named *types.Named, hasStringMethod bool) {
	typ := objName(named.Obj())
	ctx.enumValues[typ] = append(ctx.enumValues[typ], name)
	ctx.enumWithString = append(ctx.enumWithString, typ)
}

func scanStruct(s *Struct, elem *types.Struct) *Struct {

	for i := 0; i < elem.NumFields(); i++ {
		v := elem.Field(i)
		tags := findProtoTags(elem.Tag(i))

		if isIgnoredField(v, tags) {
			continue
		}

		// TODO: It has not been decided yet what exact behaviour
		// is the intended when a struct overrides a field from
		// a previously embedded type. For now, the field is just
		// completely ignored and a warning is printed to give
		// feedback to the user.
		if s.HasField(v.Name()) {
			report.Warn("struct %q already has a field %q", s.Name, v.Name())
			continue
		}

		if v.Anonymous() {
			embedded := findStruct(v.Type())
			if embedded == nil {
				report.Warn("field %q with type %q is not a valid embedded type", v.Name(), v.Type())
			} else {
				s = scanStruct(s, embedded)
			}
			continue
		}

		f := &Field{
			Name: v.Name(),
			Type: scanType(v.Type()),
		}
		if f.Type == nil {
			continue
		}

		s.Fields = append(s.Fields, f)
	}

	return s
}

func scanFunc(fn *Func, signature *types.Signature) *Func {
	if signature.Recv() != nil {
		fn.Receiver = scanType(signature.Recv().Type())
	}

	if fn.BaseType == nil {
		fn.BaseType = newBaseType()
	}

	fn.SetType(signature)
	fn.SetIsVariadic(signature.Variadic())

	fn.Input = scanTuple(signature.Params(), signature.Variadic())
	fn.Output = scanTuple(signature.Results(), false)
	fn.Variadic = signature.Variadic()

	return fn
}
func scanInterface(it *Interface, t *types.Interface, docSetter func(it string, method string, obj Documentable)) *Interface {
	it.BaseType = newBaseType()

ExplicitMethodLoop:
	for i := 0; i < t.NumExplicitMethods(); i++ {

		methObj := t.ExplicitMethod(i)
		meth := methObj.Type()

		if !methObj.Exported() {
			continue ExplicitMethodLoop
		}

		fn := scanFunc(
			&Func{Name: methObj.Name()},
			meth.(*types.Signature),
		)
		fn.Signature = StringRemoveGoPath(methObj.String())
		fn.PkgPath = RemoveGoPath(methObj.Pkg())
		fn.PkgName = methObj.Pkg().Name()

		if docSetter != nil {
			docSetter(
				it.Name,
				methObj.Name(),
				fn,
			)
		}

		it.Methods = append(it.Methods, fn)
	}
	return it
}

func scanTuple(tuple *types.Tuple, isVariadic bool) []Type {
	result := make([]Type, 0, tuple.Len())

	for i := 0; i < tuple.Len(); i++ {
		typVar := tuple.At(i)
		tp := scanType(tuple.At(i).Type())
		if tp != nil {
			tp.SetTypesVar(typVar)

			// If this is the last element,
			// and the function is variadic,
			// then set it to true:
			isLast := i == tuple.Len()-1
			if isLast && isVariadic {
				tp.SetIsVariadic(true)
			}
			result = append(result, tp)
		}
	}

	return result
}

func findStruct(t types.Type) *types.Struct {
	switch elem := t.(type) {
	case *types.Pointer:
		return findStruct(elem.Elem())
	case *types.Named:
		return findStruct(elem.Underlying())
	case *types.Struct:
		return elem
	default:
		return nil
	}
}

// newEnum creates a new enum with the given name.
// The values are looked up in the ast package and only if they are constants
// they will be added as enum values.
// All values are guaranteed to be sorted by their iota.
func newEnum(ctx *context, name string, vals []string, hasStringMethod bool) *Enum {
	enum := &Enum{Name: name, IsStringer: hasStringMethod}
	ctx.trySetDocs(name, enum)
	var values enumValues
	for _, v := range vals {
		if obj, ok := ctx.consts[v]; ok {
			values = append(values, enumValue{
				name: v,
				pos:  uint(obj.Data.(int)),
			})
		}
	}

	sort.Stable(values)

	for _, v := range values {
		val := &EnumValue{Name: v.name}
		ctx.trySetDocs(v.name, val)
		enum.Values = append(enum.Values, val)
	}

	return enum
}

type enumValue struct {
	name string
	pos  uint
}

type enumValues []enumValue

func (v enumValues) Swap(i, j int) {
	v[j], v[i] = v[i], v[j]
}

func (v enumValues) Len() int {
	return len(v)
}

func (v enumValues) Less(i, j int) bool {
	return v[i].pos < v[j].pos
}

func isIgnoredField(f *types.Var, tags []string) bool {
	return !f.Exported() || (len(tags) > 0 && tags[0] == "-")
}

func objectsInScope(scope *types.Scope) (objs []types.Object) {
	for _, n := range scope.Names() {
		obj := scope.Lookup(n)
		objs = append(objs, obj)

		typ := obj.Type()

		if _, ok := typ.Underlying().(*types.Struct); ok {
			// Only need to extract methods for the pointer type since it contains
			// the methods for the non-pointer type as well.
			objs = append(objs, methodsForType(types.NewPointer(typ))...)
		} else {
			objs = append(objs, methodsForType(types.NewPointer(typ))...)
		}

	}
	return
}

func methodsInScope(scope *types.Scope) (objs []*types.Selection) {
	for _, n := range scope.Names() {
		if !token.IsExported(n) {
			continue
		}
		obj := scope.Lookup(n)

		typ := obj.Type()

		if !obj.Exported() {
			continue
		}

		if _, ok := typ.Underlying().(*types.Struct); ok {
			// Only need to extract methods for the pointer type since it contains
			// the methods for the non-pointer type as well.
			objs = append(objs, methodNamesForType(types.NewPointer(typ))...)
		} else {
			objs = append(objs, methodNamesForType(types.NewPointer(typ))...)
		}
	}
	return
}
func methodNamesForType(typ types.Type) (objs []*types.Selection) {
	methods := types.NewMethodSet(typ)

	for i := 0; i < methods.Len(); i++ {
		objs = append(objs, methods.At(i))
	}

	return
}

func methodsForType(typ types.Type) (objs []types.Object) {
	methods := types.NewMethodSet(typ)

	for i := 0; i < methods.Len(); i++ {
		objs = append(objs, methods.At(i).Obj())
	}

	return
}

func objName(obj types.Object) string {
	return fmt.Sprintf("%s.%s", RemoveGoPath(obj.Pkg()), obj.Name())
}

func RemoveGoPath(pkg *types.Package) string {
	// error is a type.Named whose package is nil.
	if pkg == nil {
		return ""
	} else {
		return StringRemoveGoPath(pkg.Path())
	}
}
func StringRemoveGoPath(pkgPath string) string {
	clean := strings.Replace(pkgPath, filepath.Join(goPath, "src")+"/", "", -1)
	return RemoveGoSrcClonePath(clean)
}
func RemoveGoSrcClonePath(pkgPath string) string {
	clean := strings.Replace(pkgPath, "github.com/gagliardetto/codebox/src/", "", -1)
	return clean
}

type errorList []error

func (l *errorList) add(err error) {
	*l = append(*l, err)
}

func (l errorList) err() error {
	var lines []string
	for _, err := range l {
		lines = append(lines, err.Error())
	}
	return errors.New(strings.Join(lines, "\n"))
}
