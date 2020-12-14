// Extracted from: gopkg.in/src-d/proteus.v1/scanner
package scanner

import (
	"errors"
	"fmt"
	"go/types"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/gagliardetto/golang-go/cmd/go/not-internal/get"
	"github.com/gagliardetto/golang-go/cmd/go/not-internal/modfetch"
	"github.com/gagliardetto/golang-go/cmd/go/not-internal/search"
	"github.com/gagliardetto/golang-go/cmd/go/not-internal/web"
	. "github.com/gagliardetto/utilz"
	pkgerrors "github.com/pkg/errors"
	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"
	"gopkg.in/src-d/proteus.v1/report"

	parseutil "gopkg.in/src-d/go-parse-utils.v1"
)

// TODO: https://github.com/golang/tools/blob/f1b4bd93c9465ac3d4edf2a53caf28cd21f846aa/go/ssa/example_test.go

var goPath = os.Getenv("GOPATH")

const (
	// Use default Golang proxy (???)
	GoProxy = "https://proxy.golang.org/"
)

// Scanner scans packages looking for Go source files to parse
// and extract types and structs from.
type Scanner struct {
	packages []string
	importer *parseutil.Importer
}

// ErrNoGoPathSet is the error returned when the GOPATH variable is not
// set.
var ErrNoGoPathSet = errors.New("GOPATH environment variable is not set")

// SplitPathVersion splits a path string (e.g. example.com/hello/world@1.0.1) into
// its path and version components. If no version notation is present, rawPath is returned.
func SplitPathVersion(rawPath string) (path string, version string) {
	if i := strings.Index(rawPath, "@"); i >= 0 {
		return rawPath[:i], rawPath[i+1:]
	}
	return rawPath, ""
}

// New creates a new Scanner that will look for types and structs
// only in the given packages.
func NewDEPRECATED(addGoPath bool, packages ...string) (*Scanner, error) {
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

// New creates a new Scanner that will look for types and structs
// only in the given packages. A provided package path can be
// in the form `path@version`, or just `path` and the latest version will be used.
// For Go standard library packages, the local version is used (must have Go installed).
func New(packages ...string) (*Scanner, error) {
	return &Scanner{
		packages: packages,
		importer: parseutil.NewImporter(),
	}, nil
}

// ScanWithCustomScanner retrieves the scanned packages containing the extracted
// go types and structs; it uses the provided ScannerFunc.
func (s *Scanner) ScanWithCustomScanner(sc ScannerFunc) ([]*Package, error) {
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

			pkg, err := s.scanPackageWithScanner(p, sc)
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

// Scan retrieves the scanned packages containing the extracted
// go types and structs.
func (s *Scanner) Scan() ([]*Package, error) {
	return s.ScanWithCustomScanner(defaultModuleScannerFunc)
}

type ScannerFunc func(path string) (*packages.Package, error)

var (
	fromRawPathToTempGoModFilepath   = make(map[string]string)
	fromRawPathToTempGoModFilepathMu = &sync.RWMutex{}
)

func setTempGoModFilepath(rawPath string, goModFilepath string) {
	// TODO: is this relation stable?
	// - What if the same package@latest is requested at two different times, resulting in two different versions?
	fromRawPathToTempGoModFilepathMu.Lock()
	defer fromRawPathToTempGoModFilepathMu.Unlock()
	fromRawPathToTempGoModFilepath[rawPath] = goModFilepath
}

// GetTempGoModFilepath gets the go.mod file with which the package was
// loaded.
func GetTempGoModFilepath(rawPath string) string {
	fromRawPathToTempGoModFilepathMu.RLock()
	defer fromRawPathToTempGoModFilepathMu.RUnlock()
	goModFilepath, ok := fromRawPathToTempGoModFilepath[rawPath]
	if !ok {
		return ""
	}
	return goModFilepath
}

func defaultModuleScannerFunc(rawPath string) (*packages.Package, error) {
	// Split eventual path@version format:
	path, version := SplitPathVersion(rawPath)
	if path == "" {
		return nil, errors.New("No package specified")
	}
	// Check whether the path belongs to a standard library package:
	isStd := search.IsStandardImportPath(path)
	if isStd {
		Infof("Package %q is part of standard library", path)
	}
	var rootPath string
	if isStd {
		rootPath = path
	} else {
		// Find out the root of the package:
		root, err := get.RepoRootForImportPath(path, get.IgnoreMod, web.DefaultSecurity)
		if err != nil {
			return nil, fmt.Errorf("error while getting RepoRootForImportPath: %s", err)
		}
		Q(root)
		rootPath = root.Root
	}

	if !isStd {
		// Lookup the repo:
		repo, err := modfetch.Lookup(GoProxy, rootPath)
		if err != nil {
			return nil, fmt.Errorf("error while modfetch.Lookup: %s", err)
		}

		// If no version is specified,
		// or "latest" is specified,
		// then lookup what's the latest version:
		if version == "" || version == "latest" {
			latest, err := repo.Latest()
			if err != nil {
				return nil, fmt.Errorf("error while fetching info about latest revision: %s", err)
			}
			version = latest.Version
			Infof("Using latest %q version", latest)
		}

		rev, err := repo.Stat(version)
		if err != nil {
			return nil, fmt.Errorf("error while repo.Stat: %s", err)
		}
		Q(rev)
	}
	config := &packages.Config{
		Mode: packages.LoadSyntax | packages.NeedModule,
	}
	{
		// Create a temporary folder:
		tmpDir, err := ioutil.TempDir("", "codebox")
		if err != nil {
			return nil, fmt.Errorf("error while creating temp dir for module: %s", err)
		}
		tmpDir = MustAbs(tmpDir)
		Q(tmpDir)

		// Create a `go.mod` file requiring the specified version of the package:
		mf := &modfile.File{}
		mf.AddModuleStmt("example.com/hello/world")

		if !isStd {
			mf.AddNewRequire(rootPath, version, true)
		}
		mf.Cleanup()

		mfBytes, err := mf.Format()
		if err != nil {
			return nil, fmt.Errorf("error while formatting temporary go.mod: %s", err)
		}
		goModFilepath := filepath.Join(tmpDir, "go.mod")
		// Write temporary `go.mod` file:
		err = ioutil.WriteFile(goModFilepath, mfBytes, 0666)
		if err != nil {
			return nil, fmt.Errorf("error while writing temporary go.mod: %s", err)
		}
		Infof("Using the following temporary go.mod file:\n")
		Ln(string(mfBytes))
		setTempGoModFilepath(rawPath, goModFilepath)

		// Set the package loader Dir to the `tmpDir`; that will force
		// the package loader to use the `go.mod` file and thus
		// load the wanted version of the package:
		config.Dir = tmpDir
	}

	// - If you set `config.Dir` to a dir that contains a `go.mod` file,
	// and a version of `path` package is specified in that `go.mod` file,
	// then that specific version will be parsed.
	// - You can have a temporary folder with only a `go.mod` file
	// that contains a reuire for the package+version you want, and
	// go will add the missing deps, and load that version you specified.
	Infof("Starting to load package %q ...", rawPath)
	pkgs, err := packages.Load(config, path)
	if err != nil {
		return nil, fmt.Errorf("error while packages.Load: %s", err)
	}
	Infof("Loaded package %q", rawPath)

	var errs []error
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		for _, err := range pkg.Errors {
			errs = append(errs, err)
		}
	})
	err = CombineErrors(errs...)
	if len(errs) > 0 {
		return nil, fmt.Errorf("error while packages.Load: %s", err)
	}

	// TODO: remove debug:
	for _, pkg := range pkgs {
		Q(pkg.Module)
	}
	for _, pkg := range pkgs {
		Sfln(
			"%s has %v files",
			pkg.ID,
			len(pkg.GoFiles),
		)
	}
	return pkgs[0], nil
}
func deprecatedScannerFunc(path string) (*packages.Package, error) {
	// Example: path = "/usr/local/go/src/net"
	fmt.Println("Scanning", path)

	config := &packages.Config{
		Mode: packages.LoadSyntax | packages.NeedModule,
	}
	pkgs, err := packages.Load(config, path)
	if err != nil {
		return nil, pkgerrors.Wrapf(err, "Error loading package %s", path)
	}

	return pkgs[0], nil
}
func (s *Scanner) scanPackageWithScanner(p string, sc ScannerFunc) (*Package, error) {
	pkg, err := sc(p)
	if err != nil {
		return nil, fmt.Errorf("error while scanPackageWithScanner: %s", err)
	}

	ctx, err := newContext(pkg.Syntax)
	if err != nil {
		return nil, err
	}
	scannedPackage, err := buildPackage(ctx, pkg.Types)
	if err != nil {
		return nil, err
	}
	scannedPackage.Module = pkg.Module

	return scannedPackage, nil
}

func buildPackage(ctx *context, gopkg *types.Package) (*Package, error) {
	pkg := &Package{
		Path:  RemoveGoPath(gopkg),
		Name:  gopkg.Name(),
		Types: make([]*Named, 0),
	}

	{
		for _, name := range gopkg.Scope().Names() {
			obj := gopkg.Scope().Lookup(name)
			// Skip non-exported objects.
			if !obj.Exported() {
				continue
			}

			switch thing := obj.(type) {
			case *types.TypeName:
				{
					// Skip alias types:
					if thing.IsAlias() {
						continue
					}

					switch namedOrSignature := obj.Type().(type) {
					case *types.Named:
						{
							typeName := scanType(namedOrSignature)
							if named, ok := typeName.(*Named); ok {
								named.Object = obj
								ctx.trySetDocs(obj.Name(), named)
								pkg.Types = append(pkg.Types, named)
							}

							methods := methodsForNamed(namedOrSignature)
							{
								for _, fun := range methods {
									switch funcThing := fun.Type().(type) {
									case *types.Signature:
										{
											fn := scanFunc(&Func{Name: fun.Name()}, funcThing)
											fn.Signature = StringRemoveGoPath(fun.String())
											fn.PkgPath = RemoveGoPath(gopkg)
											fn.PkgName = gopkg.Name()
											ctx.trySetDocs(name+"."+fun.Name(), fn)
											pkg.Methods = append(pkg.Methods, fn)
										}
									}
								}
							}

							switch deeperThing := obj.Type().Underlying().(type) {
							case *types.Struct:
								{
									st := scanStruct(
										&Struct{
											Name: name,
											Type: namedOrSignature,
										},
										deeperThing,
										ctx.trySetDocsForStructField,
									)
									st.SetType(namedOrSignature)
									ctx.trySetDocs(name, st)

									pkg.Structs = append(pkg.Structs, st)
								}
							case *types.Interface:
								{
									it := scanInterface(&Interface{Name: name}, deeperThing, ctx.trySetDocsForInterfaceMethod)
									ctx.trySetDocs(name, it)

									it.SetType(namedOrSignature)
									pkg.Interfaces = append(pkg.Interfaces, it)
								}
							}
						}

					}

				}
			case *types.Const:
			case *types.Var:
				// TODO: scan variables of signature type?
			case *types.Func:

				switch funcThing := thing.Type().(type) {
				case *types.Signature:
					{
						fn := scanFunc(&Func{Name: name}, funcThing)
						fn.Signature = StringRemoveGoPath(thing.String())
						fn.PkgPath = RemoveGoPath(gopkg)
						fn.PkgName = gopkg.Name()
						ctx.trySetDocs(name, fn)
						pkg.Funcs = append(pkg.Funcs, fn)
					}
				}
			}

		}
	}
	return pkg, nil
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
		t = scanStruct(st, u, nil)
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

func scanStruct(s *Struct, elem *types.Struct, docSetter func(it string, method string, obj Documentable)) *Struct {
	s.BaseType = newBaseType()
	s.SetIsStruct(true)

	for i := 0; i < elem.NumFields(); i++ {
		v := elem.Field(i)

		if !v.Exported() {
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

		if v.Embedded() {
			// Scan embedded types:
			embedded := scanType(v.Type())
			if embedded == nil {
				report.Warn("field %q with type %q is not a valid embedded type", v.Name(), v.Type())
			} else {
				if s.Embedded == nil {
					s.Embedded = make([]Type, 0)
				}

				if named, ok := embedded.(*Named); ok {
					if docSetter != nil {
						docSetter(
							s.Name,
							Itoa(i),
							named,
						)
					}
					s.Embedded = append(s.Embedded, named)
				}
			}
			continue
		}

		f := &Field{
			Name: v.Name(),
			Type: scanType(v.Type()),
		}
		f.Type.SetType(v.Type())
		f.Type.SetTypesVar(v)
		if docSetter != nil {
			docSetter(
				s.Name,
				v.Name(),
				f,
			)
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
		fn.Receiver.SetTypesVar(signature.Recv())
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
		if methObj.Pkg() != nil {
			fn.PkgPath = RemoveGoPath(methObj.Pkg())
			fn.PkgName = methObj.Pkg().Name()
		}

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
