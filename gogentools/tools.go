// Package gogentools contains tools that help with Go code generation.
package gogentools

import (
	"go/types"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	. "github.com/dave/jennifer/jen"
	"github.com/gagliardetto/codebox/scanner"
	. "github.com/gagliardetto/utilz"
)

func NewNameWithPrefix(prefix string) string {
	return Sf("%s%v", prefix, DeterministicRandomIntRange(111, 999))
}
func MustVarName(name string) string {
	return MustVarNameWithDefaultPrefix(name, "variable")
}
func MustVarNameWithDefaultPrefix(name string, prefix string) string {
	if prefix == "" {
		prefix = "var"
	}
	if name == "" {
		return NewNameWithPrefix(prefix)
	}

	return name
}
func ScanTupleOfZeroValues(file *File, tuple *types.Tuple, isVariadic bool) []Code {
	result := make([]Code, 0)

	for i := 0; i < tuple.Len(); i++ {
		tp := newStatement()

		isLast := i == tuple.Len()-1
		if isLast && isVariadic {
			if slice, ok := tuple.At(i).Type().(*types.Slice); ok {
				ComposeZeroDeclaration(file, tp, slice.Elem())
			} else {
				ComposeZeroDeclaration(file, tp, tuple.At(i).Type())
			}
		} else {
			ComposeZeroDeclaration(file, tp, tuple.At(i).Type())
		}
		result = append(result, tp)
	}
	return result
}

func ComposeZeroDeclaration(file *File, stat *Statement, typ types.Type) {
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
			case "Pointer":
				{
					stat.Nil()
				}
			default:
				Errorf("unknown typeName: %q (%q) of kind %s", t.Name(), t.String(), t.Kind())
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

				ImportPackage(file, scanner.RemoveGoPath(field.Pkg()), field.Pkg().Name())

				ComposeZeroDeclaration(file, fldStm, field.Type())
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
				ImportPackage(file, scanner.RemoveGoPath(t.Obj().Pkg()), t.Obj().Pkg().Name())
			}

			switch named := t.Underlying().(type) {
			case *types.Basic:
				{
					ComposeZeroDeclaration(file, stat, named)
				}
			case *types.Array:
				{
					ComposeZeroDeclaration(file, stat, named)
				}
			case *types.Slice:
				{
					ComposeZeroDeclaration(file, stat, named)
				}
			case *types.Struct:
				{
					if guessAlias(t.Obj().Pkg().Path()) != t.Obj().Pkg().Name() {
						file.ImportAlias(t.Obj().Pkg().Path(), t.Obj().Pkg().Name())
					}
					stat.Qual(scanner.RemoveGoPath(t.Obj().Pkg()), t.Obj().Name()).Block()
				}
			case *types.Pointer:
				{
					ComposeZeroDeclaration(file, stat, named)
				}
			case *types.Tuple:
				{
					ComposeZeroDeclaration(file, stat, named)
				}
			case *types.Signature:
				{
					ComposeZeroDeclaration(file, stat, named)
				}
			case *types.Interface:
				{
					ComposeZeroDeclaration(file, stat, named)
				}
			case *types.Map:
				{
					ComposeZeroDeclaration(file, stat, named)
				}
			case *types.Chan:
				{
					ComposeZeroDeclaration(file, stat, named)
				}
			case *types.Named:
				{
					ComposeZeroDeclaration(file, stat, named)
				}

			}
		}
	}
}

// declare `name := sourceCQL.(Type)`
func ComposeTypeAssertion(file *File, group *Group, varName string, typ types.Type, isVariadic bool) {
	assertContent := newStatement()
	if isVariadic {
		if slice, ok := typ.(*types.Slice); ok {
			ComposeTypeDeclaration(file, assertContent, slice.Elem())
		} else {
			ComposeTypeDeclaration(file, assertContent, typ)
		}
	} else {
		ComposeTypeDeclaration(file, assertContent, typ)
	}
	group.Id(varName).Op(":=").Id("sourceCQL").Assert(assertContent)
}
func newStatement() *Statement {
	return &Statement{}
}

// declare `var name Type`
func ComposeVarDeclaration(file *File, group *Group, varName string, typ types.Type, isVariadic bool) {
	if isVariadic {
		if slice, ok := typ.(*types.Slice); ok {
			ComposeTypeDeclaration(file, group.Var().Id(varName), slice.Elem())
		} else {
			ComposeTypeDeclaration(file, group.Var().Id(varName), typ)
		}
	} else {
		ComposeTypeDeclaration(file, group.Var().Id(varName), typ)
	}
}
func ImportPackage(file *File, pkgPath string, pkgName string) {
	if pkgPath == "" || pkgName == "" {
		return
	}
	if ShouldUseAlias(pkgPath, pkgName) {
		file.ImportAlias(pkgPath, pkgName)
	} else {
		file.ImportName(pkgPath, pkgName)
	}
}

// ComposeTypeDeclaration adds the `Type` inside `var name Type`
func ComposeTypeDeclaration(file *File, stat *Statement, typ types.Type) {
	switch t := typ.(type) {
	case *types.Basic:
		{
			if t.Name() == "Pointer" {
				stat.Qual("unsafe", t.Name())
			} else {
				stat.Qual("", t.Name())
			}
		}
	case *types.Array:
		{
			if t.Len() > 0 {
				stat.Index(Lit(t.Len()))
			} else {
				stat.Index()
			}
			ComposeTypeDeclaration(file, stat, t.Elem())
		}
	case *types.Slice:
		{
			stat.Index()
			ComposeTypeDeclaration(file, stat, t.Elem())
		}
	case *types.Struct:
		{
			fields := make([]Code, 0)
			for i := 0; i < t.NumFields(); i++ {
				field := t.Field(i)
				fldStm := newStatement()
				fldStm.Id(field.Name())

				ImportPackage(file, scanner.RemoveGoPath(field.Pkg()), field.Pkg().Name())

				ComposeTypeDeclaration(file, fldStm, field.Type())
				fields = append(fields, fldStm)
			}
			stat.Struct(fields...)
		}
	case *types.Pointer:
		{
			stat.Op("*")
			ComposeTypeDeclaration(file, stat, t.Elem())
		}
	case *types.Tuple:
		{
			// TODO
			tuple := ScanTupleOfTypes(file, t, false)
			stat.Add(tuple...)
		}
	case *types.Signature:
		{
			paramsTuple := ScanTupleOfTypes(file, t.Params(), t.Variadic())
			resultsTuple := ScanTupleOfTypes(file, t.Results(), false)

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
					{
						// TODO: check if has at least one method?
						// Get receiver info from the first explicit method:
						meth := t.ExplicitMethod(0)
						methFunc := meth.Type().(*types.Signature)
						pkgPath := scanner.RemoveGoPath(methFunc.Recv().Pkg())
						pkgName := methFunc.Recv().Pkg().Name()
						typeName := methFunc.Recv().Name()

						ImportPackage(file, pkgPath, pkgName)

						if guessAlias(methFunc.Recv().Pkg().Path()) != methFunc.Recv().Pkg().Name() {
							file.ImportAlias(methFunc.Recv().Pkg().Path(), methFunc.Recv().Pkg().Name())
						}
						stat.Qual(pkgPath, typeName)
					}
				}
			}
		}
	case *types.Map:
		{
			mapKey := newStatement()
			ComposeTypeDeclaration(file, mapKey, t.Key())
			stat.Map(mapKey)
			ComposeTypeDeclaration(file, stat, t.Elem())
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

			ComposeTypeDeclaration(file, stat, t.Elem())
		}
	case *types.Named:
		{
			if t.Obj() != nil && t.Obj().Name() == "error" {
				stat.Error()
			} else {
				if t.Obj() != nil && t.Obj().Pkg() != nil {
					ImportPackage(file, scanner.RemoveGoPath(t.Obj().Pkg()), t.Obj().Pkg().Name())
					if guessAlias(t.Obj().Pkg().Path()) != t.Obj().Pkg().Name() {
						file.ImportAlias(t.Obj().Pkg().Path(), t.Obj().Pkg().Name())
					}
					stat.Qual(scanner.RemoveGoPath(t.Obj().Pkg()), t.Obj().Name())
				}
			}
		}
	default:
		panic(typ)
	}

}

func ScanTupleOfTypes(file *File, tuple *types.Tuple, isVariadic bool) []Code {
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
					ComposeTypeDeclaration(file, tp, singleType.Elem())
				case *types.Array:
					ComposeTypeDeclaration(file, tp, singleType.Elem())
				}
			} else {
				ComposeTypeDeclaration(file, tp, tuple.At(i).Type())
			}
			result = append(result, tp)
		}
	}

	return result
}

// ShouldUseAlias tells whether the package name and the base
// of the backage path are the same; if they are not,
// then the package should use an alias in the import.
func ShouldUseAlias(pkgPath string, pkgName string) bool {
	return filepath.Base(pkgPath) != pkgName
}
func guessAlias(path string) string {
	// From https://github.com/dave/jennifer/blob/2abe0ee856a1cfbca4a3327861b51d9c1c1a8592/jen/file.go#L224
	alias := path

	if strings.HasSuffix(alias, "/") {
		// training slashes are usually tolerated, so we can get rid of one if
		// it exists
		alias = alias[:len(alias)-1]
	}

	if strings.Contains(alias, "/") {
		// if the path contains a "/", use the last part
		alias = alias[strings.LastIndex(alias, "/")+1:]
	}

	// alias should be lower case
	alias = strings.ToLower(alias)

	// alias should now only contain alphanumerics
	importsRegex := regexp.MustCompile(`[^a-z0-9]`)
	alias = importsRegex.ReplaceAllString(alias, "")

	// can't have a first digit, per Go identifier rules, so just skip them
	for firstRune, runeLen := utf8.DecodeRuneInString(alias); unicode.IsDigit(firstRune); firstRune, runeLen = utf8.DecodeRuneInString(alias) {
		alias = alias[runeLen:]
	}

	// If path part was all digits, we may be left with an empty string. In this case use "pkg" as the alias.
	if alias == "" {
		alias = "pkg"
	}

	return alias
}
