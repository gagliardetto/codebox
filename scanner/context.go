package scanner

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
)

// context holds all the scanning context of a single package. Contains all
// the enum values we find during the scan as well as some info extracted
// from the AST that will be needed throughout the process of scanning.
type context struct {
	// types holds the type declarations indexed by the type name. The TypeSpec
	// is guaranteed to include the comments, if any, even though they were on
	// the GenDecl.
	types map[string]*ast.TypeSpec
	// consts holds the const objects indexed by the const name. We store an
	// object instead of a ValueSpec because the iota of the const is not
	// available there.
	consts map[string]*ast.Object
	// funcs holds the func objects indexed by the function or method name.
	// In case of methods, it's indexed by their qualified name, that is,
	// "TypeName.FuncName".
	funcs map[string]*ast.FuncDecl
	// enumValues contains all the values found until a point in time.
	// It is indexed by qualified type name e.g: time.Time
	enumValues map[string][]string
	// enums with string method
	enumWithString []string
}

func newContext(astFiles []*ast.File) (*context, error) {
	types, funcs := findPkgTypesAndFuncs(astFiles)
	return &context{
		types:          types,
		funcs:          funcs,
		consts:         findObjectsOfType(astFiles, ast.Con),
		enumValues:     make(map[string][]string),
		enumWithString: []string{},
	}, nil
}

func findPkgTypesAndFuncs(astFiles []*ast.File) (map[string]*ast.TypeSpec, map[string]*ast.FuncDecl) {
	var types = make(map[string]*ast.TypeSpec)
	var funcs = make(map[string]*ast.FuncDecl)

	for _, f := range astFiles {
		for _, d := range f.Decls {
			switch decl := d.(type) {
			case *ast.GenDecl:
				if decl.Tok == token.TYPE {
					for _, s := range decl.Specs {
						spec := s.(*ast.TypeSpec)
						if spec.Doc == nil {
							spec.Doc = decl.Doc
						}
						types[spec.Name.Name] = spec
					}
				}
			case *ast.FuncDecl:
				funcs[findName(decl)] = decl
			}
		}
	}

	return types, funcs
}

func findName(decl *ast.FuncDecl) (name string) {
	name = decl.Name.Name
	if decl.Recv == nil || len(decl.Recv.List) < 1 {
		return
	}

	var qualifier string
	switch t := decl.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			qualifier = ident.Name
		}
	case *ast.Ident:
		qualifier = t.Name
	}

	if qualifier != "" {
		return fmt.Sprintf("%s.%s", qualifier, name)
	}
	return
}

func findObjectsOfType(astFiles []*ast.File, kind ast.ObjKind) map[string]*ast.Object {
	var objects = make(map[string]*ast.Object)

	for _, f := range astFiles {
		for k, o := range f.Scope.Objects {
			if o.Kind == kind {
				objects[k] = o
			}
		}
	}

	return objects
}

func (ctx *context) trySetDocs(name string, obj Documentable) {
	if typ, ok := ctx.types[name]; ok && typ.Doc != nil {
		obj.SetDocs(typ.Doc)
		obj.SetComments(typ.Comment)
	} else if fn, ok := ctx.funcs[name]; ok && fn.Doc != nil {
		obj.SetDocs(fn.Doc)
	} else if v, ok := ctx.consts[name]; ok {
		if spec, ok := v.Decl.(*ast.ValueSpec); ok {
			obj.SetDocs(spec.Doc)
			obj.SetComments(spec.Comment)
		}
	}
}
func (ctx *context) trySetDocsForInterfaceMethod(it string, method string, obj Documentable) {
	if itx0, ok := ctx.types[it]; ok {
		itx1, ok := itx0.Type.(*ast.InterfaceType)
		if ok {
			for _, mtx0 := range itx1.Methods.List {
				if mtx0.Names != nil && len(mtx0.Names) > 0 {
					if method == mtx0.Names[0].Name {
						obj.SetDocs(mtx0.Doc)
						obj.SetComments(mtx0.Comment)
					}
				}
			}
		}
	}
}
func (ctx *context) trySetDocsForStructField(st string, field string, obj Documentable) {
	if stx0, ok := ctx.types[st]; ok {
		itx1, ok := stx0.Type.(*ast.StructType)
		if ok {
			for _, fldx0 := range itx1.Fields.List {
				if fldx0.Names != nil && len(fldx0.Names) > 0 {
					if field == fldx0.Names[0].Name {
						obj.SetDocs(fldx0.Doc)
						obj.SetComments(fldx0.Comment)
					}
				}
			}
		}
	}
}

const genComment = `//proteus:generate`

func (ctx *context) shouldGenerateType(name string) bool {
	if typ, ok := ctx.types[name]; ok && typ.Doc != nil {
		return hasGenerateComment(typ.Doc)
	}
	return false
}

func (ctx *context) shouldGenerateFunc(name string) bool {
	if fn, ok := ctx.funcs[name]; ok && fn.Doc != nil {
		return hasGenerateComment(fn.Doc)
	}
	return false
}

func hasGenerateComment(doc *ast.CommentGroup) bool {
	for _, l := range doc.List {
		if strings.HasPrefix(l.Text, genComment) {
			return true
		}
	}
	return false
}
