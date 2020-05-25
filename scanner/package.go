package scanner

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"
)

// Package holds information about a single Go package and
// a reference of all defined structs and type aliases.
// A Package is only safe to use once it is resolved.
type Package struct {
	Resolved   bool
	Path       string
	Name       string
	Structs    []*Struct
	Enums      []*Enum
	Funcs      []*Func
	Interfaces []*Interface
	Methods    []*types.Selection
	Aliases    map[string]Type
}

// collectEnums finds the enum values collected during the scan and generates
// the corresponding enum types, removing them as aliases from the package.
func (p *Package) collectEnums(ctx *context) {
	for k := range p.Aliases {
		if vals, ok := ctx.enumValues[k]; ok {
			idx := strings.LastIndex(k, ".")
			name := k[idx+1:]
			if !ctx.shouldGenerateType(name) {
				continue
			}

			hasStringMethod := containsString(ctx.enumWithString, k)

			p.Enums = append(p.Enums, newEnum(ctx, name, vals, hasStringMethod))
			delete(p.Aliases, k)
		}
	}
}

func containsString(arr []string, s string) bool {
	for _, str := range arr {
		if str == s {
			return true
		}
	}

	return false
}

// Type is the common interface for all possible types supported in protogo.
// Type is neither a representation of a Go type nor a representation of a
// protobuf type. Is an intermediate representation to ease future steps in
// the conversion from Go to protobuf.
// All types can be repeated (or not).
type Type interface {
	fmt.Stringer
	SetRepeated(bool)
	IsRepeated() bool

	SetNullable(bool)
	IsNullable() bool

	SetIsPtr(bool)
	IsPtr() bool

	SetIsStruct(bool)
	IsStruct() bool

	// TypeString returns a string representing the final type.
	// Though this might seem that this should be just String, for Alias types
	// both representations are different: a string representation of the final
	// type, this is just the alias, while string contains also the underlying type.
	TypeString() string
	// Name returns the unqualified name.
	UnqualifiedName() string

	GetTypesVar() *types.Var
	SetTypesVar(*types.Var)

	GetType() types.Type
	SetType(types.Type)

	SetIsVariadic(bool)
	IsVariadic() bool

	SetIsBasic(v bool)
	IsBasic() bool
}

// BaseType contains the common fields for all the types.
type BaseType struct {
	Repeated bool
	Nullable bool
	Ptr      bool
	Struct   bool
	ID       string
	TypesVar *types.Var
	Variadic bool
	Basic    bool
	Type     types.Type
}

func newBaseType() *BaseType {
	return &BaseType{
		Repeated: false,
		Nullable: false,
	}
}
func (t *BaseType) IsBasic() bool     { return t.Basic }
func (t *BaseType) SetIsBasic(v bool) { t.Basic = v }

func (t *BaseType) IsVariadic() bool     { return t.Variadic }
func (t *BaseType) SetIsVariadic(v bool) { t.Variadic = v }

func (t *BaseType) GetTypesVar() *types.Var  { return t.TypesVar }
func (t *BaseType) SetTypesVar(v *types.Var) { t.TypesVar = v }

func (t *BaseType) GetType() types.Type  { return t.Type }
func (t *BaseType) SetType(v types.Type) { t.Type = v }

// IsRepeated reports wether the type is repeated or not.
func (t *BaseType) IsRepeated() bool { return t.Repeated }

// SetRepeated sets the type as repeated or not repeated.
func (t *BaseType) SetRepeated(v bool) { t.Repeated = v }

// IsNullable reports wether the type is a pointer or not.
func (t *BaseType) IsNullable() bool { return t.Nullable }

// SetNullable sets the type as pointer.
func (t *BaseType) SetNullable(v bool) { t.Nullable = v }

// TypeString returns a string representation for the type casting
func (t *BaseType) TypeString() string { panic("not implemented") }

// String returns a string representation for the type
func (t *BaseType) String() string { panic("not implemented") }

// String returns a string representation for the type
func (t *BaseType) UnqualifiedName() string { panic("not implemented") }

func (t *BaseType) SetIsPtr(v bool) { t.Ptr = v }
func (t *BaseType) IsPtr() bool     { return t.Ptr }

func (t *BaseType) SetIsStruct(v bool) { t.Struct = v }
func (t *BaseType) IsStruct() bool     { return t.Struct }

// Basic is a basic type, which only is identified by its name.
type Basic struct {
	*BaseType
	Name string
}

// NewBasic creates a new basic type given its name.
func NewBasic(name string) Type {
	return &Basic{
		newBaseType(),
		name,
	}
}

// IsNullable returns true ONLY if it's also a pointer.
// Otherwise, Basic types are not nullable,
// and have just the zero values.
//
// Basic types:
// int, int8, int16, int32, int64
// uint, uint8, uint16, uint32, uint64
// uintptr
// float32, float64
// byte
// rune
// string
// complex64, complex128
//
// See: https://nilsmagnus.github.io/post/nillability-in-go/
func (b Basic) IsNullable() bool { return b.Nullable }
func (b Basic) IsBasic() bool    { return true }

// String returns a string representation for the type
func (b Basic) String() string {
	return b.Name
}

// TypeString returns a string representation for the type casting
func (b Basic) TypeString() string {
	return b.String()
}

// UnqualifiedName returns the bare name, without the package.
func (b Basic) UnqualifiedName() string {
	return b.Name
}

// Named is non-basic type identified by a name on some package.
type Named struct {
	*BaseType
	Path string
	Name string
}

// String returns a string representation for the type
func (n Named) String() string {
	if n.Path == "" {
		return n.Name
	}
	return fmt.Sprintf("%s.%s", n.Path, n.Name)
}

// TypeString returns a string representation for the type casting
func (n Named) TypeString() string {
	return n.String()
}

// UnqualifiedName returns the bare name, without the package.
func (n Named) UnqualifiedName() string {
	return n.Name
}

// NewNamed creates a new named type given its package path and name.
func NewNamed(path, name string) Type {
	return &Named{
		newBaseType(),
		path,
		name,
	}
}

// Alias represents a type declaration from a type to another type
type Alias struct {
	*BaseType
	// Type represents the type being declared
	Type Type
	// Underlying represent the aliased type.
	Underlying Type
}

func NewAlias(typ, underlying Type) Type {
	return &Alias{
		Type:       typ,
		Underlying: underlying,
	}
}

func (a Alias) IsNullable() bool { return a.Type.IsNullable() || a.Underlying.IsNullable() }
func (a Alias) IsRepeated() bool { return a.Type.IsRepeated() || a.Underlying.IsRepeated() }

// String returns a string representation for the type
func (a Alias) String() string {
	return fmt.Sprintf("type %s %s", a.Type.String(), a.Underlying.String())
}

// TypeString returns a string representation for the type casting
func (a Alias) TypeString() string {
	return a.Type.TypeString()
}

// UnqualifiedName returns the bare name, without the package.
func (a Alias) UnqualifiedName() string {
	return a.Type.UnqualifiedName()
}

// Map is a map type with a key and a value type.
type Map struct {
	*BaseType
	Key   Type
	Value Type
}

// NewMap creates a new map type with the given key and value types.
func NewMap(key, val Type) Type {
	return &Map{
		newBaseType(),
		key,
		val,
	}
}

// String returns a string representation for the type
func (m Map) String() string {
	return fmt.Sprintf("map[%s]%s", m.Key.String(), m.Value.String())
}

// TypeString returns a string representation for the type casting
func (m Map) TypeString() string {
	// TODO: this should return map[somepackage.SomeType]somepackage1.SomeType1
	// i.e. package name + UnqualifiedName()
	// for key and value types.
	return fmt.Sprintf("map[%s]%s", m.Key.TypeString(), m.Value.TypeString())
}

// UnqualifiedName returns the bare name, without the package.
func (m Map) UnqualifiedName() string {
	return m.String()
}

// Chan is a map type with a key and a value type.
type Chan struct {
	*BaseType
	Elem *types.Chan
}

// NewChan creates a new map type with the given key and value types.
func NewChan(elem *types.Chan) Type {
	return &Chan{
		newBaseType(),
		elem,
	}
}

// String returns a string representation for the type
func (m Chan) String() string {
	return StringRemoveGoPath(m.Elem.String())
}

// TypeString returns a string representation for the type casting
func (m Chan) TypeString() string {
	return m.String()
}

// UnqualifiedName returns the bare name, without the package.
func (m Chan) UnqualifiedName() string {
	return m.String()
}

// Documentable is something whose documentation can be set.
type Documentable interface {
	// SetDocs sets the documentation from an AST comment group.
	SetDocs(*ast.CommentGroup)
}

// Docs holds the documentation of a struct, enum, value, field, etc.
type Docs struct {
	Doc []string
}

// SetDocs sets the documentation from an AST comment group.
// It removes the //proteus:generate comment from the comments.
func (d *Docs) SetDocs(comments *ast.CommentGroup) {
	var list []*ast.Comment
	if comments != nil {
		for _, c := range comments.List {
			if !strings.HasPrefix(c.Text, genComment) {
				list = append(list, c)
			}
		}
	}

	if len(list) > 0 {
		d.Doc = strings.Split(strings.TrimSpace(
			(&ast.CommentGroup{List: list}).Text(),
		), "\n")
	}
}

// Enum consists of a list of possible values.
type Enum struct {
	Docs
	Name       string
	Values     []*EnumValue
	IsStringer bool
}

// EnumValue is a possible value of an enum.
type EnumValue struct {
	Docs
	Name string
}

// Struct represents a Go struct with its name and fields.
// All structs
type Struct struct {
	*BaseType
	Docs
	Generate      bool
	Name          string
	Fields        []*Field
	Methods       []*types.Func
	Type          *types.Named
	AnonymousType *types.Struct
	IsStringer    bool
}

// String returns a string representation for the type
func (m Struct) String() string {
	if m.Type != nil {
		return m.Type.String()
	}
	if m.AnonymousType != nil {
		return m.AnonymousType.String()
	}
	return ""
}

// TypeString returns a string representation for the type casting
func (m Struct) TypeString() string {
	return m.String()
}

// UnqualifiedName returns the bare name, without the package.
func (m Struct) UnqualifiedName() string {
	return m.String()
}

// HasField reports wether a struct has a given field name.
func (s *Struct) HasField(name string) bool {
	for _, f := range s.Fields {
		if f.Name == name {
			return true
		}
	}
	return false
}

// Field contains name and type of a struct field.
type Field struct {
	Docs
	Name string
	Type Type
}

// Func is either a function or a method. Receiver will be nil in functions,
// otherwise it is a method.
type Func struct {
	*BaseType
	Docs
	Name string
	// Receiver will not be nil if it's a method.
	Receiver Type
	Input    []Type
	Output   []Type
	// Variadic will be true if the last input parameter is variadic.
	Variadic  bool
	Signature string
	PkgPath   string
	PkgName   string
}

// String returns a string representation for the type
func (m Func) String() string {
	return StringRemoveGoPath(m.Signature)
}

// TypeString returns a string representation for the type casting
func (m Func) TypeString() string {
	return m.String()
}

// UnqualifiedName returns the bare name, without the package.
func (m Func) UnqualifiedName() string {
	return m.String()
}

// Interface is an interface.
type Interface struct {
	*BaseType
	Docs
	Name    string
	Methods []*Func
}

// String returns a string representation for the type
func (m Interface) String() string {
	return StringRemoveGoPath(m.Name)
}

// TypeString returns a string representation for the type casting
func (m Interface) TypeString() string {
	return m.String()
}

// UnqualifiedName returns the bare name, without the package.
func (m Interface) UnqualifiedName() string {
	return m.String()
}
