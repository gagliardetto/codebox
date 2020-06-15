package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	. "github.com/dave/jennifer/jen"
	"github.com/gagliardetto/codebox/scanner"
	. "github.com/gagliardetto/utils"
	"github.com/gin-gonic/gin"
)

type CacheType map[string]*CodeQlFinalVals

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

func (item *IndexItem) GetFETypeMethodOrInterfaceMethod() *FETypeMethod {
	feTyp, ok := item.original.(*FETypeMethod)
	if !ok {
		feIt, ok := item.original.(*FEInterfaceMethod)
		if !ok {
			return nil
		}
		return FEIToFET(feIt)
	}
	return feTyp
}

func FEIToFET(feIt *FEInterfaceMethod) *FETypeMethod {
	converted := FETypeMethod(*feIt)
	return &converted
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
		Errorf(Sf("%q already in the index", signature))
	} else {
		index.Set(signature, v)
	}
}

// TODO:
//OK- reject invalid cases (e.g. from receiver to receiver)
// - look for name collisions
// - make sure that varInName and varOutName are not the same.
// - don't extend name changes to the frontend (new names must stay per-generation only)
//OK- make sure vars and package name are not the same
//OK- add api to "enable" without having to modify pointers.
//OK- Zero value of variadic string parameters is not nil: Options(opts ...string)
//OK- TaintStepTest_NetTextprotoNewWriter: ./NetTextproto.go:50:40: cannot use w (type bufio.Writer) as type *bufio.Writer in argument to textproto.NewWriter
//OK- unsafe.Pointer in type assertion
func main() {
	var pkg string
	var runServer bool

	var cacheDir string
	var generatedDir string

	var toStdout bool
	var includeBoilerplace bool

	flag.StringVar(&pkg, "pkg", "", "Package you want to scan (absolute path)")
	flag.StringVar(&cacheDir, "cache-dir", "./cache", "Folder that contains cache of scanned packages and set pointers")
	flag.StringVar(&generatedDir, "out-dir", "./generated", "Folder that contains the generated assets (each run has its own timestamped folder)")
	flag.BoolVar(&runServer, "http", false, "Run http server")
	flag.BoolVar(&toStdout, "stdout", false, "Print generated to stdout")
	flag.BoolVar(&includeBoilerplace, "stub", false, "Include in go test files the utility functions (main, sink, link, etc.)")
	flag.Parse()

	// One package at a time:
	sc, err := scanner.New(false, pkg)
	if err != nil {
		panic(err)
	}

	pks, err := sc.Scan()
	if err != nil {
		panic(err)
	}

	{ // Create folders:
		// folder for all cache:
		MustCreateFolderIfNotExists(cacheDir, 0750)
		// folder for all folders for assets:
		MustCreateFolderIfNotExists(generatedDir, 0750)
	}

	feModule := &FEModule{
		Funcs:            make([]*FEFunc, 0),
		TypeMethods:      make([]*FETypeMethod, 0),
		InterfaceMethods: make([]*FEInterfaceMethod, 0),
	}

	pk := pks[0]

	// compose the feModule:
	Infof("Composing feModule %q", scanner.RemoveGoSrcClonePath(pk.Path))
	{
		feModule.Name = pk.Name
		feModule.ID = pk.Path
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

	// Sort funcs by name:
	sort.Slice(feModule.Funcs, func(i, j int) bool {
		return feModule.Funcs[i].Name < feModule.Funcs[j].Name
	})
	// Sort type methods by receiver:
	sort.Slice(feModule.TypeMethods, func(i, j int) bool {
		// If same receiver...
		if feModule.TypeMethods[i].Receiver.QualifiedName == feModule.TypeMethods[j].Receiver.QualifiedName {
			// ... sort by func name:
			return feModule.TypeMethods[i].Func.Name < feModule.TypeMethods[j].Func.Name
		}
		return feModule.TypeMethods[i].Receiver.QualifiedName < feModule.TypeMethods[j].Receiver.QualifiedName
	})
	// Sort interface methods by receiver:
	sort.Slice(feModule.InterfaceMethods, func(i, j int) bool {
		// If same receiver...
		if feModule.InterfaceMethods[i].Receiver.QualifiedName == feModule.InterfaceMethods[j].Receiver.QualifiedName {
			// ... sort by func name:
			return feModule.InterfaceMethods[i].Func.Name < feModule.InterfaceMethods[j].Func.Name
		}
		return feModule.InterfaceMethods[i].Receiver.QualifiedName < feModule.InterfaceMethods[j].Receiver.QualifiedName
	})

	{ // Deduplicate:

		feModule.Funcs = DeduplicateSlice(feModule.Funcs, func(i int) string {
			return feModule.Funcs[i].Signature
		}).([]*FEFunc)

		feModule.TypeMethods = DeduplicateSlice(feModule.TypeMethods, func(i int) string {
			return feModule.TypeMethods[i].Func.Signature
		}).([]*FETypeMethod)

		feModule.InterfaceMethods = DeduplicateSlice(feModule.InterfaceMethods, func(i int) string {
			return feModule.InterfaceMethods[i].Func.Signature
		}).([]*FEInterfaceMethod)
	}

	cacheFilepath := path.Join(cacheDir, FormatCodeQlName(scanner.RemoveGoSrcClonePath(pk.Path))+".v2.json")
	cacheExists := MustFileExists(cacheFilepath)
	{
		// try to use DEPRECATED cache:
		deprecatedCacheFilepath := path.Join(cacheDir, FormatCodeQlName(scanner.RemoveGoSrcClonePath(pk.Path))+".json")
		deprecatedCacheExists := MustFileExists(deprecatedCacheFilepath)

		canLoadFromDeprecatedCache := !cacheExists && deprecatedCacheExists
		if canLoadFromDeprecatedCache {
			tempDeprecatedFeModule := &DEPRECATEDFEModule{}
			// Load cache:
			Infof("Loading cached feModule from %q", deprecatedCacheFilepath)
			err := LoadJSON(tempDeprecatedFeModule, deprecatedCacheFilepath)
			if err != nil {
				panic(err)
			}

			findLatestFunc := func(signature string) *FEFunc {
				for _, latest := range feModule.Funcs {
					if latest.Signature == signature {
						return latest
					}
				}
				return nil
			}
			findLatestTypeMethod := func(signature string) *FETypeMethod {
				for _, latest := range feModule.TypeMethods {
					if latest.Func.Signature == signature {
						return latest
					}
				}
				return nil
			}
			findLatestInterfaceMethod := func(signature string) *FEInterfaceMethod {
				for _, latest := range feModule.InterfaceMethods {
					if latest.Func.Signature == signature {
						return latest
					}
				}
				return nil
			}

			doCopy := true

			for _, cached := range tempDeprecatedFeModule.Funcs {
				latest := findLatestFunc(cached.Signature)
				if latest == nil {
					Errorf("latest FEFunc not found for signature %q", cached.Signature)
				} else {
					// Copy CodeQL object:
					latest.CodeQL.IsEnabled = cached.CodeQL.IsEnabled
					if doCopy {
						{
							// Initialize block:
							width := len(latest.Parameters) + len(latest.Results)
							latest.CodeQL.Blocks = make([]*FlowBlock, 0)
							latest.CodeQL.Blocks = append(
								latest.CodeQL.Blocks,
								&FlowBlock{
									Inp:  make([]bool, width),
									Outp: make([]bool, width),
								},
							)

							// Copy legacy pointers into first block:
							{
								inp := cached.CodeQL.Pointers.Inp
								switch inp.Element {
								case ElementParameter:
									latest.CodeQL.Blocks[0].Inp[inp.Index] = true
								case ElementResult:
									latest.CodeQL.Blocks[0].Inp[inp.Index+len(latest.Parameters)] = true
								}
							}
							{
								outp := cached.CodeQL.Pointers.Outp
								switch outp.Element {
								case ElementParameter:
									latest.CodeQL.Blocks[0].Outp[outp.Index] = true
								case ElementResult:
									latest.CodeQL.Blocks[0].Outp[outp.Index+len(latest.Parameters)] = true
								}
							}
						}
					}

				}
			}
			for _, cached := range tempDeprecatedFeModule.TypeMethods {
				latest := findLatestTypeMethod(cached.Func.Signature)
				if latest == nil {
					Errorf("latest FETypeMethod not found for signature %q", cached.Func.Signature)
				} else {
					// Copy CodeQL object:
					latest.CodeQL.IsEnabled = cached.CodeQL.IsEnabled
					if doCopy {
						{
							// Initialize block:
							width := 1 + len(latest.Func.Parameters) + len(latest.Func.Results)
							latest.CodeQL.Blocks = make([]*FlowBlock, 0)
							latest.CodeQL.Blocks = append(
								latest.CodeQL.Blocks,
								&FlowBlock{
									Inp:  make([]bool, width),
									Outp: make([]bool, width),
								},
							)

							// Copy legacy pointers into first block:
							{
								inp := cached.CodeQL.Pointers.Inp
								switch inp.Element {
								case ElementReceiver:
									latest.CodeQL.Blocks[0].Inp[0] = true
								case ElementParameter:
									latest.CodeQL.Blocks[0].Inp[inp.Index+1] = true
								case ElementResult:
									latest.CodeQL.Blocks[0].Inp[inp.Index+len(latest.Func.Parameters)+1] = true
								}
							}
							{
								outp := cached.CodeQL.Pointers.Outp
								switch outp.Element {
								case ElementReceiver:
									latest.CodeQL.Blocks[0].Outp[0] = true
								case ElementParameter:
									latest.CodeQL.Blocks[0].Outp[outp.Index+1] = true
								case ElementResult:
									latest.CodeQL.Blocks[0].Outp[outp.Index+len(latest.Func.Parameters)+1] = true
								}
							}
						}
					}
				}
			}
			for _, cached := range tempDeprecatedFeModule.InterfaceMethods {
				latest := findLatestInterfaceMethod(cached.Func.Signature)
				if latest == nil {
					Errorf("latest FEInterfaceMethod not found for signature %q", cached.Func.Signature)
				} else {
					// Copy CodeQL object:
					latest.CodeQL.IsEnabled = cached.CodeQL.IsEnabled
					if doCopy {
						{
							// Initialize block:
							width := 1 + len(latest.Func.Parameters) + len(latest.Func.Results)
							latest.CodeQL.Blocks = make([]*FlowBlock, 0)
							latest.CodeQL.Blocks = append(
								latest.CodeQL.Blocks,
								&FlowBlock{
									Inp:  make([]bool, width),
									Outp: make([]bool, width),
								},
							)

							// Copy legacy pointers into first block:
							{
								inp := cached.CodeQL.Pointers.Inp
								switch inp.Element {
								case ElementReceiver:
									latest.CodeQL.Blocks[0].Inp[0] = true
								case ElementParameter:
									latest.CodeQL.Blocks[0].Inp[inp.Index+1] = true
								case ElementResult:
									latest.CodeQL.Blocks[0].Inp[inp.Index+len(latest.Func.Parameters)+1] = true
								}
							}
							{
								outp := cached.CodeQL.Pointers.Outp
								switch outp.Element {
								case ElementReceiver:
									latest.CodeQL.Blocks[0].Outp[0] = true
								case ElementParameter:
									latest.CodeQL.Blocks[0].Outp[outp.Index+1] = true
								case ElementResult:
									latest.CodeQL.Blocks[0].Outp[outp.Index+len(latest.Func.Parameters)+1] = true
								}
							}
						}
					}
				}
			}
		}
	}

	{
		// try to use v2 cache:
		if cacheExists {
			cachedMap := make(CacheType)
			// Load cache:
			Infof("Loading cached feModule from %q", cacheFilepath)
			err := LoadJSON(&cachedMap, cacheFilepath)
			if err != nil {
				panic(err)
			}

			findLatestFunc := func(signature string) *FEFunc {
				for _, latest := range feModule.Funcs {
					if latest.Signature == signature {
						return latest
					}
				}
				return nil
			}
			findLatestTypeMethod := func(signature string) *FETypeMethod {
				for _, latest := range feModule.TypeMethods {
					if latest.Func.Signature == signature {
						return latest
					}
				}
				return nil
			}
			findLatestInterfaceMethod := func(signature string) *FEInterfaceMethod {
				for _, latest := range feModule.InterfaceMethods {
					if latest.Func.Signature == signature {
						return latest
					}
				}
				return nil
			}

			// NOTE: we are searching all-to-some, so there will be a lot of "not found" messages here:
			for signature, cached := range cachedMap {
				latest := findLatestFunc(signature)
				if latest == nil {
					Warnf("latest FEFunc not found for signature %q", signature)
				} else {
					// Copy CodeQL object:
					latest.CodeQL = cached
				}
			}
			for signature, cached := range cachedMap {
				latest := findLatestTypeMethod(signature)
				if latest == nil {
					Warnf("latest FETypeMethod not found for signature %q", signature)
				} else {
					// Copy CodeQL object:
					latest.CodeQL = cached
				}
			}
			for signature, cached := range cachedMap {
				latest := findLatestInterfaceMethod(signature)
				if latest == nil {
					Warnf("latest FEInterfaceMethod not found for signature %q", signature)
				} else {
					// Copy CodeQL object:
					latest.CodeQL = cached
				}
			}
		}
	}

	//Q(feModule)
	lenFuncs := len(feModule.Funcs)
	lenTypeMethods := len(feModule.TypeMethods)
	lenInterfaceMethods := len(feModule.InterfaceMethods)
	lenTotal := lenFuncs + lenTypeMethods + lenInterfaceMethods
	Sfln(
		IndigoBG("package %q has %v funcs, %v methods on types, and %v methods on interfaces (total=%v)"),
		pk.Name,
		lenFuncs,
		lenTypeMethods,
		lenInterfaceMethods,
		lenTotal,
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

	go Notify(func(os.Signal) bool {
		mu.Lock()
		defer mu.Unlock()

		PopulateGeneratedClassCodeQL(feModule)

		{
			// Save cache:
			cacheFilepath := path.Join(cacheDir, FormatCodeQlName(feModule.PkgPath)+".v2.json")
			cacheMap := make(CacheType)
			{
				for _, v := range feModule.Funcs {
					cacheMap[v.Signature] = v.CodeQL
				}
				for _, v := range feModule.TypeMethods {
					cacheMap[v.Func.Signature] = v.CodeQL
				}
				for _, v := range feModule.InterfaceMethods {
					cacheMap[v.Func.Signature] = v.CodeQL
				}
			}
			Infof("Saving cache to %q", MustAbs(cacheFilepath))
			err := SaveAsIndentedJSON(cacheMap, cacheFilepath)
			if err != nil {
				panic(err)
			}
		}

		// Generate golang tests:
		file := NewTestFile(includeBoilerplace)
		testFuncNames := make([]string, 0)
		{
			for _, fe := range feModule.Funcs {
				if !fe.CodeQL.IsEnabled {
					continue
				}
				if err := fe.CodeQL.Validate(); err != nil {
					Errorf("invalid pointers for %q: %s", fe.Signature, err)
					continue
				}
				allCode := generateAll_Func(
					file,
					fe,
				)
				for _, codeEnvelope := range allCode {
					if codeEnvelope.Statement != nil {
						file.Add(codeEnvelope.Statement.Line())
						testFuncNames = append(testFuncNames, codeEnvelope.TestFuncName)
					} else {
						Warnf("NOTHING GENERATED")
					}
				}
			}
		}
		{
			for _, fe := range feModule.TypeMethods {
				if !fe.CodeQL.IsEnabled {
					continue
				}
				if err := fe.CodeQL.Validate(); err != nil {
					Errorf("invalid pointers for %q: %s", fe.Func.Signature, err)
					continue
				}
				allCode := generateAll_Method(
					file,
					fe,
				)
				for _, codeEnvelope := range allCode {
					if codeEnvelope.Statement != nil {
						file.Add(codeEnvelope.Statement.Line())
						testFuncNames = append(testFuncNames, codeEnvelope.TestFuncName)
					} else {
						Warnf("NOTHING GENERATED")
					}
				}
			}
		}
		{
			for _, fe := range feModule.InterfaceMethods {
				if !fe.CodeQL.IsEnabled {
					continue
				}
				if err := fe.CodeQL.Validate(); err != nil {
					Errorf("invalid pointers for %q: %s", fe.Func.Signature, err)
					continue
				}
				converted := FEIToFET(fe)
				allCode := generateAll_Method(
					file,
					converted,
				)
				for _, codeEnvelope := range allCode {
					if codeEnvelope.Statement != nil {
						file.Add(codeEnvelope.Statement.Line())
						testFuncNames = append(testFuncNames, codeEnvelope.TestFuncName)
					} else {
						Warnf("NOTHING GENERATED")
					}
				}
			}
		}
		{

			code := Func().
				Id("RunAllTaints_" + FormatCodeQlName(feModule.PkgPath)).
				Params().
				BlockFunc(func(group *Group) {
					for _, testFuncName := range testFuncNames {
						group.BlockFunc(func(testBlock *Group) {
							testBlock.Id("source").Op(":=").Id("newSource").Call()
							testBlock.Id(testFuncName).Call(Id("source"))
						})
					}
				})
			file.Add(code.Line())
		}
		if toStdout {
			fmt.Printf("%#v", file)
		}

		ts := time.Now()
		// Create subfolder for package for generated assets:
		packageAssetFolderName := FormatCodeQlName(feModule.PkgPath)
		packageAssetFolderPath := path.Join(generatedDir, packageAssetFolderName)
		MustCreateFolderIfNotExists(packageAssetFolderPath, 0750)
		// Create folder for assets generated during this run:
		thisRunAssetFolderName := FormatCodeQlName(feModule.PkgPath) + "_" + ts.Format(FilenameTimeFormat)
		thisRunAssetFolderPath := path.Join(packageAssetFolderPath, thisRunAssetFolderName)
		// Create a new assets folder inside the main assets folder:
		MustCreateFolderIfNotExists(thisRunAssetFolderPath, 0750)

		{
			// Save golang assets:
			assetFileName := FormatCodeQlName(feModule.PkgPath+"-TaintTracking") + ".go"
			assetFilepath := path.Join(thisRunAssetFolderPath, assetFileName)

			// Create file go test file:
			goFile, err := os.Create(assetFilepath)
			if err != nil {
				panic(err)
			}
			defer goFile.Close()

			// write generated Golang code to file:
			Infof("Saving golang assets to %q", MustAbs(assetFilepath))
			err = file.Render(goFile)
			if err != nil {
				panic(err)
			}
		}

		{
			// Generate codeQL tain-tracking classes and qll file:
			var buf bytes.Buffer

			fileHeader := `/**
 * Provides classes modeling security-relevant aspects of the standard libraries.
 */

import go` + "\n\n"

			moduleHeader := Sf(
				"/** Provides models of commonly used functions in the `%s` package. */\nmodule %s {",
				feModule.PkgPath,
				FormatCodeQlName(feModule.PkgPath+"-TaintTracking"),
			)
			buf.WriteString(fileHeader + moduleHeader)
			err := GenerateCodeQLTT_Functions(&buf, feModule.Funcs)
			if err != nil {
				panic(err)
			}
			err = GenerateCodeQLTT_TypeMethods(&buf, feModule.TypeMethods)
			if err != nil {
				panic(err)
			}
			err = GenerateCodeQLTT_InterfaceMethods(&buf, feModule.InterfaceMethods)
			if err != nil {
				panic(err)
			}

			buf.WriteString("\n}")

			if toStdout {
				fmt.Println(buf.String())
			}

			// Save codeql assets:
			assetFileName := FormatCodeQlName(feModule.PkgPath) + ".qll"
			assetFilepath := path.Join(thisRunAssetFolderPath, assetFileName)

			// Create file qll file:
			qllFile, err := os.Create(assetFilepath)
			if err != nil {
				panic(err)
			}
			defer qllFile.Close()

			// write generated codeql code to file:
			Infof("Saving codeql assets to %q", MustAbs(assetFilepath))
			_, err = buf.WriteTo(qllFile)
			if err != nil {
				panic(err)
			}
		}

		os.Exit(0)
		return false
	}, os.Kill, os.Interrupt)

	if runServer {
		r := gin.Default()
		r.StaticFile("", "./index.html")
		r.Static("/static", "./static")

		r.GET("/api/source", func(c *gin.Context) {
			mu.Lock()
			defer mu.Unlock()

			PopulateGeneratedClassCodeQL(feModule)

			c.IndentedJSON(200, feModule)
		})
		r.POST("/api/disable", func(c *gin.Context) {
			var req PayloadDisable
			err := c.BindJSON(&req)
			if err != nil {
				Errorf("error binding JSON: %s", err)
				c.Status(400)
				return
			}
			Q(req)

			if req.Signature == "" {
				Errorf("req.Signature not set")
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

			if req.Enabled {
				Infof("enabling %q", req.Signature)
			} else {
				Infof("disabling %q", req.Signature)
			}

			switch stored.original.(type) {
			case *FEFunc:
				{
					fe := stored.GetFEFunc()
					if req.Enabled {
						// partially validate before enabling:
						if err := fe.CodeQL.Validate(); err == nil {
							fe.CodeQL.IsEnabled = true
						}
					} else {
						fe.CodeQL.IsEnabled = false
					}

				}
			case *FETypeMethod, *FEInterfaceMethod:
				{
					fe := stored.GetFETypeMethodOrInterfaceMethod()
					if req.Enabled {
						// partially validate before enabling:
						if err := fe.CodeQL.Validate(); err == nil {
							fe.CodeQL.IsEnabled = true
						}
					} else {
						fe.CodeQL.IsEnabled = false
					}
				}
			}

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
				Errorf("invalid request for %q: %s", req.Signature, err)
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

			switch stored.original.(type) {
			case *FEFunc:
				{
					fe := stored.GetFEFunc()
					{
						if err := validateBlockLen_FEFunc(fe, req.Blocks...); err != nil {
							Errorf(
								"error validating block: %s", err,
							)
							c.Status(400)
							return
						}
					}

					fe.CodeQL.Blocks = req.Blocks
					fe.CodeQL.IsEnabled = true

					{
						generatedCodeql := new(bytes.Buffer)
						err := GenerateCodeQLTT_Functions(generatedCodeql, []*FEFunc{fe})
						if err != nil {
							Errorf("error generating codeql: %s", err)
							c.Status(400)
							return
						}
						Ln(generatedCodeql)

						{
							c.IndentedJSON(
								200,
								GeneratedClassResponse{
									GeneratedClass: generatedCodeql.String(),
								},
							)
							return
						}
					}

				}
			case *FETypeMethod, *FEInterfaceMethod:
				{
					fe := stored.GetFETypeMethodOrInterfaceMethod()
					{
						if err := validateBlockLen_FEMethod(fe, req.Blocks...); err != nil {
							Errorf(
								"error validating block: %s", err,
							)
							c.Status(400)
							return
						}
					}
					fe.CodeQL.Blocks = req.Blocks
					fe.CodeQL.IsEnabled = true

					{
						generatedCodeql := new(bytes.Buffer)
						st := stored.GetFETypeMethod()
						if st != nil {
							err := GenerateCodeQLTT_TypeMethods(generatedCodeql, []*FETypeMethod{st})
							if err != nil {
								Errorf("error generating codeql: %s", err)
								c.Status(400)
								return
							}
						} else {
							st := stored.GetFEInterfaceMethod()
							err := GenerateCodeQLTT_InterfaceMethods(generatedCodeql, []*FEInterfaceMethod{st})
							if err != nil {
								Errorf("error generating codeql: %s", err)
								c.Status(400)
								return
							}
						}

						Ln(generatedCodeql)

						{
							c.IndentedJSON(
								200,
								GeneratedClassResponse{
									GeneratedClass: generatedCodeql.String(),
								},
							)
							return
						}
					}
				}
			default:
				panic(Sf("unknown type for %v", stored.original))
			}

		})

		r.Run() // listen and serve on 0.0.0.0:8080
	}
}

type GeneratedClassResponse struct {
	GeneratedClass string
}

func PopulateGeneratedClassCodeQL(feModule *FEModule) error {
	for i := range feModule.Funcs {
		fe := feModule.Funcs[i]
		if err := fe.CodeQL.Validate(); err == nil {
			generatedCodeqlClass := new(bytes.Buffer)
			err := GenerateCodeQLTT_Functions(generatedCodeqlClass, []*FEFunc{fe})
			if err != nil {
				return fmt.Errorf("error generating codeql conditions for %q: %s", fe.Signature, err)
			}
			fe.CodeQL.GeneratedClass = generatedCodeqlClass.String()
		}
	}
	for i := range feModule.TypeMethods {
		fe := feModule.TypeMethods[i]
		if err := fe.CodeQL.Validate(); err == nil {
			generatedCodeqlClass := new(bytes.Buffer)
			err := GenerateCodeQLTT_TypeMethods(generatedCodeqlClass, []*FETypeMethod{fe})
			if err != nil {
				return fmt.Errorf("error generating codeql conditions for %q: %s", fe.Func.Signature, err)
			}
			fe.CodeQL.GeneratedClass = generatedCodeqlClass.String()
		}
	}
	for i := range feModule.InterfaceMethods {
		fe := feModule.InterfaceMethods[i]
		if err := fe.CodeQL.Validate(); err == nil {
			generatedCodeqlClass := new(bytes.Buffer)
			err := GenerateCodeQLTT_InterfaceMethods(generatedCodeqlClass, []*FEInterfaceMethod{fe})
			if err != nil {
				return fmt.Errorf("error generating codeql conditions for %q: %s", fe.Func.Signature, err)
			}
			fe.CodeQL.GeneratedClass = generatedCodeqlClass.String()
		}
	}

	return nil
}

func GenerateCodeQLTT_Functions(buf *bytes.Buffer, fes []*FEFunc) error {
	tpl, err := NewTextTemplateFromFile("./templates/taint-tracking_function.txt")
	if err != nil {
		return err
	}

	for _, fe := range fes {
		if !fe.CodeQL.IsEnabled {
			continue
		}
		if err := fe.CodeQL.Validate(); err != nil {
			Errorf("invalid pointers for %q: %s", fe.Signature, err)
			continue
		}
		buf.WriteString("\n")

		generatedConditions, err := generateCodeQLFlowConditions_FEFunc(fe, fe.CodeQL.Blocks)
		if err != nil {
			return fmt.Errorf("error generating codeql conditions for %q: %s", fe.Signature, err)
		}
		fe.CodeQL.GeneratedConditions = PadNewLines(generatedConditions)

		err = tpl.Execute(buf, fe)
		if err != nil {
			return fmt.Errorf("error while executing template for func %q: %s", fe.ID, err)
		}
	}

	return nil
}
func GenerateCodeQLTT_TypeMethods(buf *bytes.Buffer, fes []*FETypeMethod) error {
	tpl, err := NewTextTemplateFromFile("./templates/taint-tracking_type-method.txt")
	if err != nil {
		return err
	}

	for _, fe := range fes {
		if !fe.CodeQL.IsEnabled {
			continue
		}
		if err := fe.CodeQL.Validate(); err != nil {
			Errorf("invalid pointers for %q: %s", fe.Func.Signature, err)
			continue
		}
		buf.WriteString("\n")

		generatedConditions, err := generateCodeQLFlowConditions_FEMethod(fe, fe.CodeQL.Blocks)
		if err != nil {
			return fmt.Errorf("error generating codeql conditions for %q: %s", fe.Func.Signature, err)
		}
		fe.CodeQL.GeneratedConditions = PadNewLines(generatedConditions)

		err = tpl.Execute(buf, fe)
		if err != nil {
			return fmt.Errorf("error while executing template for type-method %q: %s", fe.ID, err)
		}
	}

	return nil
}
func GenerateCodeQLTT_InterfaceMethods(buf *bytes.Buffer, fes []*FEInterfaceMethod) error {
	tpl, err := NewTextTemplateFromFile("./templates/taint-tracking_interface-method.txt")
	if err != nil {
		return err
	}

	for _, fe := range fes {
		if !fe.CodeQL.IsEnabled {
			continue
		}
		if err := fe.CodeQL.Validate(); err != nil {
			Errorf("invalid pointers for %q: %s", fe.Func.Signature, err)
			continue
		}
		buf.WriteString("\n")

		generatedConditions, err := generateCodeQLFlowConditions_FEMethod(FEIToFET(fe), fe.CodeQL.Blocks)
		if err != nil {
			return fmt.Errorf("error generating codeql conditions for %q: %s", fe.Func.Signature, err)
		}
		fe.CodeQL.GeneratedConditions = PadNewLines(generatedConditions)

		err = tpl.Execute(buf, fe)
		if err != nil {
			return fmt.Errorf("error while executing template for interface-method %q: %s", fe.ID, err)
		}
	}

	return nil
}

func PadNewLines(s string) string {
	var res string
	scanner := bufio.NewScanner(strings.NewReader(s))
	tot := strings.Count(s, "\n")
	for i := 0; scanner.Scan(); i++ {
		var padding = ""
		if i > 0 {
			padding = RepeatString(8, " ")
		}
		res += Sf("%s%s", padding, scanner.Text())
		isLast := i == tot
		if !isLast {
			res += "\n"
		}
	}
	return res
}
func NewTestFile(includeBoilerplace bool) *File {
	file := NewFile("main")
	// Set a prefix to avoid collision between variable names and packages:
	file.PackagePrefix = "cql"

	if includeBoilerplace {
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
		{
			// newSource functions returns a new tainted thing:
			code := Func().
				Id("newSource").
				Params().
				Interface().Block(Return(Nil()))
			file.Add(code.Line())
		}
	}
	return file
}

// ShouldUseAlias tells whether the package name and the base
// of the backage path are the same; if they are not,
// then the package should use an alias in the import.
func ShouldUseAlias(pkgPath string, pkgName string) bool {
	return filepath.Base(pkgPath) != pkgName
}

func generate_Func(file *File, fe *FEFunc, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	Parameter := ElementParameter
	Result := ElementResult

	switch {
	case identityInp.Element == Parameter && identityOutp.Element == Parameter:
		return generate_ParaFuncPara(file, fe, identityInp, identityOutp)
	case identityInp.Element == Parameter && identityOutp.Element == Result:
		return generate_ParaFuncResu(file, fe, identityInp, identityOutp)
	case identityInp.Element == Result && identityOutp.Element == Parameter:
		return generate_ResuFuncPara(file, fe, identityInp, identityOutp)
	case identityInp.Element == Result && identityOutp.Element == Result:
		return generate_ResuFuncResu(file, fe, identityInp, identityOutp)
	default:
		panic(Sf("unhandled case: identityInp.Element %v, identityOutp.Element %v", identityInp.Element, identityOutp.Element))
	}

	return nil
}

func generate_Method(file *File, fe *FETypeMethod, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	Receiver := ElementReceiver
	Parameter := ElementParameter
	Result := ElementResult

	switch {
	case identityInp.Element == Receiver && identityOutp.Element == Parameter:
		return generate_ReceMethPara(file, fe, identityInp, identityOutp)
	case identityInp.Element == Receiver && identityOutp.Element == Result:
		return generate_ReceMethResu(file, fe, identityInp, identityOutp)
	case identityInp.Element == Parameter && identityOutp.Element == Receiver:
		return generate_ParaMethRece(file, fe, identityInp, identityOutp)
	case identityInp.Element == Parameter && identityOutp.Element == Parameter:
		return generate_ParaMethPara(file, fe, identityInp, identityOutp)
	case identityInp.Element == Parameter && identityOutp.Element == Result:
		return generate_ParaMethResu(file, fe, identityInp, identityOutp)
	case identityInp.Element == Result && identityOutp.Element == Receiver:
		return generate_ResuMethRece(file, fe, identityInp, identityOutp)
	case identityInp.Element == Result && identityOutp.Element == Parameter:
		return generate_ResuMethPara(file, fe, identityInp, identityOutp)
	case identityInp.Element == Result && identityOutp.Element == Result:
		return generate_ResuMethResu(file, fe, identityInp, identityOutp)
	default:
		panic(Sf("unhandled case: identityInp.Element %v,  identityOutp.Element %v", identityInp.Element, identityOutp.Element))
	}

	return nil
}

func getPlaceholder(element Element, index int, fe *FEFunc) string {
	switch element {
	case ElementParameter:
		return fe.Parameters[index].Identity.Placeholder
	case ElementResult:
		return fe.Results[index].Identity.Placeholder
	default:
		panic(Sf("not valid pointers.Inp.Element: %s", element))
	}
}

func getPlaceholderFromFunc(fe *FEFunc, ident *CodeQlIdentity) string {
	element := ident.Element
	index := ident.Index
	return getPlaceholder(element, index, fe)
}

func getPlaceholderFromMethod(fe *FETypeMethod, ident *CodeQlIdentity) string {
	element := ident.Element
	index := ident.Index
	switch element {
	case ElementReceiver:
		return fe.Receiver.Identity.Placeholder
	case ElementParameter, ElementResult:
		return getPlaceholder(element, index, fe.Func)
	default:
		panic(Sf("not valid pointers.Inp.Element: %s", element))
	}
}

func generate_ReceMethPara(file *File, fe *FETypeMethod, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	// from: receiver
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: param

	indexIn := identityInp.Index
	indexOut := identityOutp.Index
	_ = indexIn

	in := fe.Receiver
	out := fe.Func.Parameters[indexOut]

	in.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("from", in.TypeName))
	out.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

			groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			composeTypeAssertion(file, groupCase, in.VarName, in.original)

			groupCase.Line().Comment(Sf("Declare `%s` variable:", outVarName))
			composeVarDeclaration(file, groupCase, out.VarName, out.original.GetType())

			groupCase.
				Line().Comment("Call the method that transfers the taint").
				Line().Comment(Sf("from the receiver `%s` to the argument `%s`", in.VarName, out.VarName)).
				Line().Comment(Sf("(`%s` is now tainted).", out.VarName))

			importPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

			groupCase.Id(in.VarName).Dot(fe.Func.Name).CallFunc(
				func(call *Group) {

					tpFun := fe.Func.original.GetType().(*types.Signature)

					zeroVals := scanTupleOfZeroValues(file, tpFun.Params(), fe.Func.original.IsVariadic())

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
	return code.Line()
}
func generate_ReceMethResu(file *File, fe *FETypeMethod, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	// from: receiver
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: result

	indexIn := identityInp.Index
	indexOut := identityOutp.Index
	_ = indexIn

	in := fe.Receiver
	out := fe.Func.Results[indexOut]

	in.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("from", in.TypeName))
	out.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

			groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			composeTypeAssertion(file, groupCase, in.VarName, in.original)

			groupCase.
				Line().Comment("Call the method that transfers the taint").
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

					zeroVals := scanTupleOfZeroValues(file, tpFun.Params(), fe.Func.original.IsVariadic())

					for _, zero := range zeroVals {
						call.Add(zero)
					}

				},
			)

			groupCase.Line().Comment(Sf("Sink the tainted `%s`:", outVarName))
			groupCase.Id("sink").Call(Id(out.VarName))
		})
	return code.Line()
}
func generate_ParaMethRece(file *File, fe *FETypeMethod, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	// from: param
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: receiver

	indexIn := identityInp.Index
	indexOut := identityOutp.Index
	_ = indexOut

	in := fe.Func.Parameters[indexIn]
	out := fe.Receiver

	in.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("from", in.TypeName))
	out.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

			groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

			groupCase.Line().Comment(Sf("Declare `%s` variable:", outVarName))
			composeVarDeclaration(file, groupCase, out.VarName, out.original)

			groupCase.
				Line().Comment("Call the method that transfers the taint").
				Line().Comment(Sf("from the parameter `%s` to the receiver `%s`", in.VarName, out.VarName)).
				Line().Comment(Sf("(`%s` is now tainted).", out.VarName))

			importPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

			groupCase.Id(out.VarName).Dot(fe.Func.Name).CallFunc(
				func(call *Group) {

					tpFun := fe.Func.original.GetType().(*types.Signature)

					zeroVals := scanTupleOfZeroValues(file, tpFun.Params(), fe.Func.original.IsVariadic())

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
	return code.Line()
}
func generate_ParaMethPara(file *File, fe *FETypeMethod, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	// from: param
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: param

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Func.Parameters[indexIn]
	out := fe.Func.Parameters[indexOut]

	in.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("from", in.TypeName))
	out.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

			groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

			groupCase.Line().Comment(Sf("Declare `%s` variable:", outVarName))
			composeVarDeclaration(file, groupCase, out.VarName, out.original.GetType())

			groupCase.Line().Comment("Declare medium object/interface:")
			groupCase.Var().Id("mediumObjCQL").Qual(fe.Receiver.PkgPath, fe.Receiver.TypeName)

			groupCase.
				Line().Comment("Call the method that transfers the taint").
				Line().Comment(Sf("from the parameter `%s` to the parameter `%s`", in.VarName, out.VarName)).
				Line().Comment(Sf("(`%s` is now tainted).", out.VarName))

			importPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

			groupCase.Id("mediumObjCQL").Dot(fe.Func.Name).CallFunc(
				func(call *Group) {

					tpFun := fe.Func.original.GetType().(*types.Signature)

					zeroVals := scanTupleOfZeroValues(file, tpFun.Params(), fe.Func.original.IsVariadic())

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
	return code.Line()
}
func generate_ParaMethResu(file *File, fe *FETypeMethod, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	// from: param
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: result

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Func.Parameters[indexIn]
	out := fe.Func.Results[indexOut]

	in.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("from", in.TypeName))
	out.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

			groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

			groupCase.Line().Comment("Declare medium object/interface:")
			groupCase.Var().Id("mediumObjCQL").Qual(fe.Receiver.PkgPath, fe.Receiver.TypeName)

			groupCase.
				Line().Comment("Call the method that transfers the taint").
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
			}).Op(":=").Id("mediumObjCQL").Dot(fe.Func.Name).CallFunc(
				func(call *Group) {

					tpFun := fe.Func.original.GetType().(*types.Signature)

					zeroVals := scanTupleOfZeroValues(file, tpFun.Params(), fe.Func.original.IsVariadic())

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
	return code.Line()
}
func generate_ResuMethRece(file *File, fe *FETypeMethod, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	// from: result
	// medium: method
	// into: receiver

	indexIn := identityInp.Index
	indexOut := identityOutp.Index
	_ = indexOut

	in := fe.Func.Results[indexIn]
	out := fe.Receiver

	in.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("from", in.TypeName))
	out.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

			groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

			groupCase.Line().Comment(Sf("Declare `%s` variable:", outVarName))
			composeVarDeclaration(file, groupCase, out.VarName, out.original)

			groupCase.
				Line().Comment("Call the method that will transfer the taint").
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

					zeroVals := scanTupleOfZeroValues(file, tpFun.Params(), fe.Func.original.IsVariadic())

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
	return code.Line()
}
func generate_ResuMethPara(file *File, fe *FETypeMethod, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	// from: result
	// medium: method
	// into: parameter

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Func.Results[indexIn]
	out := fe.Func.Parameters[indexOut]

	in.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("from", in.TypeName))
	out.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

			groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

			groupCase.Line().Comment(Sf("Declare `%s` variable:", outVarName))
			composeVarDeclaration(file, groupCase, out.VarName, out.original.GetType())

			groupCase.Line().Comment("Declare medium object/interface:")
			groupCase.Var().Id("mediumObjCQL").Qual(fe.Receiver.PkgPath, fe.Receiver.TypeName)

			groupCase.
				Line().Comment("Call the method that transfers the taint").
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
			}).Op(":=").Id("mediumObjCQL").Dot(fe.Func.Name).CallFunc(
				func(call *Group) {

					tpFun := fe.Func.original.GetType().(*types.Signature)

					zeroVals := scanTupleOfZeroValues(file, tpFun.Params(), fe.Func.original.IsVariadic())

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
	return code.Line()
}

func JoinDash(elems ...string) string {
	return strings.Join(elems, "-")
}
func LowerCaseFirst(str string) string {
	for i, v := range str {
		return string(unicode.ToLower(v)) + str[i+1:]
	}
	return ""
}
func NewLowerTitleCodeQlName(elems ...string) string {
	return LowerCaseFirst(NewCodeQlName(elems...))
}
func NewCodeQlName(elems ...string) string {
	return FormatCodeQlName(JoinDash(elems...))
}
func generate_ResuMethResu(file *File, fe *FETypeMethod, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	// from: result
	// medium: method
	// into: result

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Func.Results[indexIn]
	out := fe.Func.Results[indexOut]

	in.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("from", in.TypeName))
	out.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

			groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

			groupCase.Line().Comment("Declare medium object/interface:")
			groupCase.Var().Id("mediumObjCQL").Qual(fe.Receiver.PkgPath, fe.Receiver.TypeName)

			groupCase.
				Line().Comment("Call the method that transfers the taint").
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
			}).Op(":=").Id("mediumObjCQL").Dot(fe.Func.Name).CallFunc(
				func(call *Group) {

					tpFun := fe.Func.original.GetType().(*types.Signature)

					zeroVals := scanTupleOfZeroValues(file, tpFun.Params(), fe.Func.original.IsVariadic())

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
	return code.Line()
}

func NewNameWithPrefix(prefix string) string {
	return Sf("%s%v", prefix, RandomIntRange(111, 999))
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
func generate_ParaFuncPara(file *File, fe *FEFunc, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	// from: param
	// medium: func
	// into: param

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Parameters[indexIn]
	out := fe.Parameters[indexOut]

	in.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("from", in.TypeName))
	out.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

			groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

			groupCase.Line().Comment(Sf("Declare `%s` variable:", outVarName))
			composeVarDeclaration(file, groupCase, out.VarName, out.original.GetType())

			groupCase.
				Line().Comment("Call the function that transfers the taint").
				Line().Comment(Sf("from the parameter `%s` to parameter `%s`;", inVarName, outVarName)).
				Line().Comment(Sf("`%s` is now tainted.", outVarName))

			importPackage(file, fe.PkgPath, fe.PkgName)

			groupCase.Qual(fe.PkgPath, fe.Name).CallFunc(
				func(call *Group) {

					tpFun := fe.original.GetType().(*types.Signature)

					zeroVals := scanTupleOfZeroValues(file, tpFun.Params(), fe.original.IsVariadic())

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

	return code.Line()
}

func generate_ParaFuncResu(file *File, fe *FEFunc, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	// from: param
	// medium: func
	// into: result

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Parameters[indexIn]
	out := fe.Results[indexOut]

	in.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("from", in.TypeName))
	out.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
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
				Line().Comment("Call the function that transfers the taint").
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

					zeroVals := scanTupleOfZeroValues(file, tpFun.Params(), fe.original.IsVariadic())

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
	return code.Line()
}
func generate_ResuFuncPara(file *File, fe *FEFunc, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	// from: result
	// medium: func
	// into: param
	// NOTE: does this actually happen? It needs extra steps, right?

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Results[indexIn]
	out := fe.Parameters[indexOut]

	in.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("from", in.TypeName))
	out.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

			groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())

			groupCase.Line().Comment(Sf("Declare `%s` variable:", out.VarName))
			composeVarDeclaration(file, groupCase, out.VarName, out.original.GetType())
			importPackage(file, out.PkgPath, out.PkgName)

			groupCase.
				Line().Comment("Call the function that will transfer the taint").
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

					zeroVals := scanTupleOfZeroValues(file, tpFun.Params(), fe.original.IsVariadic())

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
	return code.Line()
}
func generate_ResuFuncResu(file *File, fe *FEFunc, identityInp *CodeQlIdentity, identityOutp *CodeQlIdentity) *Statement {
	// from: result
	// medium: func
	// into: result

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Results[indexIn]
	out := fe.Results[indexOut]

	in.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("from", in.TypeName))
	out.VarName = NewNameWithPrefix(NewLowerTitleCodeQlName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			groupCase.Comment(Sf("The flow is from `%s` into `%s`.", inVarName, outVarName)).Line()

			groupCase.Comment(Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			composeTypeAssertion(file, groupCase, in.VarName, in.original.GetType())
			importPackage(file, out.PkgPath, out.PkgName)

			groupCase.
				Line().Comment("Call the function that transfers the taint").
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

					zeroVals := scanTupleOfZeroValues(file, tpFun.Params(), fe.original.IsVariadic())

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
	return code.Line()
}

func scanTupleOfZeroValues(file *File, tuple *types.Tuple, isVariadic bool) []Code {

	result := make([]Code, 0)

	for i := 0; i < tuple.Len(); i++ {
		tp := newStatement()

		isLast := i == tuple.Len()-1
		if isLast && isVariadic {
			composeZeroDeclaration(file, tp, tuple.At(i).Type().(*types.Slice).Elem())
		} else {
			composeZeroDeclaration(file, tp, tuple.At(i).Type())
		}
		result = append(result, tp)
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
					{
						// TODO: check if has at least one method?
						// Get receiver info from the first explicit method:
						meth := t.ExplicitMethod(0)
						methFunc := meth.Type().(*types.Signature)
						pkgPath := scanner.RemoveGoPath(methFunc.Recv().Pkg())
						pkgName := methFunc.Recv().Pkg().Name()
						typeName := methFunc.Recv().Name()

						importPackage(file, pkgPath, pkgName)
						stat.Qual(pkgPath, typeName)
					}
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
			if t.Obj() != nil && t.Obj().Name() == "error" {
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

type PayloadDisable struct {
	Signature string
	Enabled   bool
}
type PayloadSetPointers struct {
	Signature string
	Blocks    []*FlowBlock
}

//
func (req *PayloadSetPointers) Validate() error {
	if req.Signature == "" {
		return errors.New("req.Signature is not set")
	}
	if err := validateBlocksAreActive(req.Blocks...); err != nil {
		return fmt.Errorf(
			"error validating block: %s", err,
		)
	}

	return nil
}

func FormatCodeQlName(name string) string {
	return ToCamel(strings.ReplaceAll(name, "\"", ""))
}

const TODO = "TODO"

type CodeQLPointers struct {
	Inp  *CodeQlIdentity
	Outp *CodeQlIdentity
}

func (obj *CodeQLPointers) Validate() error {
	if obj.Inp == nil {
		return errors.New("obj.Inp is not set")
	}
	if obj.Outp == nil {
		return errors.New("obj.Outp is not set")
	}

	if err := obj.Inp.Identity.Validate(); err != nil {
		return err
	}
	if err := obj.Outp.Validate(); err != nil {
		return err
	}

	if obj.Inp.Identity.Element == obj.Outp.Identity.Element && (obj.Inp.Identity.Element == ElementReceiver || (obj.Inp.Identity.Index == obj.Outp.Identity.Index)) {
		return errors.New("obj.Inp and obj.Outp have same values")
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
	return &CodeQlFinalVals{}
}
func (obj *CodeQlFinalVals) Validate() error {
	if obj.Blocks == nil || len(obj.Blocks) == 0 {
		return errors.New("obj.Blocks is not set")
	}
	if err := validateBlocksAreActive(obj.Blocks...); err != nil {
		return err
	}

	return nil
}

func validateBlocksAreActive(blocks ...*FlowBlock) error {
	if len(blocks) == 0 {
		return errors.New("no blocks provided")
	}
	for blockIndex, block := range blocks {
		if AllFalse(block.Inp...) {
			return fmt.Errorf("error: Inp of block %v is all false", blockIndex)
		}
		if AllFalse(block.Outp...) {
			return fmt.Errorf("error: Outp of block %v is all false", blockIndex)
		}
	}
	return nil
}

type CodeQlFinalVals struct {
	// Generated generated contains the generated class:
	GeneratedClass string
	// GeneratedConditions contains the generated conditions of the flow:
	GeneratedConditions string
	Blocks              []*FlowBlock
	IsEnabled           bool
	//Pointers            *CodeQLPointers // Pointers is where the current pointers will be stored
}

type DEPRECATEDFEModule struct {
	Funcs            []*DEPRECATEDFEFunc
	TypeMethods      []*DEPRECATEDFETypeMethod
	InterfaceMethods []*DEPRECATEDFETypeMethod
}

type DEPRECATEDFEFunc struct {
	CodeQL    *DEPRECATEDCodeQlFinalVals
	Signature string
}
type DEPRECATEDFETypeMethod struct {
	CodeQL *DEPRECATEDCodeQlFinalVals
	Func   *DEPRECATEDFEFunc
}
type DEPRECATEDCodeQlFinalVals struct {
	IsEnabled bool
	Pointers  *CodeQLPointers // Pointers is where the current pointers will be stored
}

type Identity struct {
	Element    Element
	Index      int
	IsVariadic bool
}
type CodeQlIdentity struct {
	Placeholder string
	Identity
}
type FEModule struct {
	Name             string
	PkgPath          string
	PkgName          string
	ID               string
	Funcs            []*FEFunc
	TypeMethods      []*FETypeMethod
	InterfaceMethods []*FEInterfaceMethod
}

type FEFunc struct {
	CodeQL    *CodeQlFinalVals
	ClassName string
	Signature string
	ID        string
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
	fe.ClassName = FormatCodeQlName(fn.Name)
	fe.Name = fn.Name
	fe.PkgName = fn.PkgName
	fe.ID = FormatCodeQlName("function-" + fn.Name)
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
				Element:    ElementParameter,
				Index:      i,
				IsVariadic: v.IsVariadic,
			},
		}
		fe.Parameters = append(fe.Parameters, v)
	}
	for i, out := range fn.Output {
		v := getFEType(out)

		placeholder := Sf("isResult(%v)", i)
		if len(fn.Output) == 1 {
			placeholder = "isResult()"
		}
		v.Identity = CodeQlIdentity{
			Placeholder: placeholder,
			Identity: Identity{
				Element:    ElementResult,
				Index:      i,
				IsVariadic: v.IsVariadic,
			},
		}
		fe.Results = append(fe.Results, v)
	}
	{
		width := len(fe.Parameters) + len(fe.Results)
		fe.CodeQL.Blocks = make([]*FlowBlock, 0)
		fe.CodeQL.Blocks = append(
			fe.CodeQL.Blocks,
			&FlowBlock{
				Inp:  make([]bool, width),
				Outp: make([]bool, width),
			},
		)
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
	TypeString    string
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
	if tp.IsVariadic() {
		fe.TypeString = "..." + tp.GetType().(*types.Slice).Elem().String()
	} else {
		fe.TypeString = tp.GetType().String()
	}

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
		fe.Receiver.PkgName = named.Obj().Pkg().Name()
		//fe.Receiver.VarName =
	}
	// Skip methods on non-exported types:
	if !token.IsExported(fe.Receiver.TypeName) {
		return nil
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
						fe.Func.CodeQL = nil
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

	fe.ID = "type-method-" + fe.Receiver.TypeName + "-" + methodFuncName
	fe.ClassName = FormatCodeQlName(fe.Receiver.TypeName + "-" + methodFuncName)

	{
		width := 1 + len(fe.Func.Parameters) + len(fe.Func.Results)
		fe.CodeQL.Blocks = make([]*FlowBlock, 0)
		fe.CodeQL.Blocks = append(
			fe.CodeQL.Blocks,
			&FlowBlock{
				Inp:  make([]bool, width),
				Outp: make([]bool, width),
			},
		)
	}
	return &fe
}

type FETypeMethod struct {
	CodeQL    *CodeQlFinalVals
	ClassName string
	Docs      []string
	IsOnPtr   bool
	Receiver  *FEReceiver
	ID        string
	Func      *FEFunc
	original  types.Type
}
type FEInterfaceMethod FETypeMethod

type FEReceiver struct {
	FEType
	original types.Type
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
	feFunc.CodeQL = nil
	{
		fe.Receiver.original = it.GetType()
		fe.Receiver.TypeName = it.Name
		fe.Receiver.QualifiedName = scanner.StringRemoveGoPath(feFunc.PkgPath) + "." + feFunc.Name
		fe.Receiver.PkgPath = scanner.StringRemoveGoPath(feFunc.PkgPath)
		fe.Receiver.PkgName = feFunc.PkgName
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

	fe.ID = "interface-method-" + fe.Receiver.TypeName + "-" + methodFuncName
	fe.ClassName = FormatCodeQlName(fe.Receiver.TypeName + "-" + methodFuncName)

	{
		width := 1 + len(fe.Func.Parameters) + len(fe.Func.Results)
		fe.CodeQL.Blocks = make([]*FlowBlock, 0)
		fe.CodeQL.Blocks = append(
			fe.CodeQL.Blocks,
			&FlowBlock{
				Inp:  make([]bool, width),
				Outp: make([]bool, width),
			},
		)
	}
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

type FlowBlock struct {
	Inp  []bool
	Outp []bool
}

type IdentityGetter func(block *FlowBlock) ([]*CodeQlIdentity, []*CodeQlIdentity, error)

func generateCodeQLFlowConditions_FEFunc(fn *FEFunc, blocks []*FlowBlock) (string, error) {
	return generateCodeQLFlowCondition_V2(
		fn,
		func(block *FlowBlock) ([]*CodeQlIdentity, []*CodeQlIdentity, error) {
			return getIdentities_FEFunc(fn, block)
		},
		blocks,
	)
}
func generateCodeQLFlowConditions_FEMethod(fn *FETypeMethod, blocks []*FlowBlock) (string, error) {
	return generateCodeQLFlowCondition_V2(
		fn.Func,
		func(block *FlowBlock) ([]*CodeQlIdentity, []*CodeQlIdentity, error) {
			return getIdentities_FEMethod(fn, block)
		},
		blocks,
	)
}
func gatherIdentitiesPerType(ids []*CodeQlIdentity) (recv *CodeQlIdentity, params []*CodeQlIdentity, results []*CodeQlIdentity) {
	for _, id := range ids {
		switch id.Element {
		case ElementReceiver:
			recv = id
		case ElementParameter:
			params = append(params, id)
		case ElementResult:
			results = append(results, id)
		}
	}
	return
}
func generateCodeQLFlowCondition(idGetter IdentityGetter, blocks []*FlowBlock) (string, error) {
	finalBuf := new(bytes.Buffer)
	for blockIndex, block := range blocks {
		inp, outp, err := idGetter(block)
		if err != nil {
			return "", err
		}
		if len(inp) == 0 {
			return "", fmt.Errorf("error: no inp specified for block %v", blockIndex)
		}
		if len(outp) == 0 {
			return "", fmt.Errorf("error: no outp specified for block %v", blockIndex)
		}

		buf := new(bytes.Buffer)
		{ //inp:
			buf.WriteString("(")
			for i, in := range inp {
				// TODO: add logic to do things like inp.isParameter([0,1,3])
				if i == 0 {
					buf.WriteString("inp." + in.Placeholder)
				} else {
					buf.WriteString(" or ")
					buf.WriteString("inp." + in.Placeholder)
				}
			}
			buf.WriteString(")")
		}

		buf.WriteString(" and ")
		{ // outp:
			buf.WriteString("(")
			for i, out := range outp {
				if i == 0 {
					buf.WriteString("outp." + out.Placeholder)
				} else {
					buf.WriteString(" or ")
					buf.WriteString("outp." + out.Placeholder)
				}
			}
			buf.WriteString(")")
		}

		// write to finalBuf
		if blockIndex > 0 {
			finalBuf.WriteString("\nor\n")
		}
		finalBuf.WriteString("(")
		buf.WriteTo(finalBuf)
		finalBuf.WriteString(")")
	}
	return finalBuf.String(), nil
}
func generateCodeQLFlowCondition_V2(fn *FEFunc, idGetter IdentityGetter, blocks []*FlowBlock) (string, error) {
	finalBuf := new(bytes.Buffer)
	for blockIndex, block := range blocks {
		inp, outp, err := idGetter(block)
		if err != nil {
			return "", err
		}
		if len(inp) == 0 {
			return "", fmt.Errorf("error: no inp specified for block %v", blockIndex)
		}
		if len(outp) == 0 {
			return "", fmt.Errorf("error: no outp specified for block %v", blockIndex)
		}

		buf := new(bytes.Buffer)
		{ //inp:
			buf.WriteString("(")

			recv, params, results := gatherIdentitiesPerType(inp)

			{ // recv:
				if recv != nil {
					buf.WriteString("inp." + recv.Placeholder)
				}
			}

			if len(params) > 0 {
				if recv != nil {
					buf.WriteString(" or ")
				}
				if len(params) == len(fn.Parameters) {
					if len(params) == 1 {
						if params[0].IsVariadic {
							buf.WriteString("inp.isParameter(_)")
						} else {
							buf.WriteString(Sf("inp.isParameter(%v)", params[0].Index))
						}
					} else {
						buf.WriteString("inp.isParameter(_)")
					}
				} else {
					if len(params) == 1 {
						if params[0].IsVariadic {
							buf.WriteString(Sf("inp.isParameter(%v)", Sf("any(int i | i >= %v)", params[0].Index)))
						} else {
							buf.WriteString(Sf("inp.isParameter(%v)", params[0].Index))
						}
					} else {
						paramsBuf := make([]string, 0)
						for _, param := range params {
							if param.IsVariadic {
								paramsBuf = append(paramsBuf, Sf("any(int i | i >= %v)", param.Index))
							} else {
								paramsBuf = append(paramsBuf, Itoa(param.Index))
							}
						}
						buf.WriteString(Sf("inp.isParameter([%s])", strings.Join(paramsBuf, ", ")))
					}
				}
			}
			if len(results) > 0 {
				if recv != nil || len(params) > 0 {
					buf.WriteString(" or ")
				}
				if len(results) == len(fn.Results) {
					if len(results) == 1 {
						buf.WriteString("inp.isResult()")
					} else {
						buf.WriteString("inp.isResult(_)")
					}
				} else {
					if len(results) == 1 {
						buf.WriteString(Sf("inp.isResult(%v)", results[0].Index))
					} else {
						resultsBuf := make([]string, 0)
						for _, param := range results {
							resultsBuf = append(resultsBuf, Itoa(param.Index))
						}
						buf.WriteString(Sf("inp.isResult([%s])", strings.Join(resultsBuf, ", ")))
					}
				}
			}

			buf.WriteString(")")
		}

		buf.WriteString(" and ")
		{ // outp:
			buf.WriteString("(")

			recv, params, results := gatherIdentitiesPerType(outp)

			{ // recv:
				if recv != nil {
					buf.WriteString("outp." + recv.Placeholder)
				}
			}

			if len(params) > 0 {
				if recv != nil {
					buf.WriteString(" or ")
				}
				if len(params) == len(fn.Parameters) {
					if len(params) == 1 {
						if params[0].IsVariadic {
							buf.WriteString("outp.isParameter(_)")
						} else {
							buf.WriteString(Sf("outp.isParameter(%v)", params[0].Index))
						}
					} else {
						buf.WriteString("outp.isParameter(_)")
					}
				} else {
					if len(params) == 1 {
						if params[0].IsVariadic {
							buf.WriteString(Sf("outp.isParameter(%v)", Sf("any(int i | i >= %v)", params[0].Index)))
						} else {
							buf.WriteString(Sf("outp.isParameter(%v)", params[0].Index))
						}
					} else {
						paramsBuf := make([]string, 0)
						for _, param := range params {
							if param.IsVariadic {
								paramsBuf = append(paramsBuf, Sf("any(int i | i >= %v)", param.Index))
							} else {
								paramsBuf = append(paramsBuf, Itoa(param.Index))
							}
						}
						buf.WriteString(Sf("outp.isParameter([%s])", strings.Join(paramsBuf, ", ")))
					}
				}
			}
			if len(results) > 0 {
				if recv != nil || len(params) > 0 {
					buf.WriteString(" or ")
				}
				if len(results) == len(fn.Results) {
					if len(results) == 1 {
						buf.WriteString("outp.isResult()")
					} else {
						buf.WriteString("outp.isResult(_)")
					}
				} else {
					if len(results) == 1 {
						buf.WriteString(Sf("outp.isResult(%v)", results[0].Index))
					} else {
						resultsBuf := make([]string, 0)
						for _, param := range results {
							resultsBuf = append(resultsBuf, Itoa(param.Index))
						}
						buf.WriteString(Sf("outp.isResult([%s])", strings.Join(resultsBuf, ", ")))
					}
				}
			}

			buf.WriteString(")")
		}

		// write to finalBuf
		if blockIndex > 0 {
			finalBuf.WriteString("\nor\n")
		}
		finalBuf.WriteString("(")
		buf.WriteTo(finalBuf)
		finalBuf.WriteString(")")
	}
	return finalBuf.String(), nil
}

func validateBlockLen_FEFunc(fn *FEFunc, blocks ...*FlowBlock) error {
	for blockIndex, block := range blocks {
		// check width:
		lenParameters := len(fn.Parameters)
		lenResults := len(fn.Results)
		totalWidth := lenParameters + lenResults

		if blockInpLen := len(block.Inp); blockInpLen != totalWidth {
			return fmt.Errorf("block %v: .Inp has wrong len: %v", blockIndex, blockInpLen)
		}
		if blockOutpLen := len(block.Outp); blockOutpLen != totalWidth {
			return fmt.Errorf("block %v: .Outp has wrong len: %v", blockIndex, blockOutpLen)
		}
	}

	return nil
}

func getIdentities_FEFunc(fn *FEFunc, block *FlowBlock) ([]*CodeQlIdentity, []*CodeQlIdentity, error) {

	lenParameters := len(fn.Parameters)

	if err := validateBlockLen_FEFunc(fn, block); err != nil {
		return nil, nil, err
	}
	identitiesInp := make([]*CodeQlIdentity, 0)
	for index, v := range block.Inp {
		if v == false {
			continue
		}
		if index < lenParameters {
			// get identity from parameters:
			id := fn.Parameters[index].Identity
			identitiesInp = append(identitiesInp, &id)
		} else {
			// get identity from results:
			id := fn.Results[index-lenParameters].Identity
			identitiesInp = append(identitiesInp, &id)
		}
	}

	identitiesOutp := make([]*CodeQlIdentity, 0)
	for index, v := range block.Outp {
		if v == false {
			continue
		}
		if index < lenParameters {
			// get identity from parameters:
			id := fn.Parameters[index].Identity
			identitiesOutp = append(identitiesOutp, &id)
		} else {
			// get identity from results:
			id := fn.Results[index-lenParameters].Identity
			identitiesOutp = append(identitiesOutp, &id)
		}
	}

	return identitiesInp, identitiesOutp, nil
}

func validateBlockLen_FEMethod(fn *FETypeMethod, blocks ...*FlowBlock) error {
	for blockIndex, block := range blocks {
		// check width:
		lenReceiver := 1
		lenParameters := len(fn.Func.Parameters)
		lenResults := len(fn.Func.Results)
		totalWidth := lenReceiver + lenParameters + lenResults

		if blockInpLen := len(block.Inp); blockInpLen != totalWidth {
			return fmt.Errorf("block %v: .Inp has wrong len: %v", blockIndex, blockInpLen)
		}
		if blockOutpLen := len(block.Outp); blockOutpLen != totalWidth {
			return fmt.Errorf("block %v: .Outp has wrong len: %v", blockIndex, blockOutpLen)
		}

	}

	return nil
}
func getIdentities_FEMethod(fe *FETypeMethod, block *FlowBlock) ([]*CodeQlIdentity, []*CodeQlIdentity, error) {

	lenParameters := len(fe.Func.Parameters)

	if err := validateBlockLen_FEMethod(fe, block); err != nil {
		return nil, nil, err
	}

	identitiesInp := make([]*CodeQlIdentity, 0)
	for index, v := range block.Inp {
		if v == false {
			continue
		}
		if index == 0 {
			// get identity from receiver:
			id := fe.Receiver.Identity
			identitiesInp = append(identitiesInp, &id)
		}
		if index > 0 && index <= lenParameters {
			// get identity from parameters:
			id := fe.Func.Parameters[index-1].Identity
			identitiesInp = append(identitiesInp, &id)
		}
		if index > lenParameters {
			// get identity from results:
			id := fe.Func.Results[index-lenParameters-1].Identity
			identitiesInp = append(identitiesInp, &id)
		}
	}

	identitiesOutp := make([]*CodeQlIdentity, 0)
	for index, v := range block.Outp {
		if v == false {
			continue
		}
		if index == 0 {
			// get identity from receiver:
			id := fe.Receiver.Identity
			identitiesOutp = append(identitiesOutp, &id)
		}
		if index > 0 && index <= lenParameters {
			// get identity from parameters:
			id := fe.Func.Parameters[index-1].Identity
			identitiesOutp = append(identitiesOutp, &id)
		}
		if index > lenParameters {
			// get identity from results:
			id := fe.Func.Results[index-lenParameters-1].Identity
			identitiesOutp = append(identitiesOutp, &id)
		}
	}

	return identitiesInp, identitiesOutp, nil
}
func mustGetFirstIdentity_Inp_FEFunc(fn *FEFunc) *CodeQlIdentity {
	inp, _, err := getIdentities_FEFunc(fn, fn.CodeQL.Blocks[0])
	if err != nil {
		panic(err)
	}
	return inp[0]
}
func mustGetFirstIdentity_Outp_FEFunc(fn *FEFunc) *CodeQlIdentity {
	_, outp, err := getIdentities_FEFunc(fn, fn.CodeQL.Blocks[0])
	if err != nil {
		panic(err)
	}
	return outp[0]
}
func mustGetFirstIdentity_Inp_FEMethod(fn *FETypeMethod) *CodeQlIdentity {
	inp, _, err := getIdentities_FEMethod(fn, fn.CodeQL.Blocks[0])
	if err != nil {
		panic(err)
	}
	return inp[0]
}
func mustGetFirstIdentity_Outp_FEMethod(fn *FETypeMethod) *CodeQlIdentity {
	_, outp, err := getIdentities_FEMethod(fn, fn.CodeQL.Blocks[0])
	if err != nil {
		panic(err)
	}
	return outp[0]
}

type StatementAndName struct {
	Statement    *Statement
	TestFuncName string
}

// for each block, generate a golang test function for each inp and outp combination.
func generateAll_Func(file *File, fe *FEFunc) []*StatementAndName {

	children := make([]*StatementAndName, 0)
	for blockIndex, block := range fe.CodeQL.Blocks {
		inps, outps, err := getIdentities_FEFunc(fe, block)
		if err != nil {
			panic(err)
		}

		for inpIndex, inp := range inps {
			for outpIndex, outp := range outps {

				childBlock := generate_Func(
					file,
					fe,
					inp,
					outp,
				)
				{
					if childBlock != nil {

						testFuncID := "TaintStepTest_" + FormatCodeQlName(fe.PkgPath+"-"+fe.Name) + Sf("_B%vI%vO%v", blockIndex, inpIndex, outpIndex)
						enclosed := Func().Id(testFuncID).
							ParamsFunc(
								func(group *Group) {
									group.Add(Id("sourceCQL").Interface())
								},
							).
							Add(childBlock)

						children = append(children, &StatementAndName{
							Statement:    enclosed,
							TestFuncName: testFuncID,
						})
					} else {
						Warnf(Sf("NOTHING GENERATED; block %v, inp %v, outp %v", blockIndex, inpIndex, outpIndex))
					}
				}
			}
		}
	}

	return children
}

// for each block, generate a golang test function for each inp and outp combination.
func generateAll_Method(file *File, fe *FETypeMethod) []*StatementAndName {

	children := make([]*StatementAndName, 0)
	for blockIndex, block := range fe.CodeQL.Blocks {
		inps, outps, err := getIdentities_FEMethod(fe, block)
		if err != nil {
			panic(err)
		}

		for inpIndex, inp := range inps {
			for outpIndex, outp := range outps {

				childBlock := generate_Method(
					file,
					fe,
					inp,
					outp,
				)
				{
					if childBlock != nil {

						testFuncID := "TaintStepTest_" + FormatCodeQlName(fe.Receiver.PkgPath+"-"+fe.ClassName) + Sf("_B%vI%vO%v", blockIndex, inpIndex, outpIndex)
						enclosed := Func().Id(testFuncID).
							ParamsFunc(
								func(group *Group) {
									group.Add(Id("sourceCQL").Interface())
								},
							).
							Add(childBlock)

						children = append(children, &StatementAndName{
							Statement:    enclosed,
							TestFuncName: testFuncID,
						})
					} else {
						Warnf(Sf("NOTHING GENERATED; block %v, inp %v, outp %v", blockIndex, inpIndex, outpIndex))
					}
				}
			}
		}
	}

	return children
}
