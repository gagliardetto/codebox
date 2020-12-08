package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/types"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	. "github.com/dave/jennifer/jen"
	"github.com/gagliardetto/codebox/gogentools"
	"github.com/gagliardetto/codebox/scanner"
	"github.com/gagliardetto/feparser"
	. "github.com/gagliardetto/utilz"
	"github.com/gin-gonic/gin"
)

type CacheType map[string]*feparser.CodeQlFinalVals

var (
	mu = &sync.RWMutex{}
)

var (
	IncludeCommentsInGeneratedGo bool
	InlineGeneratedGo            bool
)

func main() {
	var pkg string
	var runServer bool

	var cacheDir string
	var generatedDir string

	var toStdout bool
	var includeBoilerplace bool
	var compressCodeQl bool

	flag.StringVar(&pkg, "pkg", "", "Package you want to scan (can be either in example.com/hello/world format, or example.com/hello/world@v1.0.1 format)")
	flag.StringVar(&cacheDir, "cache-dir", "./cache", "Folder that contains cache of taint-tracking pointers")
	flag.StringVar(&generatedDir, "out-dir", "./generated", "Folder that contains the generated assets (each run has its own timestamped folder)")
	flag.BoolVar(&runServer, "http", false, "Run http server")
	flag.BoolVar(&toStdout, "stdout", false, "Print generated to stdout")
	flag.BoolVar(&includeBoilerplace, "stub", true, "Include utility functions (main, sink, link, etc.) in the go test files")
	flag.BoolVar(&compressCodeQl, "compress", true, "Compress codeql classes")
	flag.BoolVar(&IncludeCommentsInGeneratedGo, "comments", false, "Include comments inside go test code")
	flag.BoolVar(&InlineGeneratedGo, "inline", false, "Inline tests in generated go code")
	flag.Parse()

	// Initialize module scanner:
	sc, err := scanner.New(pkg)
	if err != nil {
		panic(err)
	}

	pks, err := sc.Scan()
	if err != nil {
		panic(err)
	}
	pk := pks[0]
	// compose the fePackage:
	Infof("Composing fePackage %q", pk.Path)
	fePackage, err := feparser.Load(pk)
	if err != nil {
		panic(err)
	}

	{ // Create folders:
		// folder for all cache:
		MustCreateFolderIfNotExists(cacheDir, 0750)
		// folder for all folders for assets:
		MustCreateFolderIfNotExists(generatedDir, 0750)
	}

	cacheFilepath := path.Join(cacheDir, feparser.FormatCodeQlName(scanner.RemoveGoSrcClonePath(pk.Path))+".v2.json")
	cacheExists := MustFileExists(cacheFilepath)
	{ // Load pointer blocks from cache:
		// try to use DEPRECATED cache:
		deprecatedCacheFilepath := path.Join(cacheDir, feparser.FormatCodeQlName(scanner.RemoveGoSrcClonePath(pk.Path))+".json")
		deprecatedCacheExists := MustFileExists(deprecatedCacheFilepath)

		canLoadFromDeprecatedCache := !cacheExists && deprecatedCacheExists
		if canLoadFromDeprecatedCache {
			tempDeprecatedFeModule := &feparser.DEPRECATEDFEModule{}
			// Load cache:
			Infof("Loading cached fePackage from %q", deprecatedCacheFilepath)
			err := LoadJSON(tempDeprecatedFeModule, deprecatedCacheFilepath)
			if err != nil {
				panic(err)
			}

			findLatestFunc := func(signature string) *feparser.FEFunc {
				for _, latest := range fePackage.Funcs {
					if latest.Signature == signature {
						return latest
					}
				}
				return nil
			}
			findLatestTypeMethod := func(signature string) *feparser.FETypeMethod {
				for _, latest := range fePackage.TypeMethods {
					if latest.Func.Signature == signature {
						return latest
					}
				}
				return nil
			}
			findLatestInterfaceMethod := func(signature string) *feparser.FEInterfaceMethod {
				for _, latest := range fePackage.InterfaceMethods {
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
							latest.CodeQL.Blocks = make([]*feparser.FlowBlock, 0)
							latest.CodeQL.Blocks = append(
								latest.CodeQL.Blocks,
								&feparser.FlowBlock{
									Inp:  make([]bool, width),
									Outp: make([]bool, width),
								},
							)

							// Copy legacy pointers into first block:
							{
								inp := cached.CodeQL.Pointers.Inp
								switch inp.Element {
								case feparser.ElementParameter:
									latest.CodeQL.Blocks[0].Inp[inp.Index] = true
								case feparser.ElementResult:
									latest.CodeQL.Blocks[0].Inp[inp.Index+len(latest.Parameters)] = true
								}
							}
							{
								outp := cached.CodeQL.Pointers.Outp
								switch outp.Element {
								case feparser.ElementParameter:
									latest.CodeQL.Blocks[0].Outp[outp.Index] = true
								case feparser.ElementResult:
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
							latest.CodeQL.Blocks = make([]*feparser.FlowBlock, 0)
							latest.CodeQL.Blocks = append(
								latest.CodeQL.Blocks,
								&feparser.FlowBlock{
									Inp:  make([]bool, width),
									Outp: make([]bool, width),
								},
							)

							// Copy legacy pointers into first block:
							{
								inp := cached.CodeQL.Pointers.Inp
								switch inp.Element {
								case feparser.ElementReceiver:
									latest.CodeQL.Blocks[0].Inp[0] = true
								case feparser.ElementParameter:
									latest.CodeQL.Blocks[0].Inp[inp.Index+1] = true
								case feparser.ElementResult:
									latest.CodeQL.Blocks[0].Inp[inp.Index+len(latest.Func.Parameters)+1] = true
								}
							}
							{
								outp := cached.CodeQL.Pointers.Outp
								switch outp.Element {
								case feparser.ElementReceiver:
									latest.CodeQL.Blocks[0].Outp[0] = true
								case feparser.ElementParameter:
									latest.CodeQL.Blocks[0].Outp[outp.Index+1] = true
								case feparser.ElementResult:
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
							latest.CodeQL.Blocks = make([]*feparser.FlowBlock, 0)
							latest.CodeQL.Blocks = append(
								latest.CodeQL.Blocks,
								&feparser.FlowBlock{
									Inp:  make([]bool, width),
									Outp: make([]bool, width),
								},
							)

							// Copy legacy pointers into first block:
							{
								inp := cached.CodeQL.Pointers.Inp
								switch inp.Element {
								case feparser.ElementReceiver:
									latest.CodeQL.Blocks[0].Inp[0] = true
								case feparser.ElementParameter:
									latest.CodeQL.Blocks[0].Inp[inp.Index+1] = true
								case feparser.ElementResult:
									latest.CodeQL.Blocks[0].Inp[inp.Index+len(latest.Func.Parameters)+1] = true
								}
							}
							{
								outp := cached.CodeQL.Pointers.Outp
								switch outp.Element {
								case feparser.ElementReceiver:
									latest.CodeQL.Blocks[0].Outp[0] = true
								case feparser.ElementParameter:
									latest.CodeQL.Blocks[0].Outp[outp.Index+1] = true
								case feparser.ElementResult:
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
			Infof("Loading cached fePackage from %q", cacheFilepath)
			err := LoadJSON(&cachedMap, cacheFilepath)
			if err != nil {
				panic(err)
			}

			findCached := func(signature string) *feparser.CodeQlFinalVals {
				for cacheSignature, cached := range cachedMap {
					if cacheSignature == signature {
						return cached
					}
				}
				return nil
			}
			// Load from cache:
			for _, latest := range fePackage.Funcs {
				cached := findCached(latest.Signature)
				if cached == nil {
					Warnf("cached not found for signature %q", latest.Signature)
				} else {
					// Copy CodeQL object:
					latest.CodeQL = cached
				}
			}
			for _, latest := range fePackage.TypeMethods {
				cached := findCached(latest.Func.Signature)
				if cached == nil {
					Warnf("cached not found for signature %q", latest.Func.Signature)
				} else {
					// Copy CodeQL object:
					latest.CodeQL = cached
				}
			}
			for _, latest := range fePackage.InterfaceMethods {
				cached := findCached(latest.Func.Signature)
				if cached == nil {
					Warnf("cached not found for signature %q", latest.Func.Signature)
				} else {
					// Copy CodeQL object:
					latest.CodeQL = cached
				}
			}
		}
	}

	lenFuncs := len(fePackage.Funcs)
	lenTypeMethods := len(fePackage.TypeMethods)
	lenInterfaceMethods := len(fePackage.InterfaceMethods)
	lenTotal := lenFuncs + lenTypeMethods + lenInterfaceMethods
	Sfln(
		IndigoBG("Package %q has %v funcs, %v methods on types, and %v methods on interfaces (total=%v)"),
		pk.Name,
		lenFuncs,
		lenTypeMethods,
		lenInterfaceMethods,
		lenTotal,
	)

	// Create index, and load values to it:
	index := NewIndex()
	{
		for _, v := range fePackage.Funcs {
			index.MustSetUnique(v.Signature, v)
		}
		for _, v := range fePackage.TypeMethods {
			index.MustSetUnique(v.Func.Signature, v)
		}
		for _, v := range fePackage.InterfaceMethods {
			index.MustSetUnique(v.Func.Signature, v)
		}
	}

	// Callback executed when this program is closed:
	onExitCallback := func() {
		mu.Lock()
		defer mu.Unlock()

		PopulateGeneratedClassCodeQL(fePackage)

		{
			// Save cache:
			cacheFilepath := path.Join(cacheDir, feparser.FormatCodeQlName(fePackage.PkgPath)+".v2.json")
			cacheMap := make(CacheType)
			{
				for _, v := range fePackage.Funcs {
					cacheMap[v.Signature] = v.CodeQL
				}
				for _, v := range fePackage.TypeMethods {
					cacheMap[v.Func.Signature] = v.CodeQL
				}
				for _, v := range fePackage.InterfaceMethods {
					cacheMap[v.Func.Signature] = v.CodeQL
				}

				// Remove generated stuff:
				for _, v := range cacheMap {
					v.GeneratedClass = ""
					v.GeneratedConditions = ""
				}
			}
			Infof("Saving cache to %q", MustAbs(cacheFilepath))
			err := SaveAsIndentedJSON(cacheMap, cacheFilepath)
			if err != nil {
				panic(err)
			}
		}

		// Generate golang tests code:
		goTestFile := NewTestFile(includeBoilerplace)
		testFuncNames := make([]string, 0)
		{
			for _, fe := range fePackage.Funcs {
				if !fe.CodeQL.IsEnabled {
					continue
				}
				if err := fe.CodeQL.Validate(); err != nil {
					Errorf("invalid pointers for %q: %s", fe.Signature, err)
					continue
				}
				allCode := generateGoTestBlock_Func(
					goTestFile,
					fe,
				)
				for _, codeEnvelope := range allCode {
					if codeEnvelope.Statement != nil {
						goTestFile.Add(codeEnvelope.Statement.Line())
						testFuncNames = append(testFuncNames, codeEnvelope.TestFuncName)
					} else {
						Warnf("NOTHING GENERATED")
					}
				}
			}
		}
		{
			for _, fe := range fePackage.TypeMethods {
				if !fe.CodeQL.IsEnabled {
					continue
				}
				if err := fe.CodeQL.Validate(); err != nil {
					Errorf("invalid pointers for %q: %s", fe.Func.Signature, err)
					continue
				}
				allCode := generateGoTestBlock_Method(
					goTestFile,
					fe,
				)
				for _, codeEnvelope := range allCode {
					if codeEnvelope.Statement != nil {
						goTestFile.Add(codeEnvelope.Statement.Line())
						testFuncNames = append(testFuncNames, codeEnvelope.TestFuncName)
					} else {
						Warnf("NOTHING GENERATED")
					}
				}
			}
		}
		{
			for _, fe := range fePackage.InterfaceMethods {
				if !fe.CodeQL.IsEnabled {
					continue
				}
				if err := fe.CodeQL.Validate(); err != nil {
					Errorf("invalid pointers for %q: %s", fe.Func.Signature, err)
					continue
				}
				converted := feparser.FEIToFET(fe)
				allCode := generateGoTestBlock_Method(
					goTestFile,
					converted,
				)
				for _, codeEnvelope := range allCode {
					if codeEnvelope.Statement != nil {
						goTestFile.Add(codeEnvelope.Statement.Line())
						testFuncNames = append(testFuncNames, codeEnvelope.TestFuncName)
					} else {
						Warnf("NOTHING GENERATED")
					}
				}
			}
		}
		{

			code := Func().
				Id("RunAllTaints_" + feparser.FormatCodeQlName(fePackage.PkgPath)).
				Params().
				BlockFunc(func(group *Group) {
					for testID, testFuncName := range testFuncNames {
						group.BlockFunc(func(testBlock *Group) {
							Comments(testBlock, "Create a new source:")
							testBlock.Id("source").Op(":=").Id("newSource").Call(Lit(testID))

							Comments(testBlock, "Run the taint scenario:")
							testBlock.Id("out").Op(":=").Id(testFuncName).Call(Id("source"))

							Comments(testBlock, "If the taint step(s) succeeded, then `out` is tainted and will be sink-able here:")
							testBlock.Id("sink").Call(Lit(testID), Id("out"))
						})
					}
				})
			goTestFile.Add(code.Line())
		}
		if toStdout {
			fmt.Printf("%#v", goTestFile)
		}

		ts := time.Now()
		// Create subfolder for package for generated assets:
		packageAssetFolderName := feparser.FormatCodeQlName(fePackage.PkgPath)
		packageAssetFolderPath := path.Join(generatedDir, packageAssetFolderName)
		MustCreateFolderIfNotExists(packageAssetFolderPath, 0750)
		// Create folder for assets generated during this run:
		thisRunAssetFolderName := feparser.FormatCodeQlName(fePackage.PkgPath) + "_" + ts.Format(FilenameTimeFormat)
		thisRunAssetFolderPath := path.Join(packageAssetFolderPath, thisRunAssetFolderName)
		// Create a new assets folder inside the main assets folder:
		MustCreateFolderIfNotExists(thisRunAssetFolderPath, 0750)

		{
			// Save golang assets:
			assetFileName := feparser.FormatCodeQlName(fePackage.PkgPath) + ".go"
			assetFilepath := path.Join(thisRunAssetFolderPath, assetFileName)

			// Create file go test file:
			goFile, err := os.Create(assetFilepath)
			if err != nil {
				panic(err)
			}
			defer goFile.Close()

			// write generated Golang code to file:
			Infof("Saving golang assets to %q", MustAbs(assetFilepath))
			err = goTestFile.Render(goFile)
			if err != nil {
				panic(err)
			}
		}
		{
			// Save the go.mod file that was used to fetch the desired version of the package:
			if srcGoModFilepath := scanner.GetTempGoModFilepath(pkg); srcGoModFilepath != "" {
				dstGoModFilepath := path.Join(thisRunAssetFolderPath, "go.mod")
				Infof("Saving saving go.mod to %q", MustAbs(dstGoModFilepath))
				MustCopyFile(srcGoModFilepath, dstGoModFilepath)
			}
		}

		{
			// Generate codeQL tain-tracking classes and qll file:
			var buf bytes.Buffer

			fileHeader := `/**
 * Provides classes modeling security-relevant aspects of the ` + "`" + fePackage.PkgPath + "`" + ` package.
 */

import go` + "\n\n"

			moduleHeader := Sf(
				"/** Provides models of commonly used functions in the `%s` package. */\nmodule %s {",
				fePackage.PkgPath,
				feparser.FormatCodeQlName(fePackage.PkgPath),
			)
			buf.WriteString(fileHeader + moduleHeader)
			if compressCodeQl {
				err := CompressedGenerateCodeQLTT_All(&buf, fePackage)
				if err != nil {
					panic(err)
				}
			} else {
				err := GenerateCodeQLTT_Functions(&buf, fePackage.Funcs)
				if err != nil {
					panic(err)
				}
				err = GenerateCodeQLTT_TypeMethods(&buf, fePackage.TypeMethods)
				if err != nil {
					panic(err)
				}
				err = GenerateCodeQLTT_InterfaceMethods(&buf, fePackage.InterfaceMethods)
				if err != nil {
					panic(err)
				}
			}

			buf.WriteString("\n}")

			if toStdout {
				fmt.Println(buf.String())
			}

			// Save codeql assets:
			assetFileName := feparser.FormatCodeQlName(fePackage.PkgPath) + ".qll"
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
	}

	var once sync.Once
	go Notify(
		func(os.Signal) bool {
			once.Do(onExitCallback)
			return false
		},
		os.Kill,
		os.Interrupt,
	)
	defer once.Do(onExitCallback)

	if runServer {
		r := gin.Default()
		r.StaticFile("", "./index.html")
		r.Static("/static", "./static")

		r.GET("/api/source", func(c *gin.Context) {
			mu.Lock()
			defer mu.Unlock()

			PopulateGeneratedClassCodeQL(fePackage)

			c.IndentedJSON(200, fePackage)
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

			switch stored.GetOriginal().(type) {
			case *feparser.FEFunc:
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
			case *feparser.FETypeMethod, *feparser.FEInterfaceMethod:
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

			switch stored.GetOriginal().(type) {
			case *feparser.FEFunc:
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
						err := GenerateCodeQLTT_Functions(generatedCodeql, []*feparser.FEFunc{fe})
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
			case *feparser.FETypeMethod, *feparser.FEInterfaceMethod:
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
							err := GenerateCodeQLTT_TypeMethods(generatedCodeql, []*feparser.FETypeMethod{st})
							if err != nil {
								Errorf("error generating codeql: %s", err)
								c.Status(400)
								return
							}
						} else {
							st := stored.GetFEInterfaceMethod()
							err := GenerateCodeQLTT_InterfaceMethods(generatedCodeql, []*feparser.FEInterfaceMethod{st})
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

type IndexItem struct {
	original interface{}
}

func (item *IndexItem) GetOriginal() interface{} {
	return item.original
}

//
func NewIndexItem(v interface{}) *IndexItem {
	item := &IndexItem{}
	item.SetOriginal(v)
	return item
}

//
func (item *IndexItem) SetOriginal(v interface{}) {
	item.original = v
}

//
func (item *IndexItem) IsNil() bool {
	return item.original == nil
}

//
func (item *IndexItem) GetFEFunc() *feparser.FEFunc {
	fe, ok := item.GetOriginal().(*feparser.FEFunc)
	if !ok {
		return nil
	}
	return fe
}

//
func (item *IndexItem) GetFETypeMethod() *feparser.FETypeMethod {
	fe, ok := item.GetOriginal().(*feparser.FETypeMethod)
	if !ok {
		return nil
	}
	return fe
}

func (item *IndexItem) GetFETypeMethodOrInterfaceMethod() *feparser.FETypeMethod {
	feTyp, ok := item.GetOriginal().(*feparser.FETypeMethod)
	if !ok {
		feIt, ok := item.GetOriginal().(*feparser.FEInterfaceMethod)
		if !ok {
			return nil
		}
		return feparser.FEIToFET(feIt)
	}
	return feTyp
}

//
func (item *IndexItem) GetFEInterfaceMethod() *feparser.FEInterfaceMethod {
	fe, ok := item.GetOriginal().(*feparser.FEInterfaceMethod)
	if !ok {
		return nil
	}
	return fe
}

type Storage struct {
	mu     *sync.RWMutex
	values map[string]*IndexItem
}

func NewIndex() *Storage {
	return &Storage{
		mu:     &sync.RWMutex{},
		values: make(map[string]*IndexItem),
	}
}
func (index *Storage) GetBySignature(signature string) *IndexItem {
	index.mu.RLock()
	defer index.mu.RUnlock()

	val, ok := index.values[signature]
	if !ok {
		return nil
	}
	return val
}

func (index *Storage) Set(signature string, v interface{}) {
	index.mu.Lock()
	defer index.mu.Unlock()

	index.values[signature] = NewIndexItem(v)
}
func (index *Storage) MustSetUnique(signature string, v interface{}) {

	existing := index.GetBySignature(signature)
	if existing != nil {
		Errorf(Sf("%q already in the index", signature))
	} else {
		index.Set(signature, v)
	}
}

type GeneratedClassResponse struct {
	GeneratedClass string
}

func PopulateGeneratedClassCodeQL(fePackage *feparser.FEPackage) error {
	for i := range fePackage.Funcs {
		fe := fePackage.Funcs[i]
		if err := fe.CodeQL.Validate(); err == nil {
			generatedCodeqlClass := new(bytes.Buffer)
			err := GenerateCodeQLTT_Functions(generatedCodeqlClass, []*feparser.FEFunc{fe})
			if err != nil {
				return fmt.Errorf("error generating codeql conditions for %q: %s", fe.Signature, err)
			}
			fe.CodeQL.GeneratedClass = generatedCodeqlClass.String()
		}
	}
	for i := range fePackage.TypeMethods {
		fe := fePackage.TypeMethods[i]
		if err := fe.CodeQL.Validate(); err == nil {
			generatedCodeqlClass := new(bytes.Buffer)
			err := GenerateCodeQLTT_TypeMethods(generatedCodeqlClass, []*feparser.FETypeMethod{fe})
			if err != nil {
				return fmt.Errorf("error generating codeql conditions for %q: %s", fe.Func.Signature, err)
			}
			fe.CodeQL.GeneratedClass = generatedCodeqlClass.String()
		}
	}
	for i := range fePackage.InterfaceMethods {
		fe := fePackage.InterfaceMethods[i]
		if err := fe.CodeQL.Validate(); err == nil {
			generatedCodeqlClass := new(bytes.Buffer)
			err := GenerateCodeQLTT_InterfaceMethods(generatedCodeqlClass, []*feparser.FEInterfaceMethod{fe})
			if err != nil {
				return fmt.Errorf("error generating codeql conditions for %q: %s", fe.Func.Signature, err)
			}
			fe.CodeQL.GeneratedClass = generatedCodeqlClass.String()
		}
	}

	return nil
}

func GenerateCodeQLTT_Functions(buf *bytes.Buffer, fes []*feparser.FEFunc) error {
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
func GenerateCodeQLTT_TypeMethods(buf *bytes.Buffer, fes []*feparser.FETypeMethod) error {
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
func GenerateCodeQLTT_InterfaceMethods(buf *bytes.Buffer, fes []*feparser.FEInterfaceMethod) error {
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

		generatedConditions, err := generateCodeQLFlowConditions_FEMethod(feparser.FEIToFET(fe), fe.CodeQL.Blocks)
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
	paddingSize := 6
	var res string
	scanner := bufio.NewScanner(strings.NewReader(s))
	tot := strings.Count(s, "\n")
	for i := 0; scanner.Scan(); i++ {
		var padding = ""
		if i > 0 {
			padding = RepeatString(paddingSize, " ")
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
	// Add comment to file:
	file.HeaderComment("Code generated by https://github.com/gagliardetto/codebox. DO NOT EDIT.")

	if includeBoilerplace {
		{
			// main function:
			file.Func().Id("main").Params().Block()
		}
		{
			// sink function:
			code := Func().
				Id("sink").
				Params(Id("id").Int(), Id("v").Interface()).
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
				Params(Id("id").Int()).
				Interface().
				Block(Return(Nil()))
			file.Add(code.Line())
		}
	}
	return file
}

func generateGoChildBlock_Func(file *File, fe *feparser.FEFunc, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	Parameter := feparser.ElementParameter
	Result := feparser.ElementResult

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

func generateChildBlock_Method(file *File, fe *feparser.FETypeMethod, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	Receiver := feparser.ElementReceiver
	Parameter := feparser.ElementParameter
	Result := feparser.ElementResult

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

func getPlaceholder(element feparser.Element, index int, fe *feparser.FEFunc) string {
	switch element {
	case feparser.ElementParameter:
		return fe.Parameters[index].Identity.Placeholder
	case feparser.ElementResult:
		return fe.Results[index].Identity.Placeholder
	default:
		panic(Sf("not valid pointers.Inp.Element: %s", element))
	}
}

func getPlaceholderFromFunc(fe *feparser.FEFunc, ident *feparser.CodeQlIdentity) string {
	element := ident.Element
	index := ident.Index
	return getPlaceholder(element, index, fe)
}

func getPlaceholderFromMethod(fe *feparser.FETypeMethod, ident *feparser.CodeQlIdentity) string {
	element := ident.Element
	index := ident.Index
	switch element {
	case feparser.ElementReceiver:
		return fe.Receiver.Identity.Placeholder
	case feparser.ElementParameter, feparser.ElementResult:
		return getPlaceholder(element, index, fe.Func)
	default:
		panic(Sf("not valid pointers.Inp.Element: %s", element))
	}
}

// Comments adds comments to a Group (if enabled), and returns the group.
func Comments(group *Group, comments ...string) *Group {
	if IncludeCommentsInGeneratedGo {
		for _, comment := range comments {
			group.Line().Comment(comment)
		}
	}
	return group
}
func generate_ReceMethPara(file *File, fe *feparser.FETypeMethod, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	// from: receiver
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: param

	indexIn := identityInp.Index
	indexOut := identityOutp.Index
	_ = indexIn

	in := fe.Receiver
	out := fe.Func.Parameters[indexOut]

	in.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("from", in.TypeName))
	out.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			Comments(groupCase, Sf("The flow is from `%s` into `%s`.", inVarName, outVarName))

			Comments(groupCase, Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			gogentools.ComposeTypeAssertion(file, groupCase, in.VarName, in.GetOriginal(), in.Is.Variadic)

			Comments(groupCase, Sf("Declare `%s` variable:", outVarName))
			gogentools.ComposeVarDeclaration(file, groupCase, out.VarName, out.GetOriginal().GetType(), out.GetOriginal().IsVariadic())

			Comments(groupCase,
				"Call the method that transfers the taint",
				Sf("from the receiver `%s` to the argument `%s`", in.VarName, out.VarName),
				Sf("(`%s` is now tainted).", out.VarName),
			)

			gogentools.ImportPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

			groupCase.Id(in.VarName).Dot(fe.Func.Name).CallFunc(
				func(call *Group) {

					tpFun := fe.Func.GetOriginal().GetType().(*types.Signature)

					zeroVals := gogentools.ScanTupleOfZeroValues(file, tpFun.Params(), fe.Func.GetOriginal().IsVariadic())

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

			Comments(groupCase, Sf("Return the tainted `%s`:", outVarName))
			groupCase.Return(Id(out.VarName))
		})
	return code.Line()
}
func generate_ReceMethResu(file *File, fe *feparser.FETypeMethod, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	// from: receiver
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: result

	indexIn := identityInp.Index
	indexOut := identityOutp.Index
	_ = indexIn

	in := fe.Receiver
	out := fe.Func.Results[indexOut]

	in.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("from", in.TypeName))
	out.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			Comments(groupCase, Sf("The flow is from `%s` into `%s`.", inVarName, outVarName))

			Comments(groupCase, Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			gogentools.ComposeTypeAssertion(file, groupCase, in.VarName, in.GetOriginal(), in.Is.Variadic)

			Comments(groupCase,
				"Call the method that transfers the taint",
				Sf("from the receiver `%s` to the result `%s`", in.VarName, out.VarName),
				Sf("(`%s` is now tainted).", out.VarName),
			)

			gogentools.ImportPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

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

					tpFun := fe.Func.GetOriginal().GetType().(*types.Signature)

					zeroVals := gogentools.ScanTupleOfZeroValues(file, tpFun.Params(), fe.Func.GetOriginal().IsVariadic())

					for _, zero := range zeroVals {
						call.Add(zero)
					}

				},
			)

			Comments(groupCase, Sf("Return the tainted `%s`:", outVarName))
			groupCase.Return(Id(out.VarName))
		})
	return code.Line()
}
func generate_ParaMethRece(file *File, fe *feparser.FETypeMethod, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	// from: param
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: receiver

	indexIn := identityInp.Index
	indexOut := identityOutp.Index
	_ = indexOut

	in := fe.Func.Parameters[indexIn]
	out := fe.Receiver

	in.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("from", in.TypeName))
	out.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			Comments(groupCase, Sf("The flow is from `%s` into `%s`.", inVarName, outVarName))

			Comments(groupCase, Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			gogentools.ComposeTypeAssertion(file, groupCase, in.VarName, in.GetOriginal().GetType(), in.GetOriginal().IsVariadic())

			Comments(groupCase, Sf("Declare `%s` variable:", outVarName))
			gogentools.ComposeVarDeclaration(file, groupCase, out.VarName, out.GetOriginal(), out.Is.Variadic)

			Comments(groupCase,
				"Call the method that transfers the taint",
				Sf("from the parameter `%s` to the receiver `%s`", in.VarName, out.VarName),
				Sf("(`%s` is now tainted).", out.VarName),
			)

			gogentools.ImportPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

			groupCase.Id(out.VarName).Dot(fe.Func.Name).CallFunc(
				func(call *Group) {

					tpFun := fe.Func.GetOriginal().GetType().(*types.Signature)

					zeroVals := gogentools.ScanTupleOfZeroValues(file, tpFun.Params(), fe.Func.GetOriginal().IsVariadic())

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

			Comments(groupCase, Sf("Return the tainted `%s`:", outVarName))
			groupCase.Return(Id(out.VarName))
		})
	return code.Line()
}
func generate_ParaMethPara(file *File, fe *feparser.FETypeMethod, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	// from: param
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: param

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Func.Parameters[indexIn]
	out := fe.Func.Parameters[indexOut]

	in.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("from", in.TypeName))
	out.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			Comments(groupCase, Sf("The flow is from `%s` into `%s`.", inVarName, outVarName))

			Comments(groupCase, Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			gogentools.ComposeTypeAssertion(file, groupCase, in.VarName, in.GetOriginal().GetType(), in.GetOriginal().IsVariadic())

			Comments(groupCase, Sf("Declare `%s` variable:", outVarName))
			gogentools.ComposeVarDeclaration(file, groupCase, out.VarName, out.GetOriginal().GetType(), out.GetOriginal().IsVariadic())

			Comments(groupCase, "Declare medium object/interface:")
			groupCase.Var().Id("mediumObjCQL").Qual(fe.Receiver.PkgPath, fe.Receiver.TypeName)

			Comments(groupCase,
				"Call the method that transfers the taint",
				Sf("from the parameter `%s` to the parameter `%s`", in.VarName, out.VarName),
				Sf("(`%s` is now tainted).", out.VarName),
			)

			gogentools.ImportPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

			groupCase.Id("mediumObjCQL").Dot(fe.Func.Name).CallFunc(
				func(call *Group) {

					tpFun := fe.Func.GetOriginal().GetType().(*types.Signature)

					zeroVals := gogentools.ScanTupleOfZeroValues(file, tpFun.Params(), fe.Func.GetOriginal().IsVariadic())

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

			Comments(groupCase, Sf("Return the tainted `%s`:", outVarName))
			groupCase.Return(Id(out.VarName))
		})
	return code.Line()
}
func generate_ParaMethResu(file *File, fe *feparser.FETypeMethod, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	// from: param
	// medium: method (when there is a receiver, then it must be a method medium)
	// into: result

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Func.Parameters[indexIn]
	out := fe.Func.Results[indexOut]

	in.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("from", in.TypeName))
	out.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			Comments(groupCase, Sf("The flow is from `%s` into `%s`.", inVarName, outVarName))

			Comments(groupCase, Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			gogentools.ComposeTypeAssertion(file, groupCase, in.VarName, in.GetOriginal().GetType(), in.GetOriginal().IsVariadic())

			Comments(groupCase, "Declare medium object/interface:")
			groupCase.Var().Id("mediumObjCQL").Qual(fe.Receiver.PkgPath, fe.Receiver.TypeName)

			Comments(groupCase,
				"Call the method that transfers the taint",
				Sf("from the parameter `%s` to the result `%s`", in.VarName, out.VarName),
				Sf("(`%s` is now tainted).", out.VarName),
			)

			gogentools.ImportPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

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

					tpFun := fe.Func.GetOriginal().GetType().(*types.Signature)

					zeroVals := gogentools.ScanTupleOfZeroValues(file, tpFun.Params(), fe.Func.GetOriginal().IsVariadic())

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

			Comments(groupCase, Sf("Return the tainted `%s`:", outVarName))
			groupCase.Return(Id(out.VarName))
		})
	return code.Line()
}
func generate_ResuMethRece(file *File, fe *feparser.FETypeMethod, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	// from: result
	// medium: method
	// into: receiver

	indexIn := identityInp.Index
	indexOut := identityOutp.Index
	_ = indexOut

	in := fe.Func.Results[indexIn]
	out := fe.Receiver

	in.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("from", in.TypeName))
	out.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			Comments(groupCase, Sf("The flow is from `%s` into `%s`.", inVarName, outVarName))

			Comments(groupCase, Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			gogentools.ComposeTypeAssertion(file, groupCase, in.VarName, in.GetOriginal().GetType(), in.GetOriginal().IsVariadic())

			Comments(groupCase, Sf("Declare `%s` variable:", outVarName))
			gogentools.ComposeVarDeclaration(file, groupCase, out.VarName, out.GetOriginal(), out.Is.Variadic)

			Comments(groupCase,
				"Call the method that will transfer the taint",
				Sf("from the result `intermediateCQL` to receiver `%s`:", outVarName),
			)

			groupCase.ListFunc(func(resGroup *Group) {
				for i := range fe.Func.Results {
					if i == indexIn {
						resGroup.Id("intermediateCQL")
					} else {
						resGroup.Id("_")
					}
				}
			}).Op(":=").Id(out.VarName).Dot(fe.Func.Name).CallFunc(
				func(call *Group) {

					tpFun := fe.Func.GetOriginal().GetType().(*types.Signature)

					zeroVals := gogentools.ScanTupleOfZeroValues(file, tpFun.Params(), fe.Func.GetOriginal().IsVariadic())

					for _, zero := range zeroVals {
						call.Add(zero)
					}

				},
			)

			Comments(groupCase,
				Sf(
					"Extra step (`%s` taints `intermediateCQL`, which taints `%s`:",
					in.VarName,
					out.VarName,
				),
			)
			groupCase.Id("link").Call(Id(in.VarName), Id("intermediateCQL"))

			Comments(groupCase, Sf("Return the tainted `%s`:", out.VarName))
			groupCase.Return(Id(out.VarName))
		})
	return code.Line()
}
func generate_ResuMethPara(file *File, fe *feparser.FETypeMethod, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	// from: result
	// medium: method
	// into: parameter

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Func.Results[indexIn]
	out := fe.Func.Parameters[indexOut]

	in.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("from", in.TypeName))
	out.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			Comments(groupCase, Sf("The flow is from `%s` into `%s`.", inVarName, outVarName))

			Comments(groupCase, Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			gogentools.ComposeTypeAssertion(file, groupCase, in.VarName, in.GetOriginal().GetType(), in.GetOriginal().IsVariadic())

			Comments(groupCase, Sf("Declare `%s` variable:", outVarName))
			gogentools.ComposeVarDeclaration(file, groupCase, out.VarName, out.GetOriginal().GetType(), out.GetOriginal().IsVariadic())

			Comments(groupCase, "Declare medium object/interface:")
			groupCase.Var().Id("mediumObjCQL").Qual(fe.Receiver.PkgPath, fe.Receiver.TypeName)

			Comments(groupCase,
				"Call the method that transfers the taint",
				Sf("from the result `%s` to the parameter `%s`", in.VarName, out.VarName),
				Sf("(`%s` is now tainted).", out.VarName),
			)

			gogentools.ImportPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

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

					tpFun := fe.Func.GetOriginal().GetType().(*types.Signature)

					zeroVals := gogentools.ScanTupleOfZeroValues(file, tpFun.Params(), fe.Func.GetOriginal().IsVariadic())

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

			Comments(groupCase,
				Sf(
					"Extra step (`%s` taints `intermediateCQL`, which taints `%s`:",
					in.VarName,
					out.VarName,
				),
			)
			groupCase.Id("link").Call(Id(in.VarName), Id("intermediateCQL"))

			Comments(groupCase, Sf("Return the tainted `%s`:", out.VarName))
			groupCase.Return(Id(out.VarName))
		})
	return code.Line()
}

func generate_ResuMethResu(file *File, fe *feparser.FETypeMethod, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	// from: result
	// medium: method
	// into: result

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Func.Results[indexIn]
	out := fe.Func.Results[indexOut]

	in.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("from", in.TypeName))
	out.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			Comments(groupCase, Sf("The flow is from `%s` into `%s`.", inVarName, outVarName))

			Comments(groupCase, Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			gogentools.ComposeTypeAssertion(file, groupCase, in.VarName, in.GetOriginal().GetType(), in.GetOriginal().IsVariadic())

			Comments(groupCase, "Declare medium object/interface:")
			groupCase.Var().Id("mediumObjCQL").Qual(fe.Receiver.PkgPath, fe.Receiver.TypeName)

			Comments(groupCase,
				"Call the method that transfers the taint",
				Sf("from the result `%s` to the result `%s`", in.VarName, out.VarName),
				Sf("(`%s` is now tainted).", out.VarName),
			)

			gogentools.ImportPackage(file, fe.Func.PkgPath, fe.Func.PkgName)

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

					tpFun := fe.Func.GetOriginal().GetType().(*types.Signature)

					zeroVals := gogentools.ScanTupleOfZeroValues(file, tpFun.Params(), fe.Func.GetOriginal().IsVariadic())

					for _, zero := range zeroVals {
						call.Add(zero)
					}

				},
			)
			Comments(groupCase,
				Sf(
					"Extra step (`%s` taints `intermediateCQL`, which taints `%s`:",
					in.VarName,
					out.VarName,
				))
			groupCase.Id("link").Call(Id(in.VarName), Id("intermediateCQL"))

			Comments(groupCase, Sf("Return the tainted `%s`:", out.VarName))
			groupCase.Return(Id(out.VarName))
		})
	return code.Line()
}

func generate_ParaFuncPara(file *File, fe *feparser.FEFunc, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	// from: param
	// medium: func
	// into: param

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Parameters[indexIn]
	out := fe.Parameters[indexOut]

	in.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("from", in.TypeName))
	out.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			Comments(groupCase, Sf("The flow is from `%s` into `%s`.", inVarName, outVarName))

			Comments(groupCase, Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			gogentools.ComposeTypeAssertion(file, groupCase, in.VarName, in.GetOriginal().GetType(), in.GetOriginal().IsVariadic())

			Comments(groupCase, Sf("Declare `%s` variable:", outVarName))
			gogentools.ComposeVarDeclaration(file, groupCase, out.VarName, out.GetOriginal().GetType(), out.GetOriginal().IsVariadic())

			Comments(groupCase,
				"Call the function that transfers the taint",
				Sf("from the parameter `%s` to parameter `%s`;", inVarName, outVarName),
				Sf("`%s` is now tainted.", outVarName),
			)

			gogentools.ImportPackage(file, fe.PkgPath, fe.PkgName)

			groupCase.Qual(fe.PkgPath, fe.Name).CallFunc(
				func(call *Group) {

					tpFun := fe.GetOriginal().GetType().(*types.Signature)

					zeroVals := gogentools.ScanTupleOfZeroValues(file, tpFun.Params(), fe.GetOriginal().IsVariadic())

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

			Comments(groupCase, Sf("Return the tainted `%s`:", outVarName))
			groupCase.Return(Id(out.VarName))
		})

	return code.Line()
}

func generate_ParaFuncResu(file *File, fe *feparser.FEFunc, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	// from: param
	// medium: func
	// into: result

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Parameters[indexIn]
	out := fe.Results[indexOut]

	in.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("from", in.TypeName))
	out.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			Comments(groupCase, Sf("The flow is from `%s` into `%s`.", inVarName, outVarName))

			Comments(groupCase, Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			gogentools.ComposeTypeAssertion(file, groupCase, in.VarName, in.GetOriginal().GetType(), in.GetOriginal().IsVariadic())

			Comments(groupCase,
				"Call the function that transfers the taint",
				Sf("from the parameter `%s` to result `%s`", inVarName, outVarName),
				Sf("(`%s` is now tainted).", outVarName),
			)
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

					tpFun := fe.GetOriginal().GetType().(*types.Signature)

					zeroVals := gogentools.ScanTupleOfZeroValues(file, tpFun.Params(), fe.GetOriginal().IsVariadic())

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

			Comments(groupCase, Sf("Return the tainted `%s`:", outVarName))
			groupCase.Return(Id(out.VarName))
		})
	return code.Line()
}
func generate_ResuFuncPara(file *File, fe *feparser.FEFunc, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	// from: result
	// medium: func
	// into: param
	// NOTE: does this actually happen? It needs extra steps, right?

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Results[indexIn]
	out := fe.Parameters[indexOut]

	in.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("from", in.TypeName))
	out.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			Comments(groupCase, Sf("The flow is from `%s` into `%s`.", inVarName, outVarName))

			Comments(groupCase, Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			gogentools.ComposeTypeAssertion(file, groupCase, in.VarName, in.GetOriginal().GetType(), in.GetOriginal().IsVariadic())

			Comments(groupCase, Sf("Declare `%s` variable:", out.VarName))
			gogentools.ComposeVarDeclaration(file, groupCase, out.VarName, out.GetOriginal().GetType(), out.GetOriginal().IsVariadic())
			gogentools.ImportPackage(file, out.PkgPath, out.PkgName)

			Comments(groupCase,
				"Call the function that will transfer the taint",
				Sf("from the result `intermediateCQL` to parameter `%s`:", outVarName),
			)
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

					tpFun := fe.GetOriginal().GetType().(*types.Signature)

					zeroVals := gogentools.ScanTupleOfZeroValues(file, tpFun.Params(), fe.GetOriginal().IsVariadic())

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

			Comments(groupCase,
				Sf(
					"Extra step (`%s` taints `intermediateCQL`, which taints `%s`:",
					in.VarName,
					out.VarName,
				),
			)
			groupCase.Id("link").Call(Id(in.VarName), Id("intermediateCQL"))

			Comments(groupCase, Sf("Return the tainted `%s`:", out.VarName))
			groupCase.Return(Id(out.VarName))
		})
	return code.Line()
}
func generate_ResuFuncResu(file *File, fe *feparser.FEFunc, identityInp *feparser.CodeQlIdentity, identityOutp *feparser.CodeQlIdentity) *Statement {
	// from: result
	// medium: func
	// into: result

	indexIn := identityInp.Index
	indexOut := identityOutp.Index

	in := fe.Results[indexIn]
	out := fe.Results[indexOut]

	in.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("from", in.TypeName))
	out.VarName = gogentools.NewNameWithPrefix(feparser.NewLowerTitleName("into", out.TypeName))

	inVarName := in.VarName
	outVarName := out.VarName

	code := BlockFunc(
		func(groupCase *Group) {
			Comments(groupCase, Sf("The flow is from `%s` into `%s`.", inVarName, outVarName))

			Comments(groupCase, Sf("Assume that `sourceCQL` has the underlying type of `%s`:", inVarName))
			gogentools.ComposeTypeAssertion(file, groupCase, in.VarName, in.GetOriginal().GetType(), in.GetOriginal().IsVariadic())
			gogentools.ImportPackage(file, out.PkgPath, out.PkgName)

			Comments(groupCase,
				"Call the function that transfers the taint",
				Sf("from the result `%s` to result `%s`", inVarName, outVarName),
				"(extra steps needed)",
			)
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

					tpFun := fe.GetOriginal().GetType().(*types.Signature)

					zeroVals := gogentools.ScanTupleOfZeroValues(file, tpFun.Params(), fe.GetOriginal().IsVariadic())

					for _, zero := range zeroVals {
						call.Add(zero)
					}

				},
			)

			Comments(groupCase,
				Sf(
					"Extra step (`%s` taints `intermediateCQL`, which taints `%s`:",
					in.VarName,
					out.VarName,
				))
			groupCase.Id("link").Call(Id(in.VarName), Id("intermediateCQL"))

			Comments(groupCase, Sf("Return the tainted `%s`:", out.VarName))
			groupCase.Return(Id(out.VarName))
		})
	return code.Line()
}

func newStatement() *Statement {
	return &Statement{}
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
	Blocks    []*feparser.FlowBlock
}

//
func (req *PayloadSetPointers) Validate() error {
	if req.Signature == "" {
		return errors.New("req.Signature is not set")
	}
	if err := feparser.ValidateBlocksAreActive(req.Blocks...); err != nil {
		return fmt.Errorf(
			"error validating block: %s", err,
		)
	}

	return nil
}

func generateCodeQLFlowConditions_FEFunc(fn *feparser.FEFunc, blocks []*feparser.FlowBlock) (string, error) {
	return generateCodeQLFlowCondition_V2(
		fn,
		func(block *feparser.FlowBlock) ([]*feparser.CodeQlIdentity, []*feparser.CodeQlIdentity, error) {
			return getIdentitiesByBlock_FEFunc(fn, block)
		},
		blocks,
	)
}
func generateCodeQLFlowConditions_FEMethod(fn *feparser.FETypeMethod, blocks []*feparser.FlowBlock) (string, error) {
	return generateCodeQLFlowCondition_V2(
		fn.Func,
		func(block *feparser.FlowBlock) ([]*feparser.CodeQlIdentity, []*feparser.CodeQlIdentity, error) {
			return getIdentitiesByBlock_FEMethod(fn, block)
		},
		blocks,
	)
}
func gatherIdentitiesPerType(ids []*feparser.CodeQlIdentity) (recv *feparser.CodeQlIdentity, params []*feparser.CodeQlIdentity, results []*feparser.CodeQlIdentity) {
	for _, id := range ids {
		switch id.Element {
		case feparser.ElementReceiver:
			recv = id
		case feparser.ElementParameter:
			params = append(params, id)
		case feparser.ElementResult:
			results = append(results, id)
		}
	}
	return
}

func generateCodeQLFlowCondition_V2(fn *feparser.FEFunc, idGetter feparser.IdentityGetter, blocks []*feparser.FlowBlock) (string, error) {
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

	return "(" + finalBuf.String() + ")", nil
}

func validateBlockLen_FEFunc(fn *feparser.FEFunc, blocks ...*feparser.FlowBlock) error {
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

// getIdentitiesByBlock_FEFunc gathers and returns the inp and outp identities
// from the provided FEFunc based on the values of the FlowBlock `block`.
func getIdentitiesByBlock_FEFunc(fn *feparser.FEFunc, block *feparser.FlowBlock) ([]*feparser.CodeQlIdentity, []*feparser.CodeQlIdentity, error) {

	lenParameters := len(fn.Parameters)

	if err := validateBlockLen_FEFunc(fn, block); err != nil {
		return nil, nil, err
	}
	identitiesInp := make([]*feparser.CodeQlIdentity, 0)
	for index, v := range block.Inp {
		if v == false {
			continue
		}
		if index < lenParameters {
			// get identity from parameters:
			id := fn.Parameters[index].Identity
			identitiesInp = append(identitiesInp, id)
		} else {
			// get identity from results:
			id := fn.Results[index-lenParameters].Identity
			identitiesInp = append(identitiesInp, id)
		}
	}

	identitiesOutp := make([]*feparser.CodeQlIdentity, 0)
	for index, v := range block.Outp {
		if v == false {
			continue
		}
		if index < lenParameters {
			// get identity from parameters:
			id := fn.Parameters[index].Identity
			identitiesOutp = append(identitiesOutp, id)
		} else {
			// get identity from results:
			id := fn.Results[index-lenParameters].Identity
			identitiesOutp = append(identitiesOutp, id)
		}
	}

	return identitiesInp, identitiesOutp, nil
}

func validateBlockLen_FEMethod(fn *feparser.FETypeMethod, blocks ...*feparser.FlowBlock) error {
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
func getIdentitiesByBlock_FEMethod(fe *feparser.FETypeMethod, block *feparser.FlowBlock) ([]*feparser.CodeQlIdentity, []*feparser.CodeQlIdentity, error) {

	lenParameters := len(fe.Func.Parameters)

	if err := validateBlockLen_FEMethod(fe, block); err != nil {
		return nil, nil, err
	}

	identitiesInp := make([]*feparser.CodeQlIdentity, 0)
	for index, v := range block.Inp {
		if v == false {
			continue
		}
		if index == 0 {
			// get identity from receiver:
			id := fe.Receiver.Identity
			identitiesInp = append(identitiesInp, id)
		}
		if index > 0 && index <= lenParameters {
			// get identity from parameters:
			id := fe.Func.Parameters[index-1].Identity
			identitiesInp = append(identitiesInp, id)
		}
		if index > lenParameters {
			// get identity from results:
			id := fe.Func.Results[index-lenParameters-1].Identity
			identitiesInp = append(identitiesInp, id)
		}
	}

	identitiesOutp := make([]*feparser.CodeQlIdentity, 0)
	for index, v := range block.Outp {
		if v == false {
			continue
		}
		if index == 0 {
			// get identity from receiver:
			id := fe.Receiver.Identity
			identitiesOutp = append(identitiesOutp, id)
		}
		if index > 0 && index <= lenParameters {
			// get identity from parameters:
			id := fe.Func.Parameters[index-1].Identity
			identitiesOutp = append(identitiesOutp, id)
		}
		if index > lenParameters {
			// get identity from results:
			id := fe.Func.Results[index-lenParameters-1].Identity
			identitiesOutp = append(identitiesOutp, id)
		}
	}

	return identitiesInp, identitiesOutp, nil
}

type StatementAndName struct {
	Statement    *Statement
	TestFuncName string
}

// for each block, generate a golang test function for each inp and outp combination.
func generateGoTestBlock_Func(file *File, fe *feparser.FEFunc) []*StatementAndName {
	// Seed the random number generator with the hash of the
	// FEFunc, so that the numbers in the variable names
	// will stay the same as long as the FEFunc is the same.
	//rand.Seed(int64(MustHashAnyWithJSON(fe.CodeQL.Blocks)))

	children := make([]*StatementAndName, 0)
	for blockIndex, block := range fe.CodeQL.Blocks {
		inps, outps, err := getIdentitiesByBlock_FEFunc(fe, block)
		if err != nil {
			panic(err)
		}

		for inpIndex, inp := range inps {
			for outpIndex, outp := range outps {

				childBlock := generateGoChildBlock_Func(
					file,
					fe,
					inp,
					outp,
				)
				{
					if childBlock != nil {

						testFuncID := "TaintStepTest_" + feparser.FormatCodeQlName(fe.PkgPath+"-"+fe.Name) + Sf("_B%vI%vO%v", blockIndex, inpIndex, outpIndex)
						enclosed := Func().Id(testFuncID).
							ParamsFunc(
								func(group *Group) {
									group.Add(Id("sourceCQL").Interface())
								},
							).
							Interface().
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
func generateGoTestBlock_Method(file *File, fe *feparser.FETypeMethod) []*StatementAndName {
	// Seed the random number generator with the hash of the
	// FETypeMethod, so that the numbers in the variable names
	// will stay the same as long as the FETypeMethod is the same.
	//rand.Seed(int64(MustHashAnyWithJSON(fe.CodeQL.Blocks)))

	children := make([]*StatementAndName, 0)
	for blockIndex, block := range fe.CodeQL.Blocks {
		inps, outps, err := getIdentitiesByBlock_FEMethod(fe, block)
		if err != nil {
			panic(err)
		}

		for inpIndex, inp := range inps {
			for outpIndex, outp := range outps {

				childBlock := generateChildBlock_Method(
					file,
					fe,
					inp,
					outp,
				)
				{
					if childBlock != nil {

						testFuncID := "TaintStepTest_" + feparser.FormatCodeQlName(fe.Receiver.PkgPath+"-"+fe.ClassName) + Sf("_B%vI%vO%v", blockIndex, inpIndex, outpIndex)
						enclosed := Func().Id(testFuncID).
							ParamsFunc(
								func(group *Group) {
									group.Add(Id("sourceCQL").Interface())
								},
							).
							Interface().
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

const (
	CodeQLExtendsFunctionModel       = "TaintTracking::FunctionModel"
	CodeQLExtendsFunctionModelMethod = "TaintTracking::FunctionModel, Method"
)

const (
	CodeQL_TPL_Single_Func = `
	// signature: {{.Signature}}
	hasQualifiedName("{{ .PkgPath }}", "{{ .Name }}") and {{ .CodeQL.GeneratedConditions }}`

	CodeQL_TPL_Single_TypeMethod = `
	// signature: {{.Func.Signature}}
	hasQualifiedName("{{ .Receiver.PkgPath }}", "{{ .Receiver.TypeName }}", "{{ .Func.Name }}") and {{ .CodeQL.GeneratedConditions }}`

	CodeQL_TPL_Single_InterfaceMethod = `
	// signature: {{.Func.Signature}}
	implements("{{ .Receiver.PkgPath }}", "{{ .Receiver.TypeName }}", "{{ .Func.Name }}") and {{ .CodeQL.GeneratedConditions }}`
)

type CompressedTemplateValue struct {
	ClassName  string
	Extends    string
	Conditions string
}

func CompressedGenerateCodeQLTT_All(buf *bytes.Buffer, fePackage *feparser.FEPackage) error {
	classTpl, err := NewTextTemplateFromFile("./templates/v2-compressed-taint-tracking.txt")
	if err != nil {
		return err
	}
	{
		funcsTempBuf := new(bytes.Buffer)
		fnTpl, err := NewTextTemplateFromString("name", CodeQL_TPL_Single_Func)
		if err != nil {
			return err
		}

		found := 0
		for _, fe := range fePackage.Funcs {
			if !fe.CodeQL.IsEnabled {
				continue
			}
			if err := fe.CodeQL.Validate(); err != nil {
				Errorf("invalid pointers for %q: %s", fe.Signature, err)
				continue
			}
			if found > 0 {
				funcsTempBuf.WriteString(PadNewLines("\nor"))
			}
			found++

			generatedConditions, err := generateCodeQLFlowConditions_FEFunc(fe, fe.CodeQL.Blocks)
			if err != nil {
				return fmt.Errorf("error generating codeql conditions for %q: %s", fe.Signature, err)
			}
			fe.CodeQL.GeneratedConditions = PadNewLines(generatedConditions)

			err = fnTpl.Execute(funcsTempBuf, fe)
			if err != nil {
				return fmt.Errorf("error while executing template for func %q: %s", fe.ID, err)
			}
		}

		if found > 0 {
			vals := &CompressedTemplateValue{
				ClassName:  feparser.FormatCodeQlName("FunctionModels"),
				Extends:    CodeQLExtendsFunctionModel,
				Conditions: funcsTempBuf.String(),
			}
			buf.WriteString("\n")
			err = classTpl.Execute(buf, vals)
			if err != nil {
				return fmt.Errorf("error while executing compressed template for funcs: %s", err)
			}
		}
	}
	{
		found := 0
		foundTypeMethods := 0
		foundInterfaceMethods := 0

		typeMethodsTempBuf := new(bytes.Buffer)
		typMethTpl, err := NewTextTemplateFromString("name", CodeQL_TPL_Single_TypeMethod)
		if err != nil {
			return err
		}
		for _, fe := range fePackage.TypeMethods {
			if !fe.CodeQL.IsEnabled {
				continue
			}
			if err := fe.CodeQL.Validate(); err != nil {
				Errorf("invalid pointers for %q: %s", fe.Func.Signature, err)
				continue
			}
			if found > 0 {
				typeMethodsTempBuf.WriteString(PadNewLines("\nor"))
			}
			found++
			foundTypeMethods++

			generatedConditions, err := generateCodeQLFlowConditions_FEMethod(fe, fe.CodeQL.Blocks)
			if err != nil {
				return fmt.Errorf("error generating codeql conditions for %q: %s", fe.Func.Signature, err)
			}
			fe.CodeQL.GeneratedConditions = PadNewLines(generatedConditions)

			err = typMethTpl.Execute(typeMethodsTempBuf, fe)
			if err != nil {
				return fmt.Errorf("error while executing template for type-method %q: %s", fe.ID, err)
			}
		}

		interfaceMethodsTempBuf := new(bytes.Buffer)
		intMethTpl, err := NewTextTemplateFromString("name", CodeQL_TPL_Single_InterfaceMethod)
		if err != nil {
			return err
		}
		for _, fe := range fePackage.InterfaceMethods {
			if !fe.CodeQL.IsEnabled {
				continue
			}
			if err := fe.CodeQL.Validate(); err != nil {
				Errorf("invalid pointers for %q: %s", fe.Func.Signature, err)
				continue
			}
			if found > 0 {
				interfaceMethodsTempBuf.WriteString(PadNewLines("\nor"))
			}
			found++
			foundInterfaceMethods++

			generatedConditions, err := generateCodeQLFlowConditions_FEMethod(feparser.FEIToFET(fe), fe.CodeQL.Blocks)
			if err != nil {
				return fmt.Errorf("error generating codeql conditions for %q: %s", fe.Func.Signature, err)
			}
			fe.CodeQL.GeneratedConditions = PadNewLines(generatedConditions)

			err = intMethTpl.Execute(interfaceMethodsTempBuf, fe)
			if err != nil {
				return fmt.Errorf("error while executing template for interface-method %q: %s", fe.ID, err)
			}
		}

		finalConditions := ""
		if foundTypeMethods > 0 {
			finalConditions += typeMethodsTempBuf.String()
		}
		if foundInterfaceMethods > 0 {
			finalConditions += interfaceMethodsTempBuf.String()
		}

		if found > 0 {
			vals := &CompressedTemplateValue{
				ClassName:  feparser.FormatCodeQlName("MethodModels"),
				Extends:    CodeQLExtendsFunctionModelMethod,
				Conditions: finalConditions,
			}
			buf.WriteString("\n")
			err = classTpl.Execute(buf, vals)
			if err != nil {
				return fmt.Errorf("error while executing compressed template for type-methods: %s", err)
			}
		}
	}

	return nil
}
