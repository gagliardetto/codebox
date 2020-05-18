package main

import (
	"flag"

	"github.com/gagliardetto/codebox/scanner"
	. "github.com/gagliardetto/utils"
)

func main() {
	var pkg string
	flag.StringVar(&pkg, "pkg", "", "package you want to scan and convert to goa types")
	flag.Parse()

	sc, err := scanner.New(pkg)
	if err != nil {
		panic(err)
	}

	pks, err := sc.Scan()
	if err != nil {
		panic(err)
	}

	for _, pk := range pks {
		//fmt.Println("------")
		//fmt.Println(pk.Aliases)
		//fmt.Println(pk.Path)
		//fmt.Println(pk.Name)
		//spew.Dump(pk.Structs)
		Q(pk.Name)
		Q(pk.Funcs)
	}
}
