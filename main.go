// Package main contains patcher for windows executable to use Go-compiled .exe file in version 7 (2008 R2)
// It just replaces bcryptprimitives.dll call with acryptprimitives.dll.
// New acryptprimitives.dll *MUST* present in C:\windows\system32 directory before call.
// Original patcher: https://github.com/stunndard/golangwin7patch
package main

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// values shifted to 1 ascii symbol forward to avoid incorrect patching self executable
var (
	oldDLL = []byte("cdszquqsjnjujwft/emm") // bcryptprimitives.dll
	newDLL = []byte("bdszquqsjnjujwft/emm") // acryptprimitives.dll
)

//go:embed "acryptprimitives32.dll"
var dllData32 []byte

//go:embed "acryptprimitives64.dll"
var dllData64 []byte

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Println("input file not provided")
		os.Exit(1)
	}
	fName := flag.Arg(0)
	data, err := os.ReadFile(fName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if len(data) < 0x90 ||
		data[0] != 0x4D || data[1] != 0x5A || // exe magic
		data[0x80] != 0x50 || data[0x81] != 0x45 { // PE format
		fmt.Printf(`file not seems to be windows executable, got:
	0x80 - 0x%X, but 0x50 required
	0x81 - 0x%X, but 0x45 required
`, data[0x80], data[0x81])
		os.Exit(1)
	}
	var dll []byte
	if data[0x84] == 0x4c && data[0x85] == 0x01 { // x86
		fmt.Println("x86 executable")
		dll = dllData32
	} else if data[0x84] == 0x64 && data[0x85] == 0x86 { // x86-64
		fmt.Println("x64 executable")
		dll = dllData64
	} else {
		fmt.Printf(`unsupported windows PE machine type, got:
	0x84 - 0x%X, but 0x64/0x4C required
	0x85 - 0x%X, but 0x86/0x01 required
`, data[0x84], data[0x85])
		os.Exit(1)
	}

	oldDLLu16, newDLLu16 := make([]byte, len(oldDLL)*2), make([]byte, len(newDLL)*2)

	// shift DLL file names back to normal and
	// make LE Unicode strings
	for i := range oldDLL {
		oldDLL[i] -= 1
		oldDLLu16[i*2] = oldDLL[i]
	}
	for i := range newDLL {
		newDLL[i] -= 1
		newDLLu16[i*2] = newDLL[i]
	}

	newData := bytes.ReplaceAll(data, oldDLL, newDLL)
	newData = bytes.ReplaceAll(newData, oldDLLu16[:len(oldDLLu16)-1], newDLLu16[:len(newDLLu16)-1])

	if bytes.Equal(data, newData) {
		fmt.Println("file already patched")
	} else {
		if err = os.Rename(fName, fName+".bak"); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if err = os.WriteFile(fName, newData, 0o600); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("file", fName, "patched")
	}

	dllPath := filepath.Join(filepath.Dir(fName), string(newDLL))
	err = os.WriteFile(dllPath, dll, 0o600)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(`DLL placed to the same directory as provided file. don't forget to place it into C:\windows\system32 directory`)
}
