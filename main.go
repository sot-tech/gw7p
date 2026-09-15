// Package main contains patcher for windows executable to use Go-compiled .exe file in version 7 (2008 R2)
// It just replaces bcryptprimitives.dll call with acryptprimitives.dll.
// New acryptprimitives.dll *MUST* present in C:\windows\system32 directory before call.
// Original patcher: https://github.com/stunndard/golangwin7patch
package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// values shifted to 1 ascii symbol forward to avoid incorrect patching self executable
var (
	oldDLL = []byte("cdszquqsjnjujwft/emm") // bcryptprimitives.dll
	newDLL = []byte("bdszquqsjnjujwft/emm") // acryptprimitives.dll
)

func main() {
	var systemDLL, forceDLL bool
	if runtime.GOOS == "windows" {
		flag.BoolVar(&systemDLL, "s", false,
			"place DLL to system directory (system32 or sysWOW64 depending on executable and local kernel architecture).\nrequires administrator privileges.")
	}
	flag.BoolVar(&forceDLL, "f", false,
		"force write DLL even if it already exists in target directory (system or executable)")
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

	exe64, dll, err := checkPE(data)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if exe64 {
		fmt.Println("x64 executable detected")
	} else {
		fmt.Println("x86 executable detected")
	}

	oldDLLu16, newDLLu16 := prepareSubstitutions()
	newData := bytes.ReplaceAll(data, oldDLL, newDLL)
	newData = bytes.ReplaceAll(newData, oldDLLu16[:len(oldDLLu16)-1], newDLLu16[:len(newDLLu16)-1])
	setPEMinimumTarget(newData)
	if bytes.Equal(data, newData) {
		fmt.Println("file", fName, "already patched")
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

	if err, dllPath := writeDLL(dll, fName, exe64, systemDLL, forceDLL); err == nil {
		fmt.Println("DLL written to", dllPath)
	} else if errors.Is(err, errDLLExists) {
		fmt.Println("DLL", dllPath, "already exists")
	} else {
		fmt.Println(err)
		os.Exit(1)
	}
}

//go:embed "acryptprimitives32.dll"
var dllData32 []byte

//go:embed "acryptprimitives64.dll"
var dllData64 []byte

func checkPE(data []byte) (is64 bool, dll []byte, err error) {
	if len(data) < 0x40 ||
		data[0] != 0x4D || data[1] != 0x5A { // exe magic
		return false, nil, fmt.Errorf(`file not seems to be windows executable, got:
	0x00 - 0x%X, but 0x4D required
	0x01 - 0x%X, but 0x5A required`, data[0], data[1])
	}

	offset := binary.LittleEndian.Uint32(data[0x3c:])
	if len(data) < int(offset)+4 {
		return false, nil, fmt.Errorf(`file not seems to be windows executable, invalid PE pointer:
	0x%X greater than file length (0x%X)`, offset+4, len(data))
	}

	if data[offset] != 0x50 || data[offset+1] != 0x45 { // PE format
		return false, nil, fmt.Errorf(`file not seems to be windows executable, invalid PE header:
	0x%X - 0x%X, but 0x50 required
	0x%X - 0x%X, but 0x45 required`, offset, data[offset], offset+1, data[offset+1])
	}

	offset += 4

	if data[offset] == 0x4c && data[offset+1] == 0x01 { // x86
		dll = dllData32
	} else if data[offset] == 0x64 && data[offset+1] == 0x86 { // x86-64
		is64, dll = true, dllData64
	} else {
		err = fmt.Errorf(`unsupported windows PE machine type, got:
	0x%X - 0x%X, but 0x64/0x4C required
	0x%X - 0x%X, but 0x86/0x01 required`, offset, data[offset], offset+1, data[offset+1])
	}
	return is64, dll, err
}

func setPEMinimumTarget(data []byte) {
	// Optional Header Windows-Specific MajorOperatingSystemVersion offset
	offset := binary.LittleEndian.Uint32(data[0x3C:]) + 0x40
	data = data[offset:]
	majorOperatingSystemVersion := binary.LittleEndian.Uint16(data)
	minorOperatingSystemVersion := binary.LittleEndian.Uint16(data[2:])
	majorSubsystemVersion := binary.LittleEndian.Uint16(data[8:])
	minorSubsystemVersion := binary.LittleEndian.Uint16(data[10:])
	if majorOperatingSystemVersion > 6 || minorOperatingSystemVersion > 1 ||
		majorSubsystemVersion > 6 || minorSubsystemVersion > 1 {
		// setting minimum version to 6.1 (win7/2008r2)
		binary.LittleEndian.PutUint16(data, 6)
		binary.LittleEndian.PutUint16(data[2:], 1)
		binary.LittleEndian.PutUint16(data[8:], 6)
		binary.LittleEndian.PutUint16(data[10:], 1)
	}
}

func prepareSubstitutions() (oldDLLu16, newDLLu16 []byte) {
	oldDLLu16, newDLLu16 = make([]byte, len(oldDLL)*2), make([]byte, len(newDLL)*2)
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
	return oldDLLu16, newDLLu16
}

var (
	errDLLArchMissmatch = errors.New("unable to use x64 DLL in x86 kernel")
	errDLLExists        = errors.New("target DLL already exists")
)

const (
	system32Dir = `C:\Windows\System32`
	sysWOW64Dir = `C:\Windows\SysWOW64`
)

func writeDLL(dllData []byte, fileName string, exe64, systemDLL, forceWriteDLL bool) (
	err error, dllPath string,
) {
	if systemDLL {
		sys64 := is64()
		switch {
		case exe64 == sys64:
			dllPath = system32Dir
		case exe64 && !sys64:
			err = errDLLArchMissmatch
		case !exe64 && sys64:
			dllPath = sysWOW64Dir
		}
	} else {
		dllPath = filepath.Dir(fileName)
	}
	dllPath = filepath.Join(dllPath, string(newDLL))
	_, fErr := os.Stat(dllPath)
	if fErr == nil {
		if forceWriteDLL {
			err = os.WriteFile(dllPath, dllData, 0o600)
		} else {
			err = errDLLExists
		}
	} else if os.IsNotExist(fErr) {
		err = os.WriteFile(dllPath, dllData, 0o600)
	} else {
		err = fErr
	}
	return err, dllPath
}
