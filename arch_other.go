//go:build !windows

package main

import "runtime"

func is64() bool {
	return runtime.GOARCH == "amd64"
}
