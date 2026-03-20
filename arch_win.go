//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// is64 checks if current kernel is x64 even if in WOW32 mode
func is64() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procGetNativeSystemInfo := kernel32.NewProc("GetNativeSystemInfo")

	// sysInfo is WinAPI _SYSTEM_INFO struct.
	// basically we need only wProcessorArchitecture field.
	// x86 (Intel) means 0, x64 (AMD64) - 9.
	var sysInfo struct {
		wProcessorArchitecture uint16
		_                      uint16  // wReserved
		_                      uint32  // dwPageSize
		_                      uintptr // lpMinimumApplicationAddress
		_                      uintptr // lpMaximumApplicationAddress
		_                      uintptr // dwActiveProcessorMask
		_                      uint32  // dwNumberOfProcessors
		_                      uint32  // dwProcessorType
		_                      uint32  // dwAllocationGranularity
		_                      uint16  // wProcessorLevel
		_                      uint16  // wProcessorRevision
	}
	procGetNativeSystemInfo.Call(uintptr(unsafe.Pointer(&sysInfo)))
	return sysInfo.wProcessorArchitecture == 9
}
