# About

Simple executable patcher which just replaces **b**cryptprimitives.dll with **a**cryptprimitives.dll.

Mainly it's command line alternative of [golangwin7patch](https://github.com/stunndard/golangwin7patch),
which fixes crash of golang programs compiled with go-1.21.5+ on old windows versions (7, 2008).

Note: there is no guarantee, that after patching your EXE file will work, especially if it contains very specific
instructions. This application JUST REPLACES TWO STRINGS. That's all.
You can do it with any HEX-editor. 

# Usage

From sources:

```bash
go run /some/path/to/go-win7patcher desired_executable.exe
```

or from precompiled executable (see `Releases` section):

```bash
gw7p-x86.exe desired_executable.exe
```

It will create backup of original file and place `acryptprimitives.dll` of the same executable architecture (x86 or x64)
to the same directory. `acryptprimitives.dll` **must** present in `c:\windows\system32` of target OS before patched
executable start.

If target OS is x64, x64 DLL may be used for both x86 and x64 executables.

# Security notice

Provided DLLs received from [golangwin7patch](https://github.com/stunndard/golangwin7patch) and provided as is.
[We don't have sources](https://github.com/stunndard/golangwin7patch/issues/10) of these DLLs, you can ask golangwin7patch's author for them.

And yes, DLLs must present in system directory, it's golang requirement.

We know that two [VirusTotal](https://www.virustotal.com/gui/file/f6f83ac4022e8bf195b112268a2907efd1032da6e33e437af6d70caed8e89cc6) 
engines detects DLLs as malicious, but hope, that is false positive detection.

# Compilation

```bash
GOOS=windows GOARCH=386 go build -trimpath -o gw7p-x32.exe .
GOOS=windows GOARCH=amd64 go build -trimpath -o gw7p-x64.exe .
# OPTIONAL: patch patchers itself
go run main.go gw7p-x32.exe
go run main.go gw7p-x64.exe
```

Note: if you rename executable to "something-patcher", UAC will detect it as installer and 
[require administrator privileges](https://github.com/golang/go/issues/68523#issuecomment-2239692446) to start.

