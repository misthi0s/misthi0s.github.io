---
title: Golang Quick Tips & Tricks - Compile Project as DLL
author: misthi0s
categories: ["golang"]
tags: [golang, tips, tricks, go, dll, programming]
date: 2024-12-26 12:42:00
---

In this installment of "Golang Quick Tips & Tricks", we'll go over how to compile your Go project as a Dynamic Link Library, or DLL for short. DLLs are binary files that contain functions and data that can be used by other programs. For instance, if you are making a program that needs to launch a different process, you will likely need to call the function "CreateProcess" within the "kernel32.dll" library file to do this. Creating a DLL allows you to easily re-purpose common functions that your different programs need to use without having to re-write it in every single program that needs it.

## Pre-Requisites

For this to work properly, you'll need a few pre-requisites before compilation:

- Go version 1.10+ (for Windows; earlier versions will work if running on a Linux system)
- GCC installed and in the PATH directory (MinGW is an excellent choice for Windows systems to achieve this)
- Go environment variable "CGO_ENABLED" set to "1" (To apply globally, you can run `go env -w CGO_ENABLED=1`)

With those few requirements met, your system should be all set to compile a DLL!

## Writing the Code

For this example, we'll make a simple Go program that creates a file (called "dll_test.txt") and writes the string "Hello from DLL!" into it. We'll create this as a function named "CreateFile" in the program. The code for this can be seen below:

```
package main

import "os"

func CreateFile() {
	string := []byte("Hello from DLL!\n")
	os.WriteFile("dll_test.txt", string, 0644)
}

func main() {
	CreateFile()
}
```

This program will work, as written, as a normal exe file if desired. However, since we want to make this a DLL, there's a few extra steps we need to take to allow it to function properly.

The first step is to include another import statement of `import "C"`. This tells Go that you want to use cgo, the Golang feature that allows you to call C code from within Go.

The second step is to include an export command above the function you want to export in the commented format of `//export <function_name>`, where \<function_name\> is the name of the function to export. In the above example, this would be `//export CreateFile`, since we want to allow the "CreateFile" function to be accessed by other programs.

The final code for our program would then look like the following:

```
package main

import "C"
import "os"

//export CreateFile
func CreateFile() {
	string := []byte("Hello from DLL!\n")
	os.WriteFile("dll_test.txt", string, 0644)
}

func main() {
	CreateFile()
}
```

With this finalized, we can now build our program!

## Building the DLL

To tell the compiler to build as a DLL, you need to include the `-buildmode=c-shared` directive in the `build` command line. Using the above as an example, we can build our program to `test_dll.dll` with the following command:

`go build -buildmode=c-shared -o test_dll.dll dll.go`

where "dll.go" is the name of our source file. Remember, this will only work if you first have the variable "CGO_ENABLED" set to "1" and the GCC compiler installed on the system.

If everything works successfully, you should see two new files created: `test_dll.dll` and `test_dll.h`.

## Testing the DLL

To test the compilation to make sure everything is worked as expected, we can use `rundll32.exe`. While, under normal circumstances, you'll likely be using the exported functions in other programs, `rundll32.exe` is a great way to manually run a function without needing to wrap the call in further code. Rundll32 uses the following syntax to execute a function in a DLL:

`rundll32.exe <dll_path>,<function_name>`

The \<function_name\> in the above code can refer to the name itself (in our case, CreateFile) OR the ordinal number of the function (in our case, #1). So our test run command would look like the following:

`rundll32.exe test_dll.dll,CreateFile`

Running this in our command window, we can see that the "dll_test.txt" file is successfully created and contains the string "Hello from DLL!". There we have it; we now have a functioning DLL that we can use in other programs to run common functions!

## Going Further - Multiple Exports

Another thing I wanted to mention; while our example only has one exported function (CreateFile), you can always add more if you need to. Like normal DLLs, you can have multiple exported functions to allow you to compile all the useful features you need to access within one DLL. To do this, all you need to do is create more functions and add the `//export <function_name>` code snippet above them.

With our example, let's say we want to add three more exported functions: `WriteFile`, `ReadFile`, and `DeleteFile`. All we need to do is create the Go functions for them and then add the export commands like above. The new source code would look like the following for this:

```
package main

import "C"
import "os"

//export CreateFile
func CreateFile() {
	string := []byte("Hello from DLL!\n")
	os.WriteFile("dll_test.txt", string, 0644)
}

//export WriteFile
func WriteFile() {}

//export ReadFile
func ReadFile() {}

//export DeleteFile
func DeleteFile() {}

func main() {
	CreateFile()
}
```

Once compiled, we can then use `rundll32.exe` to call the new functions like shown before. Now, the above functions won't actually do anything if run, since they are empty functions and have no code within them, but it shows you how you can include multiple exports into one DLL file if you need to.

## TLDR; Recap

Pre-Requisites:

- Go Version 1.10+
- GCC installed
- CGO_ENABLED set to 1

In Code:

- `import "C"`
- `//export <function_name>` above each \<function_name\> that you want to export

Compilation:

- `go build -buildmode=c-shared -o <output_dll_name> <go_file>`