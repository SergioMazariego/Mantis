// Package main provides functions for managing executable files, executing commands, and retrieving files in Go.
package main

import (
	"embed"
	"fmt"
	"os"
	"os/exec"
)

//go:embed LastActivityView.exe pslist64.exe tcpvcon64.exe autorunsc64.exe
var embeddedFiles embed.FS

// WriteExecutableFile writes embedded executable files to disk.
func WriteExecutableFile() {
	// Write each executable file to disk
	writeFile("LastActivityView.exe", embeddedFiles)    // Done
	writeFile("pslist64.exe", embeddedFiles)            // Done
	writeFile("tcpvcon64.exe", embeddedFiles)           // Done
	writeFile("autorunsc64.exe", embeddedFiles)         // Done
}

// writeFile writes a file from the embedded files to disk.
func writeFile(fileName string, fs embed.FS) {
	fileContent, err := fs.ReadFile(fileName)
	if err != nil {
		panic("could not read embedded file")
	}

	err = os.WriteFile(fileName, fileContent, 0700)
	if err != nil {
		panic("could not write file to disk")
	}
}

// ExecCommandLastActivityView executes the LastActivityView command and returns its output.
func ExecCommandLastActivityView() []byte {
	output, err := exec.Command("cmd.exe", "/c", "LastActivityView.exe", "/scomma", "LastActivityView.csv").Output()
	if err != nil {
		panic("could not run LastActivityView")
	}
	return output
}

// ExecCommandPslist64 executes the pslist64 command and returns its output.
func ExecCommandPslist64() []byte {
	output, err := exec.Command("cmd.exe", "/c", "pslist64.exe", "-t", "/accepteula", ">", "ProcessList.txt").Output()
	if err != nil {
		panic("could not run pslist64")
	}
	return output
}

// ExecCommandTcpvcon64 executes the tcpvcon64 command and returns its output.
func ExecCommandTcpvcon64() []byte {
	output, err := exec.Command("cmd.exe", "/c", "tcpvcon64.exe", "/accepteula", "-c", ">", "LogsTCPView.csv").Output()
	if err != nil {
		panic("could not run tcpvcon64")
	}
	return output
}

// ExecCommandAutorunsc64 executes the autorunsc64 command and returns its output.
func ExecCommandAutorunsc64() []byte {
	output, err := exec.Command("cmd.exe", "/c", "autorunsc64.exe", "/accepteula", "-a", "*", "-h", "s", "-ct", ">", "Autoruns.csv").Output()
	if err != nil {
		panic("could not run tcpvcon64")
	}
	return output
}

// RemoveFiles removes the executable files written to disk.
func RemoveFiles() error {
	files := []string{"LastActivityView.exe", "pslist64.exe", "tcpvcon64.exe", "autorunsc64.exe"}
	for _, file := range files {
		err := os.Remove(file)
		if err != nil {
			return fmt.Errorf("could not remove file %s: %w", file, err)
		}
	}
	return nil
}

// GetEventViewerFiles copies event viewer files to a destination folder.
func GetEventViewerFiles() []byte {
	output, err := exec.Command("cmd.exe", "/c", "xcopy", "%SystemRoot%\\System32\\winevt\\Logs", "Events\\", "/s", "/i").Output()
	if err != nil {
		panic("could not copy events")
	}
	return output
}

// GetPowershellHistory copies PowerShell history files to a destination folder.
func GetPowershellHistory() []byte {
	output, err := exec.Command("cmd.exe", "/c", "xcopy", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine", "Powershell\\", "/s", "/i").Output()
	if err != nil {
		panic("could not copy powershell history file")
	}
	return output
}

// GetTempFolder copies files from the system temporary folder to a destination folder.
func GetTempFolder() []byte {
	output, err := exec.Command("cmd.exe", "/c", "xcopy", "C:\\WINDOWS\\Temp", "Temp\\", "/s", "/i").Output()
	if err != nil {
		panic("could not copy Temp folder")
	}
	return output
}

func main() {
	WriteExecutableFile()
	defer RemoveFiles()

	ExecCommandLastActivityView()
	ExecCommandPslist64()
	ExecCommandTcpvcon64()
	ExecCommandAutorunsc64()
	GetEventViewerFiles()
	GetPowershellHistory()
	GetTempFolder()
}
