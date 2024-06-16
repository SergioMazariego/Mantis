package main

import (
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed Tools/*
var embeddedFiles embed.FS

// Get hostname of the system.
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		panic("could not get hostname")
	}
	return hostname
}

// Writes embedded executable files to disk.
func WriteExecutableFile(baseDir string) {
	// Ensure the Tools directory exists inside the baseDir
	dir := filepath.Join(baseDir, "Tools")
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		panic("could not create Tools directory")
	}

	// Write each executable file to the Tools directory
	writeFile(filepath.Join(dir, "LastActivityView.exe"), embeddedFiles, "Tools/LastActivityView.exe")
	writeFile(filepath.Join(dir, "pslist64.exe"), embeddedFiles, "Tools/pslist64.exe")
	writeFile(filepath.Join(dir, "tcpvcon64.exe"), embeddedFiles, "Tools/tcpvcon64.exe")
	writeFile(filepath.Join(dir, "autorunsc64.exe"), embeddedFiles, "Tools/autorunsc64.exe")
}

// Writes a file from the embedded files to disk.
func writeFile(filePath string, fs embed.FS, embeddedPath string) {
	fileContent, err := fs.ReadFile(embeddedPath)
	if err != nil {
		panic(fmt.Sprintf("could not read embedded file %s: %v", embeddedPath, err))
	}

	err = os.WriteFile(filePath, fileContent, 0700)
	if err != nil {
		panic(fmt.Sprintf("could not write file %s to disk: %v", filePath, err))
	}
}

// Executes the LastActivityView command and returns its output.
func ExecCommandLastActivityView(baseDir string) {
	output, err := exec.Command("cmd.exe", "/c", filepath.Join(baseDir, "Tools", "LastActivityView.exe"), "/scomma", filepath.Join(baseDir, "LastActivityView.csv")).Output()
	if err != nil {
		panic("could not run LastActivityView")
	}
	fmt.Println(string(output))
}

// Executes the pslist64 command and returns its output.
func ExecCommandPslist64(baseDir string) {
	output, err := exec.Command("cmd.exe", "/c", filepath.Join(baseDir, "Tools", "pslist64.exe"), "-t", "/accepteula", ">", filepath.Join(baseDir, "ProcessList.txt")).Output()
	if err != nil {
		panic("could not run pslist64")
	}
	fmt.Println(string(output))
}

// Executes the tcpvcon64 command and returns its output.
func ExecCommandTcpvcon64(baseDir string) {
	output, err := exec.Command("cmd.exe", "/c", filepath.Join(baseDir, "Tools", "tcpvcon64.exe"), "/accepteula", "-c", ">", filepath.Join(baseDir, "LogsTCPView.csv")).Output()
	if err != nil {
		panic("could not run tcpvcon64")
	}
	fmt.Println(string(output))
}

// Executes the autorunsc64 command and returns its output.
func ExecCommandAutorunsc64(baseDir string) {
	output, err := exec.Command("cmd.exe", "/c", filepath.Join(baseDir, "Tools", "autorunsc64.exe"), "/accepteula", "-a", "*", "-h", "s", "-ct", ">", filepath.Join(baseDir, "Autoruns.csv")).Output()
	if err != nil {
		panic("could not run autorunsc64")
	}
	fmt.Println(string(output))
}

// Removes the executable files written to disk.
func RemoveFiles(baseDir string) error {
	files := []string{
		filepath.Join(baseDir, "Tools", "LastActivityView.exe"),
		filepath.Join(baseDir, "Tools", "pslist64.exe"),
		filepath.Join(baseDir, "Tools", "tcpvcon64.exe"),
		filepath.Join(baseDir, "Tools", "autorunsc64.exe"),
	}
	for _, file := range files {
		err := os.Remove(file)
		if err != nil {
			return fmt.Errorf("could not remove file %s: %w", file, err)
		}
	}

	// Remove the Tools directory.
	err := os.RemoveAll(filepath.Join(baseDir, "Tools"))
	if err != nil {
		return fmt.Errorf("could not remove Tools directory: %w", err)
	}

	return nil
}

// Copies event viewer files to a destination folder.
func GetEventViewerFiles(baseDir string) {
	output, err := exec.Command("cmd.exe", "/c", "xcopy", "%SystemRoot%\\System32\\winevt\\Logs", filepath.Join(baseDir, "Events"), "/s", "/i").Output()
	if err != nil {
		panic("could not copy events")
	}
	fmt.Println(string(output))
}

// Copies PowerShell history files to a destination folder.
func GetPowershellHistory(baseDir string) {
	output, err := exec.Command("cmd.exe", "/c", "xcopy", "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine", filepath.Join(baseDir, "Powershell"), "/s", "/i").Output()
	if err != nil {
		panic("could not copy powershell history file")
	}
	fmt.Println(string(output))
}

// Copies files from the system temporary folder to a destination folder.
func GetTempFolder(baseDir string) {
	output, err := exec.Command("cmd.exe", "/c", "xcopy", "C:\\WINDOWS\\Temp", filepath.Join(baseDir, "Temp"), "/s", "/i").Output()
	if err != nil {
		panic("could not copy Temp folder")
	}
	fmt.Println(string(output))
}

// Progress bar visible in terminal
func updateProgress(step, total int) {
	progress := float64(step) / float64(total) * 100
	fmt.Printf("\rProgress: [%-50s] %d%%", strings.Repeat("#", int(progress/2)), int(progress))
}

func main() {
	hostname := getHostname()
	baseDir := filepath.Join(".", hostname)
	totalSteps := 10
	step := 0

	WriteExecutableFile(baseDir)
	step++
	updateProgress(step, totalSteps)
	time.Sleep(500 * time.Millisecond)

	ExecCommandLastActivityView(baseDir)
	step++
	updateProgress(step, totalSteps)
	time.Sleep(500 * time.Millisecond)

	ExecCommandPslist64(baseDir)
	step++
	updateProgress(step, totalSteps)
	time.Sleep(500 * time.Millisecond)

	ExecCommandTcpvcon64(baseDir)
	step++
	updateProgress(step, totalSteps)
	time.Sleep(500 * time.Millisecond)

	ExecCommandAutorunsc64(baseDir)
	step++
	updateProgress(step, totalSteps)
	time.Sleep(500 * time.Millisecond)

	GetEventViewerFiles(baseDir)
	step++
	updateProgress(step, totalSteps)
	time.Sleep(500 * time.Millisecond)

	GetPowershellHistory(baseDir)
	step++
	updateProgress(step, totalSteps)
	time.Sleep(500 * time.Millisecond)

	GetTempFolder(baseDir)
	step++
	updateProgress(step, totalSteps)
	time.Sleep(500 * time.Millisecond)

	err := RemoveFiles(baseDir)
	if err != nil {
		fmt.Printf("\nError removing files: %v\n", err)
	} else {
		step++
		updateProgress(step, totalSteps)
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Println("\nAll tasks completed.")
}
