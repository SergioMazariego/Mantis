package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Get hostname of the system.
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Error: Could not get hostname.")
		os.Exit(1)
	}
	return hostname
}

// Verify required ZIP files exist and extract them.
func verifyAndExtractTools(baseDir string) {
	requiredZips := map[string]string{
		"SysinternalsSuite.zip": "SysinternalsSuite",
		"lastactivityview.zip":  "LastActivityView",
	}

	for zipFile, extractFolder := range requiredZips {
		zipPath := filepath.Join(baseDir, zipFile)
		destPath := filepath.Join(baseDir, extractFolder)

		if _, err := os.Stat(destPath); os.IsNotExist(err) {
			if _, err := os.Stat(zipPath); err == nil {
				fmt.Printf("Extracting: %s...\n", zipFile)
				err := unzipFile(zipPath, destPath)
				if err != nil {
					fmt.Printf("Error extracting %s: %v\n", zipFile, err)
				} else {
					fmt.Printf("Extracted: %s to %s\n", zipFile, extractFolder)
				}
			} else {
				fmt.Printf("Missing zip: %s (Skipping extraction)\n", zipFile)
			}
		} else {
			fmt.Printf("Already extracted: %s\n", extractFolder)
		}
	}
}

// Unzip a file to a destination folder.
func unzipFile(zipPath, destPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	err = os.MkdirAll(destPath, 0755)
	if err != nil {
		return err
	}

	for _, f := range r.File {
		filePath := filepath.Join(destPath, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(filePath, 0755)
			continue
		}

		outFile, err := os.Create(filePath)
		if err != nil {
			return err
		}
		defer outFile.Close()

		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		_, err = io.Copy(outFile, rc)
		if err != nil {
			return err
		}
	}
	return nil
}

// Executes a command and ensures output is written correctly.
func executeCommand(exePath, outputPath string, args ...string) {
	cmd := exec.Command("cmd.exe", append([]string{"/c", exePath}, args...)...)

	// Ensure Artifacts directory exists
	artifactsDir := filepath.Dir(outputPath)
	err := os.MkdirAll(artifactsDir, 0755)
	if err != nil {
		fmt.Printf("Error creating Artifacts folder: %v\n", err)
		return
	}

	// Redirect output to file
	outFile, err := os.Create(outputPath)
	if err != nil {
		fmt.Printf("Error creating output file %s: %v\n", outputPath, err)
		return
	}
	defer outFile.Close()

	cmd.Stdout = outFile
	cmd.Stderr = outFile

	err = cmd.Run()
	if err != nil {
		fmt.Printf("Error executing %s: %v\n", exePath, err)
	}
}

// Executes tools and saves outputs in `Artifacts/`.
func ExecCommandLastActivityView(baseDir, artifactsDir string) {
	// Define las rutas completas del ejecutable y del archivo de salida
	exePath := filepath.Join(baseDir, "LastActivityView", "LastActivityView.exe")
	outputFile := filepath.Join(artifactsDir, "LastActivityView.csv")

	// Asegurar que el directorio de salida existe
	err := os.MkdirAll(artifactsDir, 0755)
	if err != nil {
		fmt.Printf("Error creando carpeta Artifacts: %v\n", err)
		return
	}

	// Ejecuta el comando
	cmd := exec.Command("cmd.exe", "/c", exePath, "/scomma", outputFile)
	err = cmd.Run()

	if err != nil {
		fmt.Printf("Error ejecutando LastActivityView: %v\n", err)
		return
	}
}

func ExecCommandPslist64(baseDir, artifactsDir string) {
	executeCommand(filepath.Join(baseDir, "SysinternalsSuite", "pslist64.exe"), filepath.Join(artifactsDir, "ProcessList.txt"), "-t", "/accepteula")
}

func ExecCommandTcpvcon64(baseDir, artifactsDir string) {
	executeCommand(filepath.Join(baseDir, "SysinternalsSuite", "tcpvcon64.exe"), filepath.Join(artifactsDir, "LogsTCPView.csv"), "/accepteula", "-c")
}

func ExecCommandAutorunsc64(baseDir, artifactsDir string) {
	executeCommand(filepath.Join(baseDir, "SysinternalsSuite", "autorunsc64.exe"), filepath.Join(artifactsDir, "Autoruns.csv"), "/accepteula", "-a", "*", "-h", "s", "-ct")
}

// Copia archivos del visor de eventos.
func GetEventViewerFiles(baseDir string) {
	exec.Command("cmd.exe", "/c", "xcopy", os.Getenv("SystemRoot")+"\\System32\\winevt\\Logs", filepath.Join(baseDir, "Artifacts", "Events"), "/s", "/i").Run()
}

// Copia archivos de historial de PowerShell.
func GetPowershellHistory(baseDir string) {
	exec.Command("cmd.exe", "/c", "xcopy", os.Getenv("USERPROFILE")+"\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine", filepath.Join(baseDir, "Artifacts", "Powershell"), "/s", "/i").Run()
}

// Copia archivos del directorio Temp del sistema.
func GetTempFolder(baseDir string) {
	exec.Command("cmd.exe", "/c", "xcopy", "C:\\WINDOWS\\Temp", filepath.Join(baseDir, "Artifacts", "Temp"), "/s", "/i").Run()
}

// Progress bar in terminal.
func updateProgress(step, total int) {
	progress := float64(step) / float64(total) * 100
	fmt.Printf("\rProgress: [%-50s] %d%%", strings.Repeat("#", int(progress/2)), int(progress))
	os.Stdout.Sync()
}

func main() {
	// Get the directory of the running executable
	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("Error getting executable path:", err)
		return
	}
	baseDir := filepath.Dir(exePath)

	hostname := getHostname()
	artifactsDir := filepath.Join(baseDir, "Artifacts")

	fmt.Println("Running on:", hostname)

	totalSteps := 5
	step := 0

	// Verify and extract required tools
	verifyAndExtractTools(baseDir)
	step++
	updateProgress(step, totalSteps)
	time.Sleep(500 * time.Millisecond)

	// Execute tools and store outputs in Artifacts folder
	ExecCommandLastActivityView(baseDir, artifactsDir)
	step++
	updateProgress(step, totalSteps)
	time.Sleep(500 * time.Millisecond)

	ExecCommandPslist64(baseDir, artifactsDir)
	step++
	updateProgress(step, totalSteps)
	time.Sleep(500 * time.Millisecond)

	ExecCommandTcpvcon64(baseDir, artifactsDir)
	step++
	updateProgress(step, totalSteps)
	time.Sleep(500 * time.Millisecond)

	ExecCommandAutorunsc64(baseDir, artifactsDir)
	step++
	updateProgress(step, totalSteps)
	time.Sleep(500 * time.Millisecond)

	GetEventViewerFiles(baseDir)

	GetPowershellHistory(baseDir)

	GetTempFolder(baseDir)

	fmt.Println("\nAll tasks completed. Outputs saved in Artifacts/")
}
