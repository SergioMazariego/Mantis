![Mantis Logo](Mantis.jpeg){:width="200px"}

# Mantis

Mantis is a forensics tool developed in Go, designed to streamline system analysis and investigation. It automates the retrieval of critical logs and artifacts for forensic analysis, utilizing various external utilities from Sysinternals and NirSoft.

## Functionality

### LastActivityView
- **Description**: LastActivityView is a Windows utility from NirSoft that gathers information about recent system activity, opened files, and user actions.
- **Analysis**: Provides insights into recent user activity, including executed processes, file accesses, and user logins. Useful for understanding system usage patterns and identifying suspicious behavior.

### pslist64 
- **Description**: pslist64 is a command-line tool from the Sysinternals suite that lists detailed information about processes running on a system.
- **Analysis**: Enables the examination of running processes, including their process IDs, parent processes, memory usage, and executable paths. Useful for identifying malicious or suspicious processes and understanding their behavior.

### tcpvcon64
- **Description**: tcpvcon64 is a utility for displaying detailed information about TCP connections on a system.
- **Analysis**: Provides visibility into active network connections, including local and remote IP addresses, connection states, and process IDs. Helpful for identifying network-based attacks, monitoring network activity, and tracing communication paths.

### autorunsc64
- **Description**: autorunsc64 is a utility that displays autorun entries on a system, including startup programs, services, drivers, and more.
- **Analysis**: Allows examination of autorun configurations to identify potential malware persistence mechanisms, such as malicious services, scheduled tasks, and startup programs. Helps in detecting and removing unauthorized or malicious autorun entries.

### Event Viewer Logs
- **Description**: Copies event viewer logs from `%SystemRoot%\System32\winevt\Logs` to a specified destination folder.
- **Analysis**: Provides access to Windows event logs, which contain records of system events, errors, warnings, and user activities. Valuable for investigating security incidents, system crashes, and application errors.

### PowerShell History
- **Description**: Copies PowerShell history files from `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine` to a specified folder.
- **Analysis**: Allows examination of PowerShell commands executed on the system, including user inputs, executed scripts, and command outputs. Helps in understanding administrative actions, scripting activities, and potential security breaches.

### Temporary Folder
- **Description**: Copies files from the system temporary folder (`C:\WINDOWS\Temp`) to a specified destination.
- **Analysis**: Provides access to temporary files generated by system and application processes. Useful for analyzing temporary artifacts, identifying malicious files, and understanding system activity patterns.

## Usage
To use Mantis, simply run the executable as adminstrator. It will automatically perform the specified tasks and gather the necessary logs and artifacts for forensic analysis.
## Compilation Instructions
To compile the Mantis tool, follow these steps:

1. Install Go on your system if you haven't already. You can download and install it from the official website: [https://golang.org/dl/](https://golang.org/dl/).

2. Clone the Mantis repository from its GitHub URL:
   
   ```bash
   git clone https://github.com/SergioMazariego/Mantis

3. Navigate to the directory where the mantis Go file is located.
   ```bash
   cd Mantis
4. Compile the mantis tool using the following command:
   ```bash
   go build mantis.go
This command will compile the Go code and generate an executable file named mantis (or mantis.exe on Windows).

5. Once the compilation is successful, you can run the mantis tool by executing the generated executable file:
   ```bash
   mantis.exe 
Make sure to run the executable as an administrator to ensure proper functionality, as some of the tasks performed by Mantis may require elevated privileges.

That's it! You've compiled and can now use the Mantis tool for system analysis and investigation.

## Contributing
Contributions to Mantis are welcome! Feel free to submit issues or pull requests to improve the tool's functionality or add new features.

## License
This project is licensed under the [GPL-3.0 license](LICENSE).