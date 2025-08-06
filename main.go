package main

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed scaffold.sh
var scaffoldScript string

const version = "1.0.7"

func main() {
	var (
		showVersion      = flag.Bool("version", false, "Show version information")
		showVersionShort = flag.Bool("v", false, "Show version information")
		showHelp         = flag.Bool("help", false, "Show help information")
		showHelpShort    = flag.Bool("h", false, "Show help information")
	)

	flag.Parse()

	if *showVersion || *showVersionShort {
		fmt.Printf("Go API Scaffolding Tool v%s\n", version)
		return
	}

	if *showHelp || *showHelpShort {
		showUsage()
		return
	}

	// Get remaining arguments after flags
	args := flag.Args()

	// Check if project directory already exists
	if len(args) > 0 {
		projectName := filepath.Base(args[0])
		if _, err := os.Stat(projectName); err == nil {
			fmt.Printf("⚠️  Directory '%s' already exists.\n", projectName)
			if !confirmOverwrite() {
				fmt.Println("❌ Operation cancelled.")
				os.Exit(0)
			}
			// Remove existing directory
			err := os.RemoveAll(projectName)
			if err != nil {
				fmt.Printf("Error removing existing directory: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("✅ Removed existing directory '%s'\n", projectName)
		}
	}

	// Create temporary script file
	tmpDir, err := os.MkdirTemp("", "scaffold")
	if err != nil {
		fmt.Printf("Error creating temp directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	scriptPath := filepath.Join(tmpDir, "scaffold.sh")
	err = os.WriteFile(scriptPath, []byte(scaffoldScript), 0755)
	if err != nil {
		fmt.Printf("Error writing script file: %v\n", err)
		os.Exit(1)
	}

	// Execute the embedded script
	cmd := exec.Command(scriptPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err = cmd.Run()
	if err != nil {
		fmt.Printf("Error executing scaffold script: %v\n", err)
		os.Exit(1)
	}
}

func showUsage() {
	fmt.Printf(`🚀 Go API Scaffolding Tool v%s

A powerful command-line tool that generates a complete, production-ready
Go API project with best practices, database integration, middleware, and CI/CD setup.

USAGE:
    scaffold [OPTIONS] [MODULE_NAME]

OPTIONS:
    -h, --help       Show this help message
    -v, --version    Show version information

ARGUMENTS:
    MODULE_NAME    Go module name (e.g., github.com/username/project)
                   If not provided, you'll be prompted to enter it

EXAMPLES:
    scaffold                                    # Interactive mode
    scaffold github.com/username/myproject      # Direct module specification
    scaffold -v                                 # Show version
    scaffold -h                                 # Show this help

For more information, visit: https://github.com/ekediala/scaffold
`, version)
}

func confirmOverwrite() bool {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Do you want to overwrite it? (y/N): ")
		response, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			return false
		}

		response = strings.TrimSpace(strings.ToLower(response))

		switch response {
		case "y", "yes":
			return true
		case "n", "no", "":
			return false
		default:
			fmt.Println("Please enter 'y' for yes or 'n' for no.")
		}
	}
}
