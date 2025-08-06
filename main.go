package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
)

const version = "1.0.0"

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

	// Execute the scaffold.sh script
	cmd := exec.Command("./scaffold.sh", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error executing scaffold.sh: %v\n", err)
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
