package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	
	fmt.Print("Target process name: ")
	scanner.Scan()
	target := strings.TrimSpace(scanner.Text())
	
	fmt.Print("File to hijack: ")
	scanner.Scan()
	pattern := strings.TrimSpace(scanner.Text())
	
	fmt.Print("Output file path: ")
	scanner.Scan()
	output := strings.TrimSpace(scanner.Text())
	
	fmt.Print("Close handle after? (y/n): ")
	scanner.Scan()
	killInput := strings.ToLower(strings.TrimSpace(scanner.Text()))
	kill := killInput == "y" || killInput == "yes"

	fmt.Printf("\n>>> Hijacking: %s from %s\n", pattern, target)

	procs, err := ScanProcesses(target)
	if err != nil {
		fmt.Printf("!!! Scan failed: %v\n", err)
		os.Exit(1)
	}
	if len(procs) == 0 {
		fmt.Println("!!! No running instances")
		os.Exit(1)
	}

	fmt.Printf(">>> Scanning %d instance(s)\n", len(procs))

	success := false
	for pid, handles := range procs {
		fmt.Printf("... PID %d (%d handles)\n", pid, len(handles))
		
		for _, h := range handles {
			data, location, err := ExtractFile(h.Val, pid, pattern)
			if err != nil {
				continue
			}
			
			success = true
			fmt.Printf("\n*** FOUND ***\n")
			fmt.Printf("  Location: %s\n", location)
			fmt.Printf("  PID: %d\n", pid)
			fmt.Printf("  Handle: 0x%X\n", h.Val)
			fmt.Printf("  Size: %d bytes\n", len(data))
			
			if err := SaveFile(data, output); err != nil {
				fmt.Printf("!!! Save failed: %v\n", err)
				continue
			}
			
			fmt.Printf(">>> Saved to: %s\n", output)
			if kill {
				if err := KillHandle(pid, h.Val); err != nil {
					fmt.Printf("!!! Kill handle failed: %v\n", err)
				} else {
					fmt.Println(">>> Handle terminated")
				}
			}
			goto done
		}
	}

done:
	if !success {
		fmt.Println("\n!!! File not found")
		os.Exit(1)
	}
	
	fmt.Println("\n>>> Complete!")
}
