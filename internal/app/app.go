package app

import (
	"flag"
	"fmt"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("babyshark", flag.ContinueOnError)
	fs.SetOutput(nil)
	pcapPath := fs.String("pcap", "", "Path to a .pcap or .pcapng file")
	if err := fs.Parse(args); err != nil {
		fmt.Println("usage: babyshark --pcap <file>")
		return 2
	}
	if *pcapPath == "" {
		fmt.Println("usage: babyshark --pcap <file>")
		return 2
	}

	// MVP plumbing placeholder.
	fmt.Printf("babyshark: opening %s (pcap viewer coming next)\n", *pcapPath)
	return 0
}
