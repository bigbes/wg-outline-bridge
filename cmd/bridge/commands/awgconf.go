package commands

import (
	"fmt"

	"github.com/bigbes/wireguard-outline-bridge/internal/config"
)

// printAWGInterfaceParams prints AmneziaWG-specific parameters for a client config.
func printAWGInterfaceParams(awg *config.AmneziaWGConfig) {
	if awg == nil {
		return
	}
	if awg.Jc != 0 {
		fmt.Printf("Jc = %d\n", awg.Jc)
	}
	if awg.Jmin != 0 {
		fmt.Printf("Jmin = %d\n", awg.Jmin)
	}
	if awg.Jmax != 0 {
		fmt.Printf("Jmax = %d\n", awg.Jmax)
	}
	if awg.S1 != 0 {
		fmt.Printf("S1 = %d\n", awg.S1)
	}
	if awg.S2 != 0 {
		fmt.Printf("S2 = %d\n", awg.S2)
	}
	if awg.S3 != 0 {
		fmt.Printf("S3 = %d\n", awg.S3)
	}
	if awg.S4 != 0 {
		fmt.Printf("S4 = %d\n", awg.S4)
	}
	if awg.H1 != "" {
		fmt.Printf("H1 = %s\n", awg.H1)
	}
	if awg.H2 != "" {
		fmt.Printf("H2 = %s\n", awg.H2)
	}
	if awg.H3 != "" {
		fmt.Printf("H3 = %s\n", awg.H3)
	}
	if awg.H4 != "" {
		fmt.Printf("H4 = %s\n", awg.H4)
	}
	if awg.I1 != "" {
		fmt.Printf("I1 = %s\n", awg.I1)
	}
	if awg.I2 != "" {
		fmt.Printf("I2 = %s\n", awg.I2)
	}
	if awg.I3 != "" {
		fmt.Printf("I3 = %s\n", awg.I3)
	}
	if awg.I4 != "" {
		fmt.Printf("I4 = %s\n", awg.I4)
	}
	if awg.I5 != "" {
		fmt.Printf("I5 = %s\n", awg.I5)
	}
}
