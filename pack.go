package arpoof

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketStats is a struct used just in utility functions as a counter of different packet types intercepted
type PacketStats struct {
	Ethernet int
	IPv4     int
	TCP      int
	UDP      int
	HTTP     int
	Total    int
	mu       sync.Mutex
}

func (ps *PacketStats) addFromPacket(packet gopacket.Packet) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.Total++

	if packet.Layer(layers.LayerTypeEthernet) != nil {
		ps.Ethernet++
	}
	if packet.Layer(layers.LayerTypeIPv4) != nil {
		ps.IPv4++
	}
	if packet.Layer(layers.LayerTypeTCP) != nil {
		ps.TCP++
	}
	if packet.Layer(layers.LayerTypeUDP) != nil {
		ps.UDP++
	}
	if app := packet.ApplicationLayer(); app != nil {
		payload := string(app.Payload())
		if strings.Contains(payload, "HTTP/1.1") {
			ps.HTTP++
		}
	}

	if dnsl := packet.Layer(layers.LayerTypeDNS); dnsl != nil {
		dns := dnsl.(*layers.DNS)
		if dns.QR == false && len(dns.Questions) > 0 {
			domain := string(dns.Questions[0].Name)
			log.Println("DNS request for: ", domain)
		}
	}
}

func (ps *PacketStats) printSummary() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	fmt.Printf("\r[+] Total: %d | Ethernet: %d | IPv4: %d | TCP: %d | UDP: %d | HTTP: %d\n", ps.Total, ps.Ethernet, ps.IPv4, ps.TCP, ps.UDP, ps.HTTP)
}

func parsePacket(packet gopacket.Packet) string {
	var data string = ""

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		data = fmt.Sprintf("Ethernet packet: %s -> %s | Payload: %s\n", eth.SrcMAC, eth.DstMAC, string(eth.Payload))

	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		data = fmt.Sprintf("IPv4 packet: %s -> %s | Prot: %d | Payload: %s\n", ip.SrcIP, ip.DstIP, string(ip.Payload))
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		data = fmt.Sprintf("TCP: %d -> %d | SYN: %v | ACK: %v | FIN: %v\n", tcp.SrcPort, tcp.DstPort, tcp.SYN, tcp.ACK, tcp.FIN)
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		data = fmt.Sprintf("UDP: %d -> %d | Payload: %s\n", udp.SrcPort, udp.DstPort, string(udp.Payload))
	}

	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		payload := string(appLayer.Payload())
		if strings.Contains(payload, "HTTP/1.1") {
			data = fmt.Sprintf(parseHTTP(payload))
		}
	}

	return data
}

func parseHTTP(payload string) string {
	var ret string = ""

	lines := strings.Split(payload, "\n")

	if len(lines) > 0 {
		ret += fmt.Sprintf("HTTP Request: %s\n", lines[0])
	}

	for _, line := range lines[1:] {
		if line == "\r" || line == "" {
			break
		}
		ret += fmt.Sprintf("	%s\n", line)
	}

	return ret
}
