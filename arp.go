package arpoof

import (
	hdisc "github.com/KennyZ69/HdiscLib"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	serializeOpts = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
)

func NewARPReq(src, dest hdisc.DevData) ([]byte, error) {

	eth, arp, err := buildARPPacket(src, dest)
	if err != nil {
		return nil, err
	}

	arp.Operation = layers.ARPRequest

	buf := gopacket.NewSerializeBuffer()
	if err = gopacket.SerializeLayers(buf, serializeOpts, eth, arp); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func buildARPPacket(src, dest hdisc.DevData) (*layers.Ethernet, *layers.ARP, error) {
	eth := &layers.Ethernet{
		EthernetType: layers.EthernetTypeARP,
		SrcMAC:       src.Mac,
		DstMAC:       dest.Mac,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		SourceHwAddress:   []byte(src.Mac),
		DstHwAddress:      []byte(dest.Mac),
		SourceProtAddress: []byte(src.IP.To4()),
		DstProtAddress:    []byte(dest.IP.To4()),
	}

	return eth, arp, nil
}
