package arpoof

import (
	hdisc "github.com/KennyZ69/HdiscLib"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	// serializing options for gopacket layers and buffer later
	serializeOpts = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
)

// NewARPReq makes a new arp request using buildARPPacket function and returns it in bytes
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

// NewARPRep makes a new arp reply using buildARPPacket function and returns it in bytes
func NewARPRep(src, dest hdisc.DevData) ([]byte, error) {

	eth, arp, err := buildARPPacket(src, dest)
	if err != nil {
		return nil, err
	}

	arp.Operation = layers.ARPReply

	buf := gopacket.NewSerializeBuffer()
	if err = gopacket.SerializeLayers(buf, serializeOpts, eth, arp); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil

}

// internal function to build an arp packet based on passed dev data...
// returing ethernet and arp layers alongside a possible error
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
