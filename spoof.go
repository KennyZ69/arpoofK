package arpoof

import (
	"log"
	"net"

	hdisc "github.com/KennyZ69/HdiscLib"
	"github.com/mdlayher/arp"
)

func SendSpoofARP() {}

// as the attackMac a nil can be passed if you want your local machine as the middle man
func spoof(attackMac net.HardwareAddr, target hdisc.DevData, stop chan struct{}) error {
	ifi, err := hdisc.LocalIface()
	if err != nil {
		return err
	}

	attackMac = ifi.HardwareAddr
	gateIP, err := GetGateway()
	if err != nil {
		return err
	}

	// TODO: change this for a passed *pcap.Handle
	// c, err := arp.Dial(ifi)
	// if err != nil {
	// 	return err
	// }
	// defer c.Close()

	for {
		select {
		case <-stop:
			log.Println("ARP Spoofing stopped!")
			return nil
		default:
			// now keep sending the arp packet with a timeout
			p := &arp.Packet{
				Operation: arp.OperationReply,
			}
		}
	}
}

func RestoreARPTables() {}

func readARP() {}
