package arpoof

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	hdisc "github.com/KennyZ69/HdiscLib"
	"github.com/google/gopacket/pcap"
)

const (
	routeFile = "/proc/net/route"
)

// return content of a file in bytes
func readFile(file string) ([]byte, error) {
	f, err := os.Open(file) // this opens the file just for reading
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bytes, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// GetGateway returns the ip of the gateway as a string (from /proc/net/route file) and error ! I guess works only on Linux !
func GetGateway() (net.IP, error) {
	bytes, err := readFile(routeFile)
	if err != nil {
		return nil, err
	}

	return parseGatewayFile(bytes)
}

// parseGatewayFile takes in the bytes of /proc/net/route file and parses them to return the Gateway IP and error
func parseGatewayFile(file []byte) (net.IP, error) {
	s := bufio.NewScanner(bytes.NewReader(file))

	if !s.Scan() {
		err := s.Err()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("No gateway found\n")
	}

	for s.Scan() {
		row := s.Text()
		// split each row (token) by tabs ("\t")
		fields := strings.Split(row, "\t")

		if len(fields) < 11 {
			return nil, fmt.Errorf("Invalid file format for %s\n", routeFile)
		}

		// 1 is the destination and 7 is the mask
		// Iface(0)	Destination(1)	Gateway(2)	Flags	RefCnt	Use	Metric	Mask(7)		MTU	Window	IRTT
		if !(fields[1] == "00000000" && fields[7] == "00000000") {
			continue
		}

		// returning found IP address in the file
		return parseGatewayIPBytes(fields[2])
	}

	return nil, fmt.Errorf("No gateway found\n")
}

// Gets the gateway IP as a string in hex and returns it as net.IP and error
func parseGatewayIPBytes(gateway string) (net.IP, error) {
	ip32, err := strconv.ParseUint(gateway, 16, 32)
	if err != nil {
		return nil, err
	}

	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, uint32(ip32))
	return ip, nil
}

func handleExit(handle *pcap.Handle, victim, original hdisc.DevData) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, os.Kill, syscall.SIGTERM)

	go func() {
		<-sigChan // when a signal gets to the channel, continue executing this routine
		RestoreARPTables(handle, victim, original)
		log.Println("Exiting gracefully... ")
		os.Exit(0)
	}()
}

func saveToLog(data string) {
	f, err := os.Create("packets.log")
	if err != nil {
		log.Fatalf("Error creating packets.log file: %s\n", err)
	}
	defer f.Close()

	if _, err = f.WriteString(data); err != nil {
		log.Fatalf("Error writing data into a packets.log: %s\n", err)
	}
}
