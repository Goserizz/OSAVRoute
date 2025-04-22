package main

import (
	"flag"
	"fmt"
	"net"
)

var (
	iface       = flag.String("iface", "", "The interface used for OSAVRoute with TCP.")
	startTtl    = flag.Int("s", 5, "Start TTL.")
	endTtl      = flag.Int("e", 30, "End TTL.")
	inputFile   = flag.String("i", "", "Input file for scanning.")
	outputFile  = flag.String("o", "", "Output file.")
	pps         = flag.Int("pps", 10000, "Sending rate PPS.")
	dstMacStr   = flag.String("dmac", "", "The mac address of router.")
	remotePort  = flag.Uint("r", 80, "The remote port used for sending TCP SYN.")
	nSend       = flag.Int("nsend", 1, "The number of senders.")
	nSeg        = flag.Uint64("nseg", 10000000, "The number of addresses scanned in batch.")
	blockFile   = flag.String("b", "blocklist.txt", "Do not receive packets from these IPs.")
	startFileNo = flag.Uint64("sno", 0xffffffffffffffff, "The No. of file start from.")
	endFileNo   = flag.Uint64("eno", 0xffffffffffffffff, "The No. of file end with.")
)

func main() {
	var err error
	flag.Parse()
	if *iface == "" {
		*iface, err = GetDefaultRouteInterface()
		if err != nil {
			panic("Please Specify the Interface for OSAVRoute with TCP.")
		}
	}
	srcIpv4Arr, _, srcMac, err := GetIface(*iface)
	if err != nil {
		panic(err)
	}
	srcIpStr := srcIpv4Arr[0]
	if *dstMacStr == "" {
		gatewayIP, err := GetDefaultGateway()
		if err != nil {
			panic(err)
		}
		fmt.Println("Default Gateway IP:", gatewayIP)

		*dstMacStr, err = GetMACAddress(gatewayIP)
		if err != nil {
			panic(err)
		}
		fmt.Println("Gateway MAC Address:", *dstMacStr)
	}
	dstMac, err := net.ParseMAC(*dstMacStr)
	if err != nil {
		panic(err)
	}

	if *inputFile == "" {
		TCPRouteScanWithForwarder(srcIpStr, *iface, *outputFile, *blockFile, uint8(*startTtl), uint8(*endTtl), *pps, *nSend, *startFileNo, *endFileNo, *nSeg, srcMac, dstMac, uint16(*remotePort))
	} else {
		TCPRouteScan(srcIpStr, *iface, *inputFile, *outputFile, uint8(*startTtl), uint8(*endTtl), *pps, srcMac, dstMac, uint16(*remotePort))
	}
}
