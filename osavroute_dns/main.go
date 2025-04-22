package main

import (
	"flag"
	"fmt"
	"net"
)

var (
	iface       = flag.String("iface", "", "The interface used for OSAVRoute with DNS.")
	startTTL    = flag.Int("s", 5, "Start TTL.")
	endTTL      = flag.Int("e", 30, "End TTL.")
	inputFile   = flag.String("i", "", "Input file for scanning.")
	outputFile  = flag.String("o", "", "Output file.")
	natFile     = flag.String("nat", "", "Output file for SNAT.")
	dnsFile     = flag.String("d", "", "Output file for DNS response without transparent forwarding.")
	pps         = flag.Int("pps", 200000, "Sending rate PPS.")
	dstMacStr   = flag.String("dmac", "", "The mac address of router.")
	nSend       = flag.Int("nsend", 1, "The number of senders.")
	nSeg        = flag.Uint64("nseg", 10000000, "The number of addresses scanned in batch.")
	shards      = flag.Uint64("shards", 0, "The bits used for scanning id.")
	shard       = flag.Uint64("shard", 0, "The scanning id used for this scan.")
	startFileNo = flag.Uint64("sno", 0xffffffffffffffff, "The No. of file start from.")
	endFileNo   = flag.Uint64("eno", 0xffffffffffffffff, "The No. of file end with.")
	mode        = flag.String("mode", "stateless", "`early` for early-filtering scanning or `stateless` or stateless scanning or `gran` for blocking granularity scanning.")
	randPfx     = flag.String("rand", "123456789", "The random prefix for domain.")
)

func main() {
	var err error
	flag.Parse()
	if *iface == "" {
		*iface, err = GetDefaultRouteInterface()
		fmt.Println("Default Interface:", *iface)
		if err != nil {
			panic("Please Specify the Interface for OSAVRoute with DNS.")
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

	if *mode == "stateless" {
		if *outputFile == "" {
			panic("Please specify the output path!")
		}

		if *inputFile != "" {
			StatelessScan(srcIpStr, *iface, *inputFile, *outputFile, *natFile, *dnsFile, uint8(*startTTL), uint8(*endTTL), *nSend, *pps, srcMac, dstMac)
		} else {
			StatelessScanWithForwarder(srcMac, dstMac, srcIpStr, *iface, *outputFile, uint8(*startTTL), uint8(*endTTL), *pps, *nSend, *startFileNo, *endFileNo, *nSeg, *shards, *shard)
		}
	} else if *mode == "early" {
		EealyFilteringScan(srcIpStr, *iface, *inputFile, *outputFile, *dnsFile, *randPfx, uint8(*startTTL), uint8(*endTTL), *pps, srcMac, dstMac)
	} else if *mode == "gran" {
		BlockingGranScan(*iface, *inputFile, *randPfx, *pps, srcMac, dstMac)
	} else {
		panic("Invalid mode!")
	}
}
