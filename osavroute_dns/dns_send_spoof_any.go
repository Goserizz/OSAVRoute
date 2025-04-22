package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"syscall"
)

type DNSPoolSpoofAny struct {
	inSrcChan   chan []byte
	inDstChan   chan []byte
	inRangeChan chan uint8
	ifaceName   string
	srcMac      []byte
	dstMac      []byte
	finish      bool
	randPfx     string
}

func NewDNSPoolSpoofAny(ifaceName string, srcMac, dstMac []byte, randPfx string) *DNSPoolSpoofAny {
	dnsPool := &DNSPoolSpoofAny{
		inSrcChan:   make(chan []byte, BUF_SIZE),
		inDstChan:   make(chan []byte, BUF_SIZE),
		inRangeChan: make(chan uint8, BUF_SIZE),
		ifaceName:   ifaceName,
		srcMac:      srcMac,
		dstMac:      dstMac,
		finish:      false,
		randPfx:     randPfx,
	}
	go dnsPool.send()
	return dnsPool
}

func (p *DNSPoolSpoofAny) Add(srcIp []byte, dstIp []byte, _range uint8) {
	p.inSrcChan <- srcIp
	p.inDstChan <- dstIp
	p.inRangeChan <- _range
}

func (p *DNSPoolSpoofAny) LenInChan() int {
	return len(p.inSrcChan)
}

func (p *DNSPoolSpoofAny) send() {
	// Create IPv6 raw socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_IP)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)

	// Construct MAC Header
	macHdr := make([]byte, MAC_HDR_SIZE)
	copy(macHdr[0:6], p.dstMac)
	copy(macHdr[6:12], p.srcMac)
	binary.BigEndian.PutUint16(macHdr[12:14], syscall.ETH_P_IP)

	// Get Interface Info
	iface, err := net.InterfaceByName(p.ifaceName)
	if err != nil {
		panic(err)
	}
	bindAddr := &syscall.SockaddrLinklayer{Protocol: syscall.ETH_P_IP, Ifindex: iface.Index}

	// IP Header
	// srcIp := net.ParseIP(p.srcIpStr)
	ipv4Hdr := make([]byte, IPV4_HDR_SIZE)
	ipv4Hdr[0] = 0x45 // Vesrion = 4 | header length = 5
	// [1]	 TOS
	// [2] [3] Total length
	// binary.BigEndian.PutUint16(ipv4Hdr[2:4], IPV4_LEN)
	binary.BigEndian.PutUint16(ipv4Hdr[2:4], 70)
	// [4] [5] Identification
	// [6] [7] Flags | Fragment offset
	ipv4Hdr[8] = 64                  // TTL
	ipv4Hdr[9] = syscall.IPPROTO_UDP // Protocol = 17 (UDP)
	// [10 - 11] Header Checksum
	// [12 - 16] Source address
	// [16 - 20] Destination address

	// UDP Header
	udpHdrBuf := new(bytes.Buffer)
	binary.Write(udpHdrBuf, binary.BigEndian, BASE_PORT)  // local port
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(53)) // remote port
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(0))  // length
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(0))  // checksum
	udpHdr := udpHdrBuf.Bytes()

	// Construct DNS Header
	dnsHdrBuf := new(bytes.Buffer)
	var flags uint16 = 0x0100                      // recursive
	var qdcount uint16 = 1                         // # Queries
	var ancount, nscount, arcount uint16 = 0, 0, 0 //  Answer, Authoritive, Addition
	binary.Write(dnsHdrBuf, binary.BigEndian, TRANSACTION_ID)
	binary.Write(dnsHdrBuf, binary.BigEndian, flags)
	binary.Write(dnsHdrBuf, binary.BigEndian, qdcount)
	binary.Write(dnsHdrBuf, binary.BigEndian, ancount)
	binary.Write(dnsHdrBuf, binary.BigEndian, nscount)
	binary.Write(dnsHdrBuf, binary.BigEndian, arcount)
	dnsHdr := dnsHdrBuf.Bytes()

	// construct DNS Query
	dnsQryBuf := new(bytes.Buffer)
	formatDomain := p.randPfx + ".00.00000000.4." + EARLY_DOMAIN
	sections := strings.Split(formatDomain, ".")
	for _, s := range sections {
		binary.Write(dnsQryBuf, binary.BigEndian, byte(len(s))) // length
		for _, b := range []byte(s) {
			binary.Write(dnsQryBuf, binary.BigEndian, b)
		}
	}
	binary.Write(dnsQryBuf, binary.BigEndian, byte(0))   // 0
	binary.Write(dnsQryBuf, binary.BigEndian, uint16(1)) // A
	binary.Write(dnsQryBuf, binary.BigEndian, uint16(1)) // Internet
	dnsQry := dnsQryBuf.Bytes()

	// calculate IP length and UDP length and fill in the header
	ipv4Len := IPV4_HDR_SIZE + UDP_HDR_SIZE + DNS_HDR_SIZE + len(dnsQry)
	binary.BigEndian.PutUint16(ipv4Hdr[2:4], uint16(ipv4Len))
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(UDP_HDR_SIZE+DNS_HDR_SIZE+len(dnsQry)))

	// pre calculate IP header checksum
	ipv4Cks := uint32(0)
	for i := 0; i < 20; i += 2 {
		ipv4Cks += uint32(binary.BigEndian.Uint16(ipv4Hdr[i : i+2]))
	}

	// Combine IP header, UDP header, DNS header, DNS query
	packet := append(macHdr, ipv4Hdr...)
	packet = append(packet, udpHdr...)
	packet = append(packet, dnsHdr...)
	packet = append(packet, dnsQry...)

	var srcIp []byte
	var dstIp []byte
	var _range uint8
	for {
		srcIp = <-p.inSrcChan
		dstIp = <-p.inDstChan
		_range = <-p.inRangeChan
		if srcIp == nil {
			break
		}

		// Complete IPv4 Header
		// Invert the last bit of dstIp to get srcIp

		dstIpHigh := uint32(binary.BigEndian.Uint16(dstIp[0:2]))
		dstIpLow := uint32(binary.BigEndian.Uint16(dstIp[2:4]))
		srcIpHigh := uint32(binary.BigEndian.Uint16(srcIp[0:2]))
		srcIpLow := uint32(binary.BigEndian.Uint16(srcIp[2:4]))

		copy(packet[26:30], srcIp)
		copy(packet[30:34], dstIp)
		ipv4NowCks := ipv4Cks + dstIpHigh + dstIpLow + srcIpHigh + srcIpLow
		binary.BigEndian.PutUint16(packet[24:26], uint16(^(ipv4NowCks + (ipv4NowCks >> 16))))

		// Complete UDP Header
		rangeStr := fmt.Sprintf("%02d", _range)
		for i, c := range rangeStr {
			packet[56+RAND_NUM_LEN+i] = byte(c)
		}
		ipString := ipToHex(dstIp)
		for i, c := range ipString {
			packet[57+RAND_NUM_LEN+RANGE_LEN+i] = byte(c)
		}

		// Send packet
		for {
			if err = syscall.Sendto(fd, packet, 0, bindAddr); err == nil {
				break
			}
		}
	}
}

func (p *DNSPoolSpoofAny) Finish() {
	p.Add(nil, nil, 0)
	p.finish = true
}
