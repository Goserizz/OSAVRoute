package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"syscall"
)

type DNSPoolSpoofSame struct {
	inIpChan  chan []byte
	inTtlChan chan uint8
	srcIpStr  string
	ifaceName string
	srcMac    []byte
	dstMac    []byte
	finish    bool
	randPfx   string
	domain    string
}

func NewDNSPoolSpoofSame(
	srcIpStr string,
	ifaceName string,
	randPfx string,
	domain string,
	srcMac []byte,
	dstMac []byte,
) *DNSPoolSpoofSame {
	dnsPool := &DNSPoolSpoofSame{
		inIpChan:  make(chan []byte, BUF_SIZE),
		inTtlChan: make(chan uint8, BUF_SIZE),
		srcIpStr:  srcIpStr,
		ifaceName: ifaceName,
		srcMac:    srcMac,
		dstMac:    dstMac,
		finish:    false,
		randPfx:   randPfx,
		domain:    domain,
	}
	go dnsPool.send()
	return dnsPool
}

func (p *DNSPoolSpoofSame) Add(
	dstIp []byte,
	ttl uint8,
) {
	p.inIpChan <- dstIp
	p.inTtlChan <- ttl
}

func (p *DNSPoolSpoofSame) LenInChan() int {
	return len(p.inIpChan)
}

func (p *DNSPoolSpoofSame) send() {
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
	// [8]     TTL
	ipv4Hdr[9] = syscall.IPPROTO_UDP // Protocol = 17 (UDP)
	// [10 - 11] Header Checksum
	// [12 - 16] Source address
	// [16 - 20] Destination address

	// UDP Header
	udpHdrBuf := new(bytes.Buffer)
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(BASE_PORT)) // local port
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(53))        // remote port
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(0))         // length
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(0))         // checksum
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
	formatDomain := p.randPfx + ".00.00000000.2." + p.domain
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

	var dstIp []byte
	var ttl uint8
	for {
		dstIp = <-p.inIpChan
		ttl = <-p.inTtlChan
		if dstIp == nil {
			break
		}

		// Complete IPv4 Header
		// Invert the last bit of dstIp to get srcIp

		dstIpHigh := uint32(binary.BigEndian.Uint16(dstIp[0:2]))
		dstIpLow := uint32(binary.BigEndian.Uint16(dstIp[2:4]))

		copy(packet[26:30], dstIp)
		copy(packet[30:34], dstIp)
		packet[22] = ttl // TTL
		ipv4NowCks := ipv4Cks + dstIpHigh + dstIpLow + dstIpHigh + dstIpLow + (uint32(ttl) << 8)
		binary.BigEndian.PutUint16(packet[24:26], uint16(^(ipv4NowCks + (ipv4NowCks >> 16))))

		// Complete UDP Header
		ttlString := fmt.Sprintf("%02d", ttl)
		for i, c := range ttlString {
			packet[56+RAND_NUM_LEN+i] = byte(c)
		}
		ipString := ipToHex(dstIp)
		for i, c := range ipString {
			packet[57+RAND_NUM_LEN+TTL_LEN+i] = byte(c)
		}

		// Send packet
		for {
			if err = syscall.Sendto(fd, packet, 0, bindAddr); err == nil {
				break
			}
		}
	}
}

func (p *DNSPoolSpoofSame) Finish() {
	p.Add(nil, 0)
	p.finish = true
}

func (p *DNSPoolSpoofSame) GetIcmp() (
	string,
	string,
	uint8,
) {
	// Implementation of GetIcmp method
	// This method should return three values: string, string, uint8
	// You can implement the logic to return these values based on your requirements
	// For now, we'll return empty strings and a default uint8 value
	return "", "", 0
}
