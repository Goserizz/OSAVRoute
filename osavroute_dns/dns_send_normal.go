package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type DNSPoolNormal struct {
	inIpChan          chan []byte
	inTtlChan         chan uint8
	outIcmpTargetChan chan string
	outIcmpResChan    chan string
	outIcmpTtlChan    chan uint8
	outDnsTargetChan  chan string
	outDnsTtlChan     chan uint8
	outDnsResChan     chan string
	srcIpStr          string
	ifaceName         string
	srcMac            []byte
	dstMac            []byte
	finish            bool
	randPfx           string
	domain            string
}

func NewDNSPoolNormal(
	srcIpStr string,
	ifaceName string,
	randPfx string,
	domain string,
	srcMac []byte,
	dstMac []byte,
) *DNSPoolNormal {
	dnsPool := &DNSPoolNormal{
		inIpChan:          make(chan []byte, BUF_SIZE),
		inTtlChan:         make(chan uint8, BUF_SIZE),
		outIcmpTargetChan: make(chan string, BUF_SIZE),
		outIcmpResChan:    make(chan string, BUF_SIZE),
		outIcmpTtlChan:    make(chan uint8, BUF_SIZE),
		outDnsTargetChan:  make(chan string, BUF_SIZE),
		outDnsTtlChan:     make(chan uint8, BUF_SIZE),
		outDnsResChan:     make(chan string, BUF_SIZE),
		srcIpStr:          srcIpStr,
		ifaceName:         ifaceName,
		srcMac:            srcMac,
		dstMac:            dstMac,
		finish:            false,
		randPfx:           randPfx,
		domain:            domain,
	}
	go dnsPool.send()
	go dnsPool.recvIcmp()
	go dnsPool.recvDns()
	return dnsPool
}

func (p *DNSPoolNormal) Add(
	dstIp []byte,
	ttl uint8,
) {
	p.inIpChan <- dstIp
	p.inTtlChan <- ttl
}

func (p *DNSPoolNormal) GetIcmp() (
	string,
	string,
	uint8,
) {
	select {
	case targetIp := <-p.outIcmpTargetChan:
		return targetIp, <-p.outIcmpResChan, <-p.outIcmpTtlChan
	case <-time.After(time.Second):
		return "", "", 0
	}
}

func (p *DNSPoolNormal) GetDns() (
	string,
	string,
	uint8,
) {
	select {
	case targetIp := <-p.outDnsTargetChan:
		return targetIp, <-p.outDnsResChan, <-p.outDnsTtlChan
	case <-time.After(time.Second):
		return "", "", 0
	}
}

func (p *DNSPoolNormal) LenInChan() int {
	return len(p.inIpChan)
}

func (p *DNSPoolNormal) send() {
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
	srcIp := net.ParseIP(p.srcIpStr)
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
	copy(ipv4Hdr[12:16], srcIp.To4()) // Source address
	// [16 - 20] Destination address

	// UDP Header
	udpHdrBuf := new(bytes.Buffer)
	binary.Write(udpHdrBuf, binary.BigEndian, uint16(0))  // local port
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
	formatDomain := p.randPfx + ".00.00000000.1." + p.domain
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

		dstIpHigh := uint32(binary.BigEndian.Uint16(dstIp[0:2]))
		dstIpLow := uint32(binary.BigEndian.Uint16(dstIp[2:4]))

		// Complete IPv4 Header
		copy(packet[30:34], dstIp)
		packet[22] = ttl // TTL
		ipv4NowCks := ipv4Cks + dstIpHigh + dstIpLow + (uint32(ttl) << 8)
		binary.BigEndian.PutUint16(packet[24:26], uint16(^(ipv4NowCks + (ipv4NowCks >> 16))))

		// Complete UDP Header
		// encode ttl in packet[55:57]
		ttlString := fmt.Sprintf("%02d", ttl)
		for i, c := range ttlString {
			packet[56+RAND_NUM_LEN+i] = byte(c)
		}
		// encode ip in packet[58:66]
		ipString := ipToHex(dstIp)
		for i, c := range ipString {
			packet[57+RAND_NUM_LEN+TTL_LEN+i] = byte(c)
		}

		binary.BigEndian.PutUint16(packet[34:36], uint16(ttl)+BASE_PORT) // encode ttl in source port

		// Send packet
		for {
			if err = syscall.Sendto(fd, packet, 0, bindAddr); err == nil {
				break
			}
		}
	}
}

func (p *DNSPoolNormal) recvIcmp() {
	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)

	// Bind local address
	addr := syscall.SockaddrInet4{Port: 0, Addr: [4]byte{0, 0, 0, 0}}
	err = syscall.Bind(fd, &addr)
	if err != nil {
		panic(err)
	}

	ipv4LenUint8 := uint8(IPV4_HDR_SIZE + UDP_HDR_SIZE + DNS_HDR_SIZE + 1 + RAND_NUM_LEN + 1 + TTL_LEN + 1 + IPV4_ENCODE_LEN + 1 + IS_NORMAL_LEN + 1 + len(p.domain) + 5)
	// Receive ICMP packets
	for {
		buf := make([]byte, 1500)
		_, addr, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			panic(err)
		}
		if p.finish {
			break
		}
		if buf[31] != ipv4LenUint8 || buf[37] != syscall.IPPROTO_UDP || buf[20] != 11 || buf[21] != 0 {
			continue
		}
		p.outIcmpTargetChan <- net.IP(buf[44:48]).String()
		p.outIcmpResChan <- net.IP(addr.(*syscall.SockaddrInet4).Addr[:]).String()
		p.outIcmpTtlChan <- uint8(binary.BigEndian.Uint16(buf[48:50]) - BASE_PORT)
	}
}

func (p *DNSPoolNormal) recvDns() {
	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)

	laddr := &syscall.SockaddrInet4{}
	copy(laddr.Addr[:], net.ParseIP(p.srcIpStr))
	err = syscall.Bind(fd, laddr)
	if err != nil {
		panic(err)
	}

	domainLen := RAND_NUM_LEN + 1 + TTL_LEN + 1 + IPV4_ENCODE_LEN + 1 + IS_NORMAL_LEN + 1 + len(p.domain) + 1

	// Read packets
	for {
		buf := make([]byte, 1500)
		_, addr, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			panic(err)
		}
		if p.finish {
			break
		}

		txId := binary.BigEndian.Uint16(buf[28:30])
		if txId != TRANSACTION_ID {
			continue
		}

		dnsPacket := buf[28:]
		question, _ := ParseDNSQuestion(dnsPacket, 12)
		if len(question.Name) == 0 {
			continue
		}
		if len(question.Name) != domainLen {
			continue
		}
		ttl, err := strconv.Atoi(question.Name[RAND_NUM_LEN+1:][:TTL_LEN])
		if err != nil {
			continue
		}
		ipStr, err := hexToIp(question.Name[RAND_NUM_LEN+1+TTL_LEN+1:][:IPV4_ENCODE_LEN])
		if err != nil {
			continue
		}
		p.outDnsTargetChan <- ipStr
		p.outDnsTtlChan <- uint8(ttl)
		p.outDnsResChan <- net.IP(addr.(*syscall.SockaddrInet4).Addr[:]).String()
	}
}

func (p *DNSPoolNormal) Finish() {
	p.Add(nil, 0)
	p.finish = true
}
