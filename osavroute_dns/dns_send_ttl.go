package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
)

type IcmpResp struct {
	Target string
	Real   string
	Res    string
	Ttl    uint8
}

type DNSPoolTtl struct {
	inIpChan      chan []byte
	inTtlChan     chan uint8
	icmpParseChan chan []byte
	outIcmpChan   chan IcmpResp
	srcIpStr      string
	ifaceName     string
	srcMac        []byte
	dstMac        []byte
	finish        bool
	nSender       int
	shards        uint16
	shard         uint16
}

func NewDNSPoolTtl(
	nSender, bufSize int,
	srcIpStr, ifaceName string,
	srcMac, dstMac []byte,
	shards, shard uint16,
) *DNSPoolTtl {
	dnsPool := &DNSPoolTtl{
		inIpChan:      make(chan []byte, bufSize),
		inTtlChan:     make(chan uint8, bufSize),
		icmpParseChan: make(chan []byte, bufSize),
		outIcmpChan:   make(chan IcmpResp, bufSize),
		srcIpStr:      srcIpStr,
		ifaceName:     ifaceName,
		srcMac:        srcMac,
		dstMac:        dstMac,
		finish:        false,
		nSender:       nSender,
		shards:        shards,
		shard:         shard,
	}
	for i := 0; i < nSender; i++ {
		go dnsPool.send()
		go dnsPool.parseIcmp()
	}
	go dnsPool.recvIcmp()
	return dnsPool
}

func (p *DNSPoolTtl) Add(
	dstIp []byte,
	ttl uint8,
) {
	if p.finish {
		return
	}
	p.inIpChan <- dstIp
	p.inTtlChan <- ttl
}

func (p *DNSPoolTtl) GetIcmp() (
	string,
	string,
	string,
	uint8,
) {
	select {
	case icmpResp, ok := <-p.outIcmpChan:
		if !ok || p.finish {
			return "", "", "", 0
		}
		return icmpResp.Target, icmpResp.Real, icmpResp.Res, icmpResp.Ttl
	case <-time.After(time.Second):
		return "", "", "", 0
	}
}

func (p *DNSPoolTtl) LenInChan() (
	int,
	int,
	int,
) {
	return len(p.inIpChan), len(p.icmpParseChan), len(p.outIcmpChan)
}

func (p *DNSPoolTtl) send() {
	// Create IPv6 raw socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_IP)
	if err != nil {
		panic(err)
	}
	defer func(fd int) {
		err := syscall.Close(fd)
		if err != nil {
			panic(err)
		}
	}(fd)

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
	ipv4Hdr[0] = 0x45 // Version = 4 | header length = 5
	// [1]	 TOS
	// [2] [3] Total length
	// binary.BigEndian.PutUint16(ipv4Hdr[2:4], IPV4_LEN)
	binary.BigEndian.PutUint16(ipv4Hdr[2:4], 70)
	// [4] [5] Identification
	// [6] [7] Flags | Fragment offset
	ipv4Hdr[6] = 0x40 // Don't fragment
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

	// pre calculate IP header checksum
	ipv4Cks := uint32(0)
	for i := 0; i < 20; i += 2 {
		ipv4Cks += uint32(binary.BigEndian.Uint16(ipv4Hdr[i : i+2]))
	}

	// Combine IP header, UDP header, bogus DNS payload
	packet := append(macHdr, ipv4Hdr...)
	packet = append(packet, udpHdr...)
	for i := 0; i < 42; i++ {
		packet = append(packet, 0)
	}

	var dstIp []byte
	var ok bool
	var ttl uint8
	for {
		dstIp = <-p.inIpChan
		ttl, ok = <-p.inTtlChan
		if !ok || p.finish {
			break
		}
		dstIpHigh := uint32(binary.BigEndian.Uint16(dstIp[0:2]))
		dstIpLow := uint32(binary.BigEndian.Uint16(dstIp[2:4]))

		// Complete IPv4 Header
		copy(packet[18:20], dstIp[:2]) // encode high 16 bits in IP-ID
		copy(packet[30:34], dstIp)
		packet[22] = ttl // TTL
		ipv4NowCks := ipv4Cks + dstIpHigh + dstIpHigh + dstIpLow + (uint32(ttl) << 8)
		binary.BigEndian.PutUint16(packet[24:26], uint16(^(ipv4NowCks + (ipv4NowCks >> 16))))

		// Complete UDP Header
		binary.BigEndian.PutUint16(packet[34:36], uint16(dstIpLow>>p.shards)+BASE_PORT)
		packet[39] = ttl // encode ttl in length

		// Send packet
		for {
			if err = syscall.Sendto(fd, packet, 0, bindAddr); err == nil {
				break
			}
		}
	}
}

func (p *DNSPoolTtl) recvIcmp() {
	// 创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		panic(err)
	}
	defer func(fd int) {
		err := syscall.Close(fd)
		if err != nil {
			panic(err)
		}
	}(fd)

	// 绑定本地地址
	addr := syscall.SockaddrInet4{Port: 0, Addr: [4]byte{0, 0, 0, 0}}
	err = syscall.Bind(fd, &addr)
	if err != nil {
		panic(err)
	}

	// 接收ICMP报文
	for {
		buf := make([]byte, 1500)
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if p.finish {
			break
		}
		if n < 56 {
			continue
		}
		if err != nil {
			panic(err)
		}
		p.icmpParseChan <- buf
	}
}

func (p *DNSPoolTtl) parseIcmp() {
	ipv4LenUint8 := uint8(70)
	ipLowBytes := make([]byte, 2)
	for {
		buf, ok := <-p.icmpParseChan
		if !ok || p.finish {
			break
		}
		if buf[31] != ipv4LenUint8 || buf[37] != syscall.IPPROTO_UDP || buf[20] != 11 || buf[21] != 0 {
			continue
		}
		binary.BigEndian.PutUint16(ipLowBytes[0:2], ((binary.BigEndian.Uint16(buf[48:50])-BASE_PORT)<<p.shards)+p.shard)
		p.outIcmpChan <- IcmpResp{
			Target: fmt.Sprintf("%d.%d.%d.%d", buf[32], buf[33], ipLowBytes[0], ipLowBytes[1]),
			Real:   fmt.Sprintf("%d.%d.%d.%d", buf[44], buf[45], buf[46], buf[47]),
			Res:    fmt.Sprintf("%d.%d.%d.%d", buf[12], buf[13], buf[14], buf[15]),
			Ttl:    buf[53],
		}
	}
}

func (p *DNSPoolTtl) Finish() {
	p.finish = true
	close(p.inIpChan)
	close(p.inTtlChan)
	close(p.icmpParseChan)
	close(p.outIcmpChan)
}

func (p *DNSPoolTtl) IsFinished() bool {
	return p.finish
}
