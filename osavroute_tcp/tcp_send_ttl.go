package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
	"sync"
)

const (
	BasePort = 50000
)

type IpTtlPair struct {
	Ip []byte
	Ttl uint8
}

type TCPTtlResponse struct {
	Target string
	Real   string
	Port   uint16
	Ttl    uint8
}

type ICMPTtlResponse struct {
	Target string
	Real   string
	Res    string
	Port   uint16
	Ttl    uint8
}

type TCPoolTtl struct {
	inChan        chan IpTtlPair
	outTcpChan    chan TCPTtlResponse
	outIcmpChan   chan ICMPTtlResponse
	icmpParseChan chan []byte
	tcpParseChan  chan []byte
	srcIpStr      string
	remotePort    uint16
	ipv4Cks       uint32
	iface         string
	srcMac        []byte
	dstMac        []byte
	finish        bool
	blockSet      map[string]bool
	wg            sync.WaitGroup
}

func NewTCPoolTtl(remotePort uint16, bufSize int, iface, srcIpStr string, srcMac []byte, dstMac []byte, blockFile string, nSend int) *TCPoolTtl {
	srcIp := net.ParseIP(srcIpStr).To4()
	ipv4Cks := uint32(0)
	ipv4Cks += 0x45 << 8
	ipv4Cks += Ipv4HdrSize + TcpHdrSize
	ipv4Cks += syscall.IPPROTO_TCP
	ipv4Cks += uint32(binary.BigEndian.Uint16(srcIp[0:2]))
	ipv4Cks += uint32(binary.BigEndian.Uint16(srcIp[2:4]))

	blockSet := make(map[string]bool)
	blockF, err := os.Open(blockFile)
	if err != nil {
		panic(err)
	}

	scanner := bufio.NewScanner(blockF)
	for scanner.Scan() {
		blockSet[strings.TrimSpace(scanner.Text())] = true
	}
	err = blockF.Close()
	if err != nil {
		return nil
	}

	p := &TCPoolTtl{
		inChan:        make(chan IpTtlPair, bufSize),
		outTcpChan:    make(chan TCPTtlResponse, bufSize),
		outIcmpChan:   make(chan ICMPTtlResponse, bufSize),
		icmpParseChan: make(chan []byte, bufSize),
		tcpParseChan:  make(chan []byte, bufSize),
		srcIpStr:      srcIpStr,
		remotePort:    remotePort,
		ipv4Cks:       ipv4Cks,
		iface:         iface,
		srcMac:        srcMac,
		dstMac:        dstMac,
		finish:        false,
		blockSet:      blockSet,
		wg:			   sync.WaitGroup{},
	}
	for i := 0; i < nSend; i++ {
		p.wg.Add(2)
		go p.send()
		go p.parseIcmp()
	}
	p.wg.Add(1)
	go p.recvIcmp()
	return p
}

func (p *TCPoolTtl) Add(dstIp []byte, ttl uint8) {
	if p.finish {
		return
	}
	p.inChan <- IpTtlPair{dstIp, ttl}
}

func (p *TCPoolTtl) LenInChan() (int, int, int) {
	return len(p.inChan), len(p.icmpParseChan), len(p.outIcmpChan)
}

func (p *TCPoolTtl) GetIcmp() (string, string, string, uint16, uint8) {
	select {
	case icmpResp, ok := <-p.outIcmpChan:
		if !ok || p.finish {
			return "", "", "", 0, 0
		}
		return icmpResp.Target, icmpResp.Real, icmpResp.Res, icmpResp.Port, icmpResp.Ttl
	case <-time.After(time.Second):
		return "", "", "", 0, 0
	}
}

func (p *TCPoolTtl) GetTcp() (string, string, uint16, uint8) {
	select {
	case tcpResp, ok := <-p.outTcpChan:
		if !ok || p.finish {
			return "", "", 0, 0
		}
		return tcpResp.Target, tcpResp.Real, tcpResp.Port, tcpResp.Ttl
	case <-time.After(time.Second):
		return "", "", 0, 0
	}
}

func (p *TCPoolTtl) calCks(dstIp []byte, ttl uint8) uint16 {
	ipv4Cks := p.ipv4Cks
	ipv4Cks += uint32(binary.BigEndian.Uint16(dstIp[0:2]))
	ipv4Cks += uint32(binary.BigEndian.Uint16(dstIp[2:4]))
	ipv4Cks += uint32(ttl) << 8
	return ^uint16((ipv4Cks >> 16) + (ipv4Cks & 0xffff))
}

func (p *TCPoolTtl) send() {
	defer p.wg.Done()
	// 创建原始套接字
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_IP)
	if err != nil {
		log.Fatalf("Socket error: %v\n", err)
	}
	defer func(fd int) {
		err := syscall.Close(fd)
		if err != nil {
			panic(err)
		}
	}(fd)

	// construct MAC header
	macHdr := make([]byte, MacHdrSize)
	copy(macHdr[0:6], p.dstMac)
	copy(macHdr[6:12], p.srcMac)
	binary.BigEndian.PutUint16(macHdr[12:14], syscall.ETH_P_IP)

	// Get Interface Info
	iface, err := net.InterfaceByName(p.iface)
	if err != nil {
		log.Fatalf("Interface error: %v\n", err)
	}
	bindAddr := &syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_IP,
		Ifindex:  iface.Index,
	}

	// IP Header
	srcIp := net.ParseIP(p.srcIpStr)
	ipv4Hdr := make([]byte, Ipv4HdrSize)
	ipv4Hdr[0] = 0x45 // Version = 4 | header length = 5
	// [1]	 TOS
	// [2] [3] Total length
	binary.BigEndian.PutUint16(ipv4Hdr[2:4], Ipv4HdrSize+TcpHdrSize)
	// [4] [5] Identification
	// [6] [7] Flags | Fragment offset
	// [8] TTL
	ipv4Hdr[9] = syscall.IPPROTO_TCP // Protocol = 6 (TCP)
	// [10 - 11] Header Checksum
	copy(ipv4Hdr[12:16], srcIp.To4()) // Source address
	// [16 - 20] Destination address

	// TCP Header
	tcpHdr := make([]byte, TcpHdrSize)
	binary.BigEndian.PutUint16(tcpHdr[0:2], 0)            // local port
	binary.BigEndian.PutUint16(tcpHdr[2:4], p.remotePort) // remote port
	// [4 -  8] Seq Num
	// [8 - 12] Ack Num
	tcpHdr[12] = DataOffset << 4                          // [12] DataOffset (4 bits) | RSV (3 bits)
	tcpHdr[13] = SynFlag                                  // [13] SYN flag
	binary.BigEndian.PutUint16(tcpHdr[14:16], WindowSize) // [14 - 16] Window Size
	// [16 - 18] Checksum
	// [18 - 20] Urgent Point
	// [20 - 24] option: MSS = 1460
	copy(tcpHdr[20:24], TcpMss)

	pkt := append(macHdr, ipv4Hdr...)
	pkt = append(pkt, tcpHdr...)

	var dstIp []byte
	var ok bool
	var ttl uint8
	var ipTtlPair IpTtlPair
	for {
		select {
		case ipTtlPair, ok = <-p.inChan:
			dstIp = ipTtlPair.Ip
			ttl = ipTtlPair.Ttl
		case <-time.After(time.Second):
		}
		if !ok || p.finish {
			break
		}
		ipv4Cks := p.calCks(dstIp, ttl)

		// Complete IP Header
		pkt[22] = ttl
		copy(pkt[30:34], dstIp)
		binary.BigEndian.PutUint16(pkt[24:26], ipv4Cks)

		// Complete TCP Header
		// binary.BigEndian.PutUint16(pkt[34:36], BasePort+uint16(ttl)) // encode ttl in Src Port
		// copy(pkt[38:42], dstIp)                                      // encode dstIp in Seq Num
		copy(pkt[34:36], dstIp[0:2])  // encode high 16 bits of dstIp in Src Port
		copy(pkt[38:40], dstIp[2:4])  // encode low 16 bits of dstIp in high 16 bits of Seq Num
		binary.BigEndian.PutUint16(pkt[40:42], uint16(ttl))  // encode ttl in low 16 bits of Seq Num

		// Send the Packet
		for {
			if err := syscall.Sendto(fd, pkt, 0, bindAddr); err == nil {
				break
			} else {
				log.Println(err)
			}
		}
	}
}

// func (p *TCPoolTtl) recvTcp() {
// 	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.ETH_P_IP)
// 	if err != nil {
// 		log.Fatalf("Socket error: %v\n", err)
// 	}
// 	defer func(fd int) {
// 		err := syscall.Close(fd)
// 		if err != nil {
// 			panic(err)
// 		}
// 	}(fd)

// 	for {
// 		buf := make([]byte, 54)
// 		_, _, err := syscall.Recvfrom(fd, buf, 0)
// 		if p.finish {
// 			break
// 		}
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 		p.tcpParseChan <- buf
// 	}
// }

// func (p *TCPoolTtl) parseTcp() {
// 	for {
// 		buf, ok := <-p.tcpParseChan
// 		if !ok || p.finish {
// 			break
// 		}
// 		// localPort := binary.BigEndian.Uint16(buf[36:38])
// 		remotePort := binary.BigEndian.Uint16(buf[34:36])
// 		flag := buf[47]
// 		if flag != (SynFlag | AckFlag) {
// 			continue
// 		}
// 		realIpStr := fmt.Sprintf("%d.%d.%d.%d", buf[26], buf[27], buf[28], buf[29])
// 		// ackNum := binary.BigEndian.Uint32(buf[42:46])
// 		// targetIpBytes := make([]byte, 4)
// 		// binary.BigEndian.PutUint32(targetIpBytes, ackNum-1)
// 		// targetIpStr := fmt.Sprintf("%d.%d.%d.%d", targetIpBytes[0], targetIpBytes[1], targetIpBytes[2], targetIpBytes[3])
// 		targetIpStr := fmt.Sprintf("%d.%d.%d.%d", buf[36], buf[37], buf[42], buf[43])
// 		ttl := uint8(binary.BigEndian.Uint16(buf[44:46]) - 1)
// 		p.outTcpChan <- TCPTtlResponse{
// 			Target: targetIpStr,
// 			Real:   realIpStr,
// 			Port:   remotePort,
// 			Ttl:    ttl,
// 		}
// 	}
// }

func (p *TCPoolTtl) recvIcmp() {
	defer p.wg.Done()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		log.Fatalf("Socket error: %v\n", err)
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

	for {
		buf := make([]byte, 1500)
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if n < 56 {
			continue
		}
		if err != nil {
			log.Fatalln(err)
		}
		if p.finish { break }
		p.icmpParseChan <- buf
	}
}

func (p *TCPoolTtl) parseIcmp() {
	defer p.wg.Done()
	for {
		var buf []byte
		ok := false
		select {
		case buf, ok = <-p.icmpParseChan:
		case <-time.After(time.Second):
		}
		if !ok || p.finish {
			break
		}

		resIpStr := fmt.Sprintf("%d.%d.%d.%d", buf[12], buf[13], buf[14], buf[15])
		if _, ok := p.blockSet[resIpStr]; ok {
			continue
		}

		if buf[31] != Ipv4HdrSize+TcpHdrSize || buf[37] != syscall.IPPROTO_TCP || buf[20] != 11 || buf[21] != 0 {
			continue
		}
		remotePort := binary.BigEndian.Uint16(buf[50:52]) 
		targetIpStr := fmt.Sprintf("%d.%d.%d.%d", buf[48], buf[49], buf[52], buf[53])
		realIpStr := fmt.Sprintf("%d.%d.%d.%d", buf[44], buf[45], buf[46], buf[47])
		ttl := uint8(binary.BigEndian.Uint16(buf[54:56]))
		// fmt.Println(targetIpStr, realIpStr, resIpStr, remotePort, ttl)
		p.outIcmpChan <- ICMPTtlResponse{
			Target: targetIpStr,
			Real:   realIpStr,
			Res:    resIpStr,
			Port:   remotePort,
			Ttl:    ttl,
		}
	}
}

func (p *TCPoolTtl) Finish() {
	p.finish = true
	p.wg.Wait()
	close(p.inChan)
	close(p.outTcpChan)
	close(p.outIcmpChan)
	close(p.icmpParseChan)
	close(p.tcpParseChan)
}

func (p *TCPoolTtl) IsFinish() bool {
	return p.finish
}
