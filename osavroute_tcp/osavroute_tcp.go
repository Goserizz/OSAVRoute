package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

const (
	LocalPort        = 37300
	BufSize          = 100000
	BURST            = 10000
	PRIME     uint64 = 4294967311
	IPNUM     uint64 = 4294967296
	LogIntv          = 10000
)

func TCPRouteScan(srcIpStr, iface, inputFile, outputFile string, startTtl, endTtl uint8, pps int, srcMac, dstMac []byte, remotePort uint16) {
	err := os.Remove(outputFile)
	if err != nil {
		return
	}
	dstIpStrArray := ReadLineAddr6FromFS(inputFile)
	bar := progressbar.Default(int64(len(dstIpStrArray)*int(endTtl-startTtl+1)), "Scanning...")
	var doneIps sync.Map
	var testIps sync.Map
	limiter := rate.NewLimiter(rate.Limit(pps), BURST)

	for _, dstIpStr := range dstIpStrArray {
		testIps.Store(dstIpStr, true)
	}
	counter := 0
	tfSet := make(map[string]bool)
	for ttl := endTtl; ttl >= startTtl; ttl-- {
		p := NewTCPoolv4(remotePort, BufSize, LocalPort, iface, srcIpStr, srcMac, dstMac, ttl)
		bar.Describe(fmt.Sprintf("Scanning TTL=%d...", ttl))
		finish := false

		// send
		go func() {
			for _, dstIpStr := range dstIpStrArray {
				counter += 1
				if counter%LogIntv == 0 {
					err := bar.Add(LogIntv)
					if err != nil {
						panic(err)
					}
				}
				_, ok := doneIps.Load(dstIpStr)
				if ok {
					continue
				}
				err := limiter.Wait(context.TODO())
				if err != nil {
					panic(err)
				}
				p.Add(net.ParseIP(dstIpStr).To4())
			}
			time.Sleep(10 * time.Second)
			finish = true
		}()

		// receive icmp
		go func() {
			for {
				icmpRes := p.GetIcmp()
				if icmpRes == nil {
					if finish {
						break
					}
				} else {
					if icmpRes.Type != 11 {
						continue
					}
					if _, ok := testIps.Load(icmpRes.Target); !ok {
						continue
					}
					if icmpRes.Target != icmpRes.Real {
						AddrToFs(outputFile, icmpRes.Target+","+icmpRes.Real+","+icmpRes.Res)
						tfSet[icmpRes.Target] = true
					} else if tfSet[icmpRes.Target] {
						AddrToFs(outputFile, icmpRes.Target+","+icmpRes.Real+","+icmpRes.Res)
					}
				}
			}
		}()

		// receive tcp
		go func() {
			for {
				targetIp, realIp, _ := p.GetTcp()
				if targetIp == "" {
					if finish {
						break
					}
				} else {
					if _, ok := testIps.Load(targetIp); !ok {
						continue
					}
					if targetIp != realIp {
						doneIps.Store(targetIp, true)
					}
				}
			}
		}()

		for !finish {
			time.Sleep(time.Second)
		}
		p.Finish()
	}
}

func TCPRouteScanWithForwarder(srcIpStr, iface, outDir, blockFile string, startTtl, endTtl uint8, pps, nsend int, startFileNo, endFileNo, nSeg uint64, srcMac, dstMac []byte, remotePort uint16) {
	if startFileNo == 0xffffffffffffffff {
		if _, err := os.Stat(outDir); !os.IsNotExist(err) {
			fmt.Printf("Your are about to delete %s, are you sure?[y/n]", outDir)
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				response := scanner.Text()
				if strings.ToLower(response) == "y" {
					err := os.RemoveAll(outDir)
					if err != nil {
						panic(err)
					}
				} else {
					os.Exit(0)
				}
			}
		}
		err := os.Mkdir(outDir, 0755)
		if err != nil {
			panic(err)
		}
		startFileNo = 0
	}
	tcpDir := filepath.Join(outDir, "tcp")
	if _, err := os.Stat(tcpDir); os.IsNotExist(err) {
		err := os.Mkdir(tcpDir, 0755)
		if err != nil {
			panic(err)
		}
	}
	icmpDir := filepath.Join(outDir, "icmp")
	if _, err := os.Stat(icmpDir); os.IsNotExist(err) {
		err := os.Mkdir(icmpDir, 0755)
		if err != nil {
			panic(err)
		}
	}
	icmpReDir := filepath.Join(outDir, "icmp-re")
	if _, err := os.Stat(icmpReDir); os.IsNotExist(err) {
		err := os.Mkdir(icmpReDir, 0755)
		if err != nil {
			panic(err)
		}
	}

	limiter := rate.NewLimiter(rate.Limit(pps), BURST)
	limiterRe := rate.NewLimiter(rate.Limit(10000), 100)
	ipDec := uint64(1)
	fileNo := startFileNo
	for i := uint64(0); i < fileNo*nSeg; i++ {
		ipDec = (ipDec * 3) % PRIME
	}
	ipDecStart := ipDec

	nIp := int64(PRIME) - int64(startFileNo*nSeg)
	if endFileNo != 0xffffffffffffffff {
		nIp = min(nIp, int64((endFileNo-startFileNo+1)*nSeg))
	}
	bar := progressbar.Default(nIp*int64(endTtl-startTtl+1), "Scanning TTL=50, 0 waiting...")
	for seg := startFileNo * nSeg; seg < PRIME; seg += nSeg {
		icmpFile := filepath.Join(icmpDir, fmt.Sprintf("icmp-%d.txt", fileNo))
		tcpFile := filepath.Join(tcpDir, fmt.Sprintf("tcp-%d.txt", fileNo))
		icmpReFile := filepath.Join(icmpReDir, fmt.Sprintf("icmp-re-%d.txt", fileNo))
		file, err := os.Create(icmpFile)
		if err != nil {
			panic(err)
		} else {
			err := file.Close()
			if err != nil {
				panic(err)
			}
		}
		file, err = os.Create(tcpFile)
		if err != nil {
			panic(err)
		} else {
			err := file.Close()
			if err != nil {
				panic(err)
			}
		}
		file, err = os.Create(icmpReFile)
		if err != nil {
			panic(err)
		} else {
			err := file.Close()
			if err != nil {
				panic(err)
			}
		}
		// traceroute
		tfSet := make(map[string]bool)
		p := NewTCPoolTtl(remotePort, BufSize, iface, srcIpStr, srcMac, dstMac, blockFile, nsend)
		finish := false
		nowTtl := endTtl
		go func() {
			for nowTtl = endTtl; nowTtl >= startTtl; nowTtl-- {
				ipDec = ipDecStart
				for i := uint64(0); i < nSeg; i++ {
					if (i+1)%LogIntv == 0 {
						err := bar.Add(LogIntv)
						if err != nil {
							panic(err)
						}
						nIn, nIcmpParse, nIcmpOut := p.LenInChan()
						bar.Describe(fmt.Sprintf("Scanning %d-%d TTL=%d, %d in, %d parsing, %d out", seg, seg+nSeg, nowTtl, nIn, nIcmpParse, nIcmpOut))
					}
					ipDec = (ipDec * 3) % PRIME
					if ipDec == 1 { // All IPs are scanned
						break
					}
					if ipDec >= IPNUM || IsBogon(ipDec) {
						continue
					}
					dstIp := make([]byte, 4)
					binary.BigEndian.PutUint32(dstIp, uint32(ipDec))
					err := limiter.Wait(context.TODO())
					if err != nil {
						panic(err)
					}
					p.Add(dstIp, nowTtl)
				}
			}
			finish = true
		}()

		go func() {
			for {
				targetIp, realIp, resIp, _, ttl := p.GetIcmp()
				if targetIp == "" {
					if p.IsFinish() {
						break
					}
				} else if ttl < nowTtl || ttl > endTtl {
					continue
				} else if targetIp != realIp {
					AddrToFs(icmpFile, targetIp+","+realIp+","+resIp+","+fmt.Sprintf("%d", ttl))
					tfSet[targetIp] = true
				} else if tfSet[targetIp] {
					AddrToFs(icmpFile, targetIp+","+realIp+","+resIp+","+fmt.Sprintf("%d", ttl))
				}
			}
		}()

		for !finish {
			time.Sleep(time.Second)
		}
		time.Sleep(2 * time.Second)
		p.Finish()

		// re-traceroute
		finish = false
		ipDec = ipDecStart
		trueTfSet := make(map[string]bool)
		for i := uint64(0); i < nSeg; i++ {
			ipDec = (ipDec * 3) % PRIME
			if ipDec >= IPNUM || IsBogon(ipDec) {
				continue
			}
			dstIp := make([]byte, 4)
			binary.BigEndian.PutUint32(dstIp, uint32(ipDec))
			dstIpStr := net.IP(dstIp).String()
			if _, ok := tfSet[dstIpStr]; ok {
				trueTfSet[dstIpStr] = true
			}
		}

		rePool := NewTCPoolTtl(remotePort, BufSize, iface, srcIpStr, srcMac, dstMac, blockFile, 1)
		go func() {
			for nowTtl = 50; nowTtl >= 2; nowTtl-- {
				for dstIpStr := range trueTfSet {
					err := limiterRe.Wait(context.TODO())
					if err != nil {
						panic(err)
					}
					rePool.Add(net.ParseIP(dstIpStr).To4(), nowTtl)
				}
			}
			finish = true
		}()

		go func() { // recv
			for {
				targetIp, realIp, resIp, _, ttl := rePool.GetIcmp()
				if targetIp == "" {
					if rePool.IsFinish() {
						break
					}
				} else if ttl < nowTtl || ttl > endTtl {
					continue
				} else if _, ok := trueTfSet[targetIp]; ok {
					AddrToFs(icmpReFile, targetIp+","+realIp+","+resIp+","+fmt.Sprintf("%d", ttl))
				}
			}
		}()

		for !finish {
			time.Sleep(time.Second)  // Wait for sending over
		}
		time.Sleep(2 * time.Second)  // Wait for final responses
		rePool.Finish()

		ipDecStart = ipDec
		fileNo += 1

		// TCP
		finish = false
		ipStrSet := make(map[string]bool)
		icmpF, err := os.Open(icmpReFile)
		if err != nil {
			panic(err)
		}
		scanner := bufio.NewScanner(icmpF)
		for scanner.Scan() {
			ipStrSet[strings.Split(scanner.Text(), ",")[0]] = true
			ipStrSet[strings.Split(scanner.Text(), ",")[1]] = true
		}
		err = icmpF.Close()
		if err != nil {
			panic(err)
		}

		tcpPool := NewTCPoolv4(remotePort, BufSize, LocalPort, iface, srcIpStr, srcMac, dstMac, 99)
		go func() {
			for {
				targetIp, realIp, _ := tcpPool.GetTcp()
				if targetIp == "" {
					if tcpPool.IsFinish() {
						break
					}
				} else {
					AddrToFs(tcpFile, targetIp+","+realIp+",TCP")
				}
			}
		}()
		go func() {
			for {
				icmpRes := tcpPool.GetIcmp()
				if icmpRes == nil {
					if tcpPool.IsFinish() {
						break
					}
				} else {
					AddrToFs(tcpFile, icmpRes.Target+","+icmpRes.Res+fmt.Sprintf(",ICMP%d-%d", icmpRes.Type, icmpRes.Code))
				}
			}
		}()
		for i := 0; i < 3; i++ {
			for ipStr := range ipStrSet {
				err := limiterRe.Wait(context.TODO())
				if err != nil {
					panic(err)
				}
				tcpPool.Add(net.ParseIP(ipStr).To4())
			}
			time.Sleep(5 * time.Second)
			tcpF, err := os.Open(tcpFile)
			if err != nil {
				panic(err)
			}
			scanner := bufio.NewScanner(tcpF)
			for scanner.Scan() {
				delete(ipStrSet, strings.Split(scanner.Text(), ",")[0])
			}
			err = tcpF.Close()
			if err != nil {
				panic(err)
			}
		}
		tcpPool.Finish()
		finish = true

		if fileNo > endFileNo {
			break
		}
	}
}
