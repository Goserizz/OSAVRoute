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
	LogIntv        = 100000
	BURST          = 10000
	PRIME   uint64 = 4294967311
	IPNUM   uint64 = 4294967296
	BufSize        = 10000
)

func StatelessScan(
	srcIpStr, ifaceName, inFile, outFile, natFile, dnsFile string,
	startTtl, endTtl uint8,
	nSender, pps int,
	srcMac, dstMac []byte,
) {
	file, err := os.Create(outFile)
	if err != nil {
		panic(err)
	} else {
		err := file.Close()
		if err != nil {
			return
		}
	}
	file, err = os.Create(natFile)
	if err != nil {
		panic(err)
	} else {
		err := file.Close()
		if err != nil {
			return
		}
	}
	file, err = os.Create(dnsFile)
	if err != nil {
		panic(err)
	} else {
		err := file.Close()
		if err != nil {
			return
		}
	}
	dstIpStrArray := ReadLineAddr6FromFS(inFile)
	bar := progressbar.Default(int64(len(dstIpStrArray)*int(endTtl-startTtl+1)), "Scanning...")
	var doneIps sync.Map
	var testIps sync.Map
	limiter := rate.NewLimiter(rate.Limit(pps), BURST)

	for _, dstIpStr := range dstIpStrArray {
		testIps.Store(dstIpStr, true)
	}
	counter := 0
	for ttl := startTtl; ttl <= endTtl; ttl++ {
		p := NewDNSPoolSlow(nSender, BufSize, srcIpStr, ifaceName, srcMac, dstMac, ttl)
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
					if _, ok := testIps.Load(icmpRes.Target); !ok {
						continue
					}
					if icmpRes.Target != icmpRes.Real || icmpRes.Target == icmpRes.Res {
						Append1Addr6ToFS(outFile, icmpRes.Target+","+icmpRes.Real+","+icmpRes.Res+","+fmt.Sprintf("%d", ttl))
					}
				}
			}
		}()

		// receive dns
		go func() {
			for {
				targetIp, realIp := p.GetDns()
				if targetIp == "" {
					if finish {
						break
					}
				} else {
					if _, ok := testIps.Load(targetIp); !ok {
						continue
					}
					if targetIp != realIp {
						Append1Addr6ToFS(dnsFile, targetIp+","+realIp+","+fmt.Sprintf("%d", ttl))
						doneIps.Store(targetIp, true)
					}
				}
			}
		}()

		for !finish {
			time.Sleep(time.Second)
		}
		time.Sleep(1 * time.Second)
		p.Finish()
	}
}

func StatelessScanWithForwarder(
	srcMac, dstMac []byte,
	srcIpStr, ifaceName, outDir string,
	startTtl, endTtl uint8,
	pps, nSender int,
	startFileNo, endFileNo, nSeg, shards, shard uint64,
) {
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
	dnsDir := filepath.Join(outDir, "dns")
	if _, err := os.Stat(dnsDir); os.IsNotExist(err) && os.Mkdir(dnsDir, 0755) != nil {
		panic(err)
	}
	icmpDir := filepath.Join(outDir, "icmp")
	if _, err := os.Stat(icmpDir); os.IsNotExist(err) && os.Mkdir(icmpDir, 0755) != nil {
		panic(err)
	}
	icmpReDir := filepath.Join(outDir, "icmp-re")
	if _, err := os.Stat(icmpReDir); os.IsNotExist(err) && os.Mkdir(icmpReDir, 0755) != nil {
		panic(err)
	}

	shardsMask := uint64((1 << shards) - 1)
	limiter := rate.NewLimiter(rate.Limit(pps), BURST)
	limiterRe := rate.NewLimiter(rate.Limit(10000), 100)
	ipDec := uint64(1)
	fileNo := startFileNo
	for i := uint64(0); i < fileNo*nSeg; i++ {
		ipDec = (ipDec * 3) % PRIME
	}
	ipDecStart := ipDec

	nIp := int64(PRIME) - int64(fileNo*nSeg)
	if endFileNo != 0xffffffffffffffff {
		nIp = min(nIp, int64((endFileNo-startFileNo+1)*nSeg))
	}
	bar := progressbar.Default(nIp*int64(endTtl-startTtl+1), "Scanning TTL=50, 0 waiting")
	for seg := startFileNo * nSeg; seg < PRIME; seg += nSeg {
		icmpFile := filepath.Join(icmpDir, fmt.Sprintf("icmp-%d.txt", fileNo))
		icmpReFile := filepath.Join(icmpReDir, fmt.Sprintf("icmp-re-%d.txt", fileNo))
		dnsFile := filepath.Join(dnsDir, fmt.Sprintf("dns-%d.txt", fileNo))
		file, err := os.Create(icmpFile)
		if err != nil {
			panic(err)
		} else {
			err := file.Close()
			if err != nil {
				return
			}
		}
		file, err = os.Create(icmpReFile)
		if err != nil {
			panic(err)
		} else {
			err := file.Close()
			if err != nil {
				return
			}
		}
		file, err = os.Create(dnsFile)
		if err != nil {
			panic(err)
		} else {
			err := file.Close()
			if err != nil {
				return
			}
		}

		// traceroute
		tfSet := make(map[string]bool)
		p := NewDNSPoolTtl(nSender, BufSize, srcIpStr, ifaceName, srcMac, dstMac, uint16(shards), uint16(shard))
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
						nIn, nPar, nOut := p.LenInChan()
						bar.Describe(fmt.Sprintf("Scanning %d-%d TTL=%d, %d in, %d parsing, %d out", seg, seg+nSeg, nowTtl, nIn, nPar, nOut))
					}
					ipDec = (ipDec * 3) % PRIME
					if ipDec == 1 {
						break
					}
					if ipDec >= IPNUM || IsBogon(ipDec) || (ipDec&shardsMask) != shard {
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
			time.Sleep(2 * time.Second)
			finish = true
		}()

		go func() {
			for {
				targetIp, realIp, resIp, ttl := p.GetIcmp()
				if targetIp == "" {
					if p.IsFinished() {
						break
					}
				} else if ttl < nowTtl {
					continue
				} else if targetIp != realIp {
					Append1Addr6ToFS(icmpFile, targetIp+","+realIp+","+resIp+","+fmt.Sprintf("%d", ttl))
					tfSet[targetIp] = true
				} else if tfSet[targetIp] {
					Append1Addr6ToFS(icmpFile, targetIp+","+realIp+","+resIp+","+fmt.Sprintf("%d", ttl))
				}
			}
		}()

		for !finish {
			time.Sleep(time.Second)
		}
		p.Finish()
		ipDecStart = ipDec
		fileNo += 1

		// re-traceroute
		pRe := NewDNSPoolTtl(nSender, BufSize, srcIpStr, ifaceName, srcMac, dstMac, 0, 0)
		finish = false
		go func() {
			for nowTtl = 50; nowTtl >= 2; nowTtl-- {
				for dstIpStr := range tfSet {
					dstIp := net.ParseIP(dstIpStr).To4()
					err := limiterRe.Wait(context.TODO())
					if err != nil {
						panic(err)
					}
					pRe.Add(dstIp, nowTtl)
				}
			}
			time.Sleep(2 * time.Second)
			finish = true
		}()

		go func() {
			for {
				targetIp, realIp, resIp, ttl := pRe.GetIcmp()
				if targetIp == "" {
					if pRe.IsFinished() {
						break
					}
				} else if ttl < nowTtl {
					continue
				} else {
					Append1Addr6ToFS(icmpReFile, targetIp+","+realIp+","+resIp+","+fmt.Sprintf("%d", ttl))
				}
			}
		}()

		for !finish {
			time.Sleep(time.Second)
		}
		pRe.Finish()

		// DNS
		finish = false
		ipStrSet := make(map[string]bool)
		icmpF, err := os.Open(icmpFile)
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

		pSlow := NewDNSPoolSlow(nSender, 10000, srcIpStr, ifaceName, srcMac, dstMac, 99)
		go func() {
			for {
				targetIp, realIp := pSlow.GetDns()
				if targetIp == "" {
					if finish {
						break
					}
				} else {
					Append1Addr6ToFS(dnsFile, targetIp+","+realIp+",DNS")
				}
			}
		}()
		go func() {
			for {
				icmpRes := pSlow.GetIcmp()
				if icmpRes == nil {
					if finish {
						break
					}
				} else {
					Append1Addr6ToFS(dnsFile, icmpRes.Target+","+icmpRes.Res+fmt.Sprintf(",ICMP%d-%d", icmpRes.Type, icmpRes.Code))
				}
			}
		}()
		for i := 0; i < 3; i++ {
			for ipStr := range ipStrSet {
				err := limiter.Wait(context.TODO())
				if err != nil {
					return
				}
				pSlow.Add(net.ParseIP(ipStr).To4())
			}
			time.Sleep(1 * time.Second)
			dnsF, err := os.Open(dnsFile)
			if err != nil {
				panic(err)
			}
			scanner := bufio.NewScanner(dnsF)
			for scanner.Scan() {
				delete(ipStrSet, strings.Split(scanner.Text(), ",")[0])
			}
			err = dnsF.Close()
			if err != nil {
				panic(err)
			}
		}
		finish = true
		pSlow.Finish()

		if fileNo > endFileNo {
			break
		}
	}
}
