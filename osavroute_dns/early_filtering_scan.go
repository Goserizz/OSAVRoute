package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

func EealyFilteringScan(srcIpStr, ifaceName, inputFile, outputFile, dnsFile, randPfx string, startTtl, endTtl uint8, pps int, srcMac, dstMac []byte) {
	os.Remove(outputFile)
	os.Remove(dnsFile)
	dstIpStrArr := ReadLineAddr6FromFS(inputFile)
	limiter := rate.NewLimiter(rate.Limit(pps), pps)

	finish := false
	fmt.Println("Random Prefix:", randPfx)
	fmt.Println("Press Enter to continue...")
	pNormal := NewDNSPoolNormal(srcIpStr, ifaceName, srcMac, dstMac, randPfx)
	pSpoof := NewDNSPoolSpoof(srcIpStr, ifaceName, srcMac, dstMac, randPfx)
	pSpoofSame := NewDNSPoolSpoofSame(srcIpStr, ifaceName, srcMac, dstMac, randPfx)
	go func() {
		for {
			targetIp, res, ttl := pNormal.GetIcmp()
			if targetIp != "" {
				Append1Addr6ToFS(outputFile, fmt.Sprintf("%s,%s,%d", targetIp, res, ttl))
			} else if finish {
				break
			}
		}
	}()
	go func() {
		for {
			targetIp, res, ttl := pNormal.GetDns()
			if targetIp != "" {
				Append1Addr6ToFS(dnsFile, fmt.Sprintf("%s,%s,%d", targetIp, res, ttl))
			} else if finish {
				break
			}
		}
	}()

	bar := progressbar.Default(int64(len(dstIpStrArr))*int64(endTtl-startTtl+1)*3, "Scanning Normal...")
	for ttl := startTtl; ttl <= endTtl; ttl++ {
		for i, dstIpStr := range dstIpStrArr {
			if (i+1)%LOG_INTV == 0 {
				bar.Add(LOG_INTV)
				bar.Describe(fmt.Sprintf("Scanning Normal TTL=%d", ttl))
			}
			dstIp := net.ParseIP(dstIpStr).To4()
			pNormal.Add(dstIp, ttl)
			limiter.Wait(context.TODO())
		}
	}
	time.Sleep(10 * time.Second)
	finish = true

	for ttl := startTtl; ttl <= endTtl; ttl++ {
		for i, dstIpStr := range dstIpStrArr {
			if (i+1)%LOG_INTV == 0 {
				bar.Add(LOG_INTV)
				bar.Describe(fmt.Sprintf("Scanning Spoof TTL=%d", ttl))
			}
			dstIp := net.ParseIP(dstIpStr).To4()
			pSpoof.Add(dstIp, ttl)
			limiter.Wait(context.TODO())
		}
	}

	for ttl := startTtl; ttl <= endTtl; ttl++ {
		for i, dstIpStr := range dstIpStrArr {
			if (i+1)%LOG_INTV == 0 {
				bar.Add(LOG_INTV)
				bar.Describe(fmt.Sprintf("Scanning Spoof TTL=%d", ttl))
			}
			dstIp := net.ParseIP(dstIpStr).To4()
			pSpoofSame.Add(dstIp, ttl)
		}
	}
	bar.Finish()
	time.Sleep(10 * time.Second)
}

func BlockingGranScan(ifaceName, inputFile, randPfx string, pps int, srcMac, dstMac []byte) {
	file, err := os.Open(inputFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var ips []string

	for scanner.Scan() {
		line := scanner.Text()
		ips = append(ips, strings.Split(line, ",")[0])
	}

	fmt.Println("Random Prefix:", randPfx)
	fmt.Println("Press Enter to continue...")
	spoofSender := NewDNSPoolSpoofAny(ifaceName, srcMac, dstMac, randPfx)
	limiter := rate.NewLimiter(rate.Limit(pps), pps)
	bar := progressbar.Default(int64(len(ips)*25), "Scanning Spoof Range...")
	for _range := uint8(31); _range > 7; _range-- {
		for i, ip := range ips {
			if (i+1)%100 == 0 {
				bar.Add(100)
			}
			limiter.Wait(context.Background())
			dstIp := net.ParseIP(ip).To4()
			dstIpUint32 := binary.BigEndian.Uint32(dstIp)
			srcIpUint32 := dstIpUint32 ^ (1 << (31 - _range))
			srcIp := make([]byte, 4)
			binary.BigEndian.PutUint32(srcIp, srcIpUint32)
			spoofSender.Add(srcIp, dstIp, _range)
		}
	}
	time.Sleep(10 * time.Second)
}
