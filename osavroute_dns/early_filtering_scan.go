package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"
)

func EealyFilteringScan(
	srcIpStr string,
	ifaceName string,
	inputFile string,
	outputFile string,
	dnsFile string,
	randPfx string,
	domain string,
	startTtl uint8,
	endTtl uint8,
	pps int,
	srcMac []byte,
	dstMac []byte,
) {
	os.Remove(outputFile)
	os.Remove(dnsFile)
	dstIpStrArr := ReadLineAddr6FromFS(inputFile)
	limiter := rate.NewLimiter(rate.Limit(pps), pps)

	finish := false
	fmt.Println("Random Prefix:", randPfx)
	fmt.Println("Press Enter to continue...")
	pNormal := NewDNSPoolNormal(srcIpStr, ifaceName, randPfx, domain, srcMac, dstMac)
	pSpoof := NewDNSPoolSpoof(srcIpStr, ifaceName, randPfx, domain, srcMac, dstMac)
	pSpoofSame := NewDNSPoolSpoofSame(srcIpStr, ifaceName, randPfx, domain, srcMac, dstMac)
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
