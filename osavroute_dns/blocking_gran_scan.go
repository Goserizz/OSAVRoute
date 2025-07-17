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

func BlockingGranScan(
	ifaceName string,
	inputFile string,
	randPfx string,
	domain string,
	pps int,
	srcMac []byte,
	dstMac []byte,
) {
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
	spoofSender := NewDNSPoolSpoofAny(ifaceName, randPfx, domain, srcMac, dstMac)
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