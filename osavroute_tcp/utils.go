package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/vishvananda/netlink"
)

func ReadLineAddr6FromFS(filename string) []string {
	var strAddrs []string
	f, err := os.Open(filename)
	if err != nil {
		panic("Open file error.")
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			panic(err)
		}
	}(f)

	br := bufio.NewReader(f)
	for {
		lineBytes, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}
		strAddrs = append(strAddrs, string(lineBytes))
	}
	return strAddrs
}

func AddrToFs(filename string, strAddr string) {
	if filename == "" {
		return
	}
	if _, err := os.Stat(filename); err != nil {
		_, err := os.Create(filename)
		if err != nil {
			panic(err)
		}
	}
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0777)
	if err != nil {
		panic("Open file error.")
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			panic(err)
		}
	}(f)

	strWriting := strAddr + "\n"
	if n, err := f.WriteString(strWriting); err != nil || n != len(strWriting) {
		fmt.Println(err, n, len(strWriting))
	}
}

func GetDefaultRouteInterface() (string, error) {
	// 获取路由表
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return "", err
	}

	for _, route := range routes {
		// 检查是否为默认路由 (0.0.0.0/0 或 ::/0)
		if route.Dst == nil {
			// 获取与默认路由关联的网卡
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				return "", err
			}
			return link.Attrs().Name, nil
		}
	}

	return "", errors.New("default route not found")
}

func GetIface(interfaceName string) ([]string, []string, []byte, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, nil, nil, err
	}

	var ipv4Addrs []string
	var ipv6Addrs []string

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, nil, err
	}

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipv4 := ipnet.IP.To4(); ipv4 != nil {
			ipv4Addrs = append(ipv4Addrs, ipv4.String())
		} else if ipv6 := ipnet.IP.To16(); ipv6 != nil {
			ipv6Addrs = append(ipv6Addrs, ipv6.String())
		}
	}

	return ipv4Addrs, ipv6Addrs, iface.HardwareAddr, nil
}

func IsBogon(decIp uint64) bool {
	if ((decIp & 0xFF000000) == 0x00000000) || // 0.0.0.0/8
		((decIp & 0xFF000000) == 0x0A000000) || // 10.0.0.0/8
		((decIp & 0xFFC00000) == 0x64400000) || // 100.64.0.0/10
		((decIp & 0xFF000000) == 0x7F000000) || // 127.0.0.0/8
		((decIp & 0xFFFF0000) == 0xA9FE0000) || // 169.254.0.0/16
		((decIp & 0xFFF00000) == 0xAC100000) || // 172.16.0.0/12
		((decIp & 0xFFFFFF00) == 0xC0000000) || // 192.0.0.0/24
		((decIp & 0xFFFFFF00) == 0xC0000200) || // 192.0.2.0/24
		((decIp & 0xFFFF0000) == 0xC0A80000) || // 192.168.0.0/16
		((decIp & 0xFFFE0000) == 0xC6120000) || // 198.18.0.0/15
		((decIp & 0xFFFFFF00) == 0xC6336400) || // 198.51.100.0/24
		((decIp & 0xFFFFFF00) == 0xCB007100) || // 203.0.113.0/24
		((decIp & 0xF0000000) == 0xE0000000) || // 224.0.0.0/4
		((decIp & 0xF0000000) == 0xF0000000) {
		return true
	} else {
		return false
	} // 240.0.0.0/4
}

// GetDefaultGateway 获取默认网关的IP地址
func GetDefaultGateway() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	route := strings.Fields(out.String())
	if len(route) < 3 {
		return "", fmt.Errorf("unexpected output: %s", out.String())
	}
	return route[2], nil
}

// GetMACAddress 获取MAC地址
func GetMACAddress(ip string) (string, error) {
	cmd := exec.Command("arp", "-n", ip)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	lines := strings.Split(out.String(), "\n")
	if len(lines) < 2 {
		return "", fmt.Errorf("unexpected output: %s", out.String())
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 3 {
		return "", fmt.Errorf("unexpected output: %s", lines[1])
	}
	return fields[2], nil
}
