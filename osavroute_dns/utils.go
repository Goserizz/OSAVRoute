package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
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
	defer f.Close()

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

func Append1Addr6ToFS(filename string, strAddr string) {
	if filename == "" {
		return
	}
	if _, err := os.Stat(filename); err != nil {
		os.Create(filename)
	}
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0777)
	if err != nil {
		panic("Open file error.")
	}
	defer f.Close()

	strWriting := strAddr + "\n"
	if n, err := f.WriteString(strWriting); err != nil || n != len(strWriting) {
		fmt.Println(err, n, len(strWriting))
	}
}

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

func ParseDNSQuestion(buffer []byte, offset int) (DNSQuestion, int) {
	// 读取question的name字段
	name, bytesRead := readName(buffer, offset)
	offset += bytesRead

	// 读取question的type和class字段
	questionType := binary.BigEndian.Uint16(buffer[offset : offset+2])
	questionClass := binary.BigEndian.Uint16(buffer[offset+2 : offset+4])
	offset += 4

	// 创建DNSQuestion对象
	question := DNSQuestion{
		Name:  name,
		Type:  questionType,
		Class: questionClass,
	}

	return question, offset
}

func readName(buffer []byte, offset int) (string, int) {
	var name string
	var bytesRead int

	// DNS报文中的name字段以长度+字符串的形式表示
	// 0xC0表示name字段中的某一部分是一个偏移量，需要跳转到该位置读取
	// 具体参考DNS报文的编码规范

	// 循环读取name字段的各个部分
	for {
		if offset > len(buffer) {
			break
		}
		// 读取长度
		length := int(buffer[offset])
		offset++
		bytesRead++

		if length == 0 {
			// 结束条件是遇到长度为0的部分表示name字段结束
			break
		}

		if length >= 0xC0 {
			// 遇到偏移量，需要跳转到偏移量指向的位置继续读取
			nextOffset := int(binary.BigEndian.Uint16([]byte{buffer[offset-1], buffer[offset]})) & 0x3FFF
			if nextOffset <= offset {
				break
			}
			part, _ := readName(buffer, nextOffset)
			name += part
			bytesRead++
			break
		}

		// 读取字符串部分
		name += string(buffer[offset : offset+length])
		offset += length
		bytesRead += length
		name += "."

	}

	return name, bytesRead
}

func CalCksum(data []byte) uint16 {
	var (
		sum    uint32
		length = len(data)
		index  int
	)

	//以每16比特（2字节）为单位进行求和
	for length > 1 {
		sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
		index += 2
		length -= 2
	}

	//如果长度为奇数，将最后剩下的8比特（1字节）看作16比特的高8位进行求和
	if length > 0 {
		sum += uint32(data[index]) << 8
	}

	//至此，sum可能超过了16比特可以表示的最大范围，因此需要将高16位与低16位相加
	sum += (sum >> 16)

	//返回求和的补码，这就是UDP校验和
	return uint16(^sum)
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

func SplitIPStr(ipStr string) []string {
	if ipStr[len(ipStr)-1] == ':' {
		ipStr = ipStr[:len(ipStr)-1]
	}
	ipSeg := strings.Split(ipStr, ":")
	var ipFullSeg []string
	for i := 0; i < len(ipSeg); i++ {
		seg := ipSeg[i]
		if seg == "" {
			nIgnore := 9 - len(ipSeg)
			for j := 0; j < nIgnore; j++ {
				ipFullSeg = append(ipFullSeg, "0000")
			}
			continue
		}
		nZero := 4 - len(seg)
		for i := 0; i < nZero; i++ {
			seg = "0" + seg
		}
		ipFullSeg = append(ipFullSeg, seg)
	}
	return ipFullSeg
}

func GetFullIP(ipStr string) string {
	ipFullSeg := SplitIPStr(ipStr)
	return strings.Join(ipFullSeg, ":")
}

func FormatIpv4(ipv4 string) string {
	var formatParts []string
	for _, part := range strings.Split(ipv4, ".") {
		for len(part) < 3 {
			part = "0" + part
		}
		formatParts = append(formatParts, part)
	}
	return strings.Join(formatParts, ":")
}

func DeformatIpv4(ipv4 string) string {
	var deformatParts []string
	for _, part := range strings.Split(ipv4, ":") {
		for part[0] == '0' && len(part) > 1 {
			part = part[1:]
		}
		deformatParts = append(deformatParts, part)
	}
	return strings.Join(deformatParts, ".")
}

func IsBogon(dec_ip uint64) bool {
	if ((dec_ip & 0xFF000000) == 0x00000000) || // 0.0.0.0/8
		((dec_ip & 0xFF000000) == 0x0A000000) || // 10.0.0.0/8
		((dec_ip & 0xFFC00000) == 0x64400000) || // 100.64.0.0/10
		((dec_ip & 0xFF000000) == 0x7F000000) || // 127.0.0.0/8
		((dec_ip & 0xFFFF0000) == 0xA9FE0000) || // 169.254.0.0/16
		((dec_ip & 0xFFF00000) == 0xAC100000) || // 172.16.0.0/12
		((dec_ip & 0xFFFFFF00) == 0xC0000000) || // 192.0.0.0/24
		((dec_ip & 0xFFFFFF00) == 0xC0000200) || // 192.0.2.0/24
		((dec_ip & 0xFFFF0000) == 0xC0A80000) || // 192.168.0.0/16
		((dec_ip & 0xFFFE0000) == 0xC6120000) || // 198.18.0.0/15
		((dec_ip & 0xFFFFFF00) == 0xC6336400) || // 198.51.100.0/24
		((dec_ip & 0xFFFFFF00) == 0xCB007100) || // 203.0.113.0/24
		((dec_ip & 0xF0000000) == 0xE0000000) || // 224.0.0.0/4
		((dec_ip & 0xF0000000) == 0xF0000000) {
		return true
	} else {
		return false
	} // 240.0.0.0/4
}

// 获取默认网关的IP地址
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

// 获取MAC地址
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

func ipToHex(ip []byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x", ip[0], ip[1], ip[2], ip[3])
}

func hexToIp(hexStr string) (string, error) {
	ip, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}
	if len(ip) < 4 {
		return "", errors.New("invalid IP length")
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]), nil
}

func GetDomainRandPfx(randLen int) string {
	randSuffixBytes := make([]byte, randLen)
	for i := range randSuffixBytes {
		randSuffixBytes[i] = CHARS[rand.Intn(len(CHARS))]
	}
	return string(randSuffixBytes)
}

func GetDomainRandNumPfx(randLen int) string {
	randSuffixBytes := make([]byte, randLen)
	for i := range randSuffixBytes {
		randSuffixBytes[i] = CHARS_NUM[rand.Intn(len(CHARS_NUM))]
	}
	return string(randSuffixBytes)
}
