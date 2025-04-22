# Introduction

Source IP address spoofing facilitates various malicious attacks, and Outbound Source Address Validation (OSAV) remains the best current practice for preventing spoofed packets from exiting a network. Accurately measuring OSAV deployment is essential for investigating the Internet’s vulnerability to IP spoofing. However, such measurements typically require sending spoofed packets from within the tested network, necessitating cooperation from network operators.

OSAVRoute is the first non-cooperative system capable of capturing the fine-grained characteristics of OSAV deployment. Unlike existing non-cooperative methods that can only identify the ** presence ** and **absence** of OSAV, OSAVRoute identifies both the **presence** and **absence** of OSAV and further measures its **blocking granularity** and **blocking depth**, achieving capabilities previously limited to cooperative methods. OSAVRoute accomplishes this by explicitly tracing the forwarding paths of spoofed packets, enabling identification of their generation and propagation behavior.

# Compilation
OSAVRoute with DNS can be compiled with
```bash
cd osavroute_dns && go build -o osavroute_dns
```
OSAVRoute with TCP can be compiled with
```bash
cd osavroute_tcp && go build -o osavroute_tcp
```
OSAVRoute requires `go1.22+`.

# Usage

## Stateless scanning
For stateless scanning, the common usage is
```bash
osavroute_dns -o <OUTPUT_DIR> -pps <PACKET_PER_SECOND> -nsend <N_SENDERS>
```
In this command, `OUTPUT_DIR` specifies the path to store output files. When scanning is finished, there will be three directors in `OUTPUT_DIR`:

- `OUTPUT_DIR/dns` stores response messages except ICMP Time-Exceeds messages received. Each line in each file is `<ORG_ADDR>,<RESP_ADDR>,<RESP_TYPE>`. `<ORG_ADDR>` is the destination address of the initial probing packet. `<RESP_ADDR>` is the responding address. `<RESP_TYPE>` is the protocol type of the response.

- `OUTPUT_DIR/icmp` stores intermediate files and is usually unimportant.

- `OUTPUT_DIR/icmp-re` stores ICMP Time-Exceeds messages received. Each line in each file is `<ORG_ADDR>,<FD_ADDR>,<RESP_ADDR>,<TTL>`. `<FD_ADDR>` is the destination address when the probing packet's TTL decreases to 0. `<TTL>` is the TTL of the initial probing packet.

`<PACKET_PER_SECOND>` is the sending rate you control. `<N_SENDERS>` is the number of goroutines used for sending packets. Larger `<PACKET_PER_SECOND>` requires larger `<N_SENDERS>`.

If you are using OSAVRoute with TCP, it is totally the same as DNS, except it stores response messages in `OUTPUT_DIR/tcp`.

## Early-filtering scanning
For early-filtering scanning, the common usage is

```bash
osavroute_dns -mode=early -i <INPUT_FILE> -d <DNS_OUT_FILE> -o <ICMP_OUT_FILE>
```

In this command, `<INPUT_FILE>` specifies the input file containing addresses you want to scan. This file is formatted by one address on each line. `<DNS_OUT_FILE>` specifies the path to store DNS responses and is formatted as `<ORG_ADDR>,<RESP_ADDR>,<TTL>` on each line. `<ICMP_OUT_FILE>` specifies the path to store ICMP Time-Exceeds messages and is formatted as `<ORG_ADDR>,<RESP_ADDR>,<TTL>`.

## Blocking granularity scanning
For blocking granularity scanning, the common usage is

```bash
osavroute_dns -mode=gran -i <INPUT_FILE>
```
In this command, `<INPUT_FILE>` specifies the input file containing addresses you want to scan. This file is formatted by one address on each line. 

# Note
1. OSAVRoute can automatically find your network interface and destination MAC address (MAC address of your gateway). However, you can always specify them by:
 ```bash
    osavroute_dns -o <OUTPUT_DIR> -pps <PACKET_PER_SECOND> -nsend <N_SENDERS> -iface <NETWORK_INTERFACE> -dmac <DEST_MAC>
 ```
2. The ADNS is also required when performing early-filtering scanning and blocking granularity scanning. The setup of the ADNS will not be specified here.
3. Early-filtering and blocking granularity scanning is based on DNS, and OSAVRoute with TCP cannot run them.
4. For more details, you can run
 ```bash
    osavroute_dns -h
 ```
 or
 ```bash
    osavroute_tcp -h
 ```