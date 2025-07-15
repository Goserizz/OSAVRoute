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
OSAVRoute requires Go 1.22 or later.

# Usage

## Stateless scanning
For stateless scanning, the common usage is
```bash
osavroute_dns -o <OUTPUT_DIR> -pps <PACKET_PER_SECOND> -nsend <N_SENDERS> -domain <DOMAIN>
```
- `OUTPUT_DIR` specifies the path to store output files. When scanning is finished, there will be three directories in `OUTPUT_DIR`:

   - `OUTPUT_DIR/dns` stores response messages except ICMP Time-Exceeds messages received. Each line in each file is `<ORG_ADDR>,<RESP_ADDR>,<RESP_TYPE>`. `<ORG_ADDR>` is the destination address of the initial probing packet. `<RESP_ADDR>` is the responding address. `<RESP_TYPE>` is the protocol type of the response.

   - `OUTPUT_DIR/icmp` stores intermediate files and is usually unimportant.

   - `OUTPUT_DIR/icmp-re` stores ICMP Time-Exceeds messages received. Each line in each file is `<ORG_ADDR>,<FD_ADDR>,<RESP_ADDR>,<TTL>`. `<FD_ADDR>` is the destination address when the probing packet's TTL decreases to 0. `<TTL>` is the TTL of the initial probing packet.

- `<PACKET_PER_SECOND>` is the user-defined sending rate. 
- `<N_SENDERS>` is the number of goroutines used for sending packets. Larger `<PACKET_PER_SECOND>` requires larger `<N_SENDERS>`.

- `<DOMAIN>` is the domain used for stateless scanning.

To use OSAVRoute with TCP, execute the following command:
```bash
osavroute_tcp -o <OUTPUT_DIR> -r <REMOTE_PORT> -pps <PACKET_PER_SECOND> -nsend <N_SENDERS>
```
The output format is similar to `osavroute_dns`; however, `osavroute_tcp` stores response messages in the `OUTPUT_DIR/tcp` directory rather than `OUTPUT_DIR/dns`. Furthermore, you must specify the target TCP port using the `-r <REMOTE_PORT>` option.

## Early-filtering scanning
For early-filtering scanning, the common usage is

```bash
osavroute_dns -mode=early -i <INPUT_FILE> -d <DNS_OUT_FILE> -o <ICMP_OUT_FILE> -domain <DOMAIN> -rand <RAND_PFX>
```
In this command,
- `<INPUT_FILE>` specifies the input file containing addresses you want to scan. This file is formatted by one address on each line.
- `<DNS_OUT_FILE>` specifies the path to store DNS responses and is formatted as 
   > `<ORG_ADDR>,<RESP_ADDR>,<TTL>` 

   on each line.
- `<ICMP_OUT_FILE>` specifies the path to store ICMP Time-Exceeds messages and is formatted as 
   > `<ORG_ADDR>,<RESP_ADDR>,<TTL>`

   on each line.
- `<DOMAIN>` is the domain used for scanning.
- `<RAND_PFX>` is a prefix string added to the query domain to distinguish between different scans.

On the ADNS side, you can receive DNS queries of domains in the following format:
> \<RAND_PFX\>.\<TTL\>.\<IP_HEX\>.\<IS_NORMAL\>.\<DOMAIN\>

- `<RAND_PFX>` is the random prefix specified by the user in the command.
- `<TTL>` is the Time-To-Live value of the probing packet that triggers this DNS query.
- `<IP_HEX>` is the probed IP address in the hex format.
- `<IS_NORMAL>` indicates the type of packet that triggered the DNS query:
    - `1` is triggered by a normal packet.
    - `0` is triggered by a spoofed packet.
- `<DOMAIN>` is the he domain specified by the user in the command.

## Blocking granularity scanning
For blocking granularity scanning, the common usage is

```bash
osavroute_dns -mode=gran -i <INPUT_FILE> -domain <DOMAIN> -rand <RAND_PFX>
```
In this command,

- `<INPUT_FILE>` specifies the input file containing addresses you want to scan. This file is formatted by one address on each line. 
- `<DOMAIN>` is the domain used for scanning.

ADNS receives DNS queries for domains in the following format:

> \<RAND_PFX\>.\<GRAN\>.\<IP_HEX\>.4.\<DOMAIN\>

- `<RAND_PFX>` is the random prefix specified by the user in the command.
- `<GRAN>` is the blocking granularity tested by the probing packet that triggers the DNS query.
- `<IP_HEX>` is the probed IP address in hexadecimal format.
- `4` indicates that the DNS query is triggered by a blocking granularity scan.
- `<DOMAIN>` is the domain specified by the user in the command.

# Note
1. OSAVRoute can automatically find your network interface and destination MAC address (MAC address of your gateway). However, you can always specify them by:
   ```bash
   osavroute_dns -o <OUTPUT_DIR> -pps <PACKET_PER_SECOND> -nsend <N_SENDERS> -iface <NETWORK_INTERFACE> -dmac <DEST_MAC>
   ```
2. You **SHOULD** own the domain used for stateless scanning, unless doing so would be unethical, as the scanning will draw DNS traffic to the owner's ADNS.
3. You **MUST** own the domain used for early-filtering scanning and blocking granularity scanning. The ADNS must also be configured to receive DNS queries. The configuration of the ADNS is not specified here.
4. Early-filtering and blocking granularity scanning is based on DNS, and OSAVRoute with TCP cannot run them.
5. For more details, you can run
   ```bash
   osavroute_dns -h
   ```
   or
   ```bash
   osavroute_tcp -h
   ```

# License
This artifact is licensed under the [MIT License](LICENSE.txt).
