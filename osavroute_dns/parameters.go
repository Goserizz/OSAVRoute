package main

const (
	STATELESS_DOMAIN                      = "v4.ruiruitest.online"
	CHARS                                 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
	CHARS_NUM                             = "0123456789"
	FORMAT_TTL_LEN                        = 2
	BASE_PORT                      uint16 = 50000
	STATELESS_QRY_SIZE_SLOW               = 50
	STATELESS_RAND_LEN_SLOW               = 4 // must be even
	STATELESS_FORMAT_IPV4_LEN_SLOW        = 15
	STATELESS_FORMAT_IPV4_SLOW            = "000:000:000:000"
	MAC_HDR_SIZE                          = 14
	IPV4_HDR_SIZE                         = 20
	UDP_HDR_SIZE                          = 8
	DNS_HDR_SIZE                          = 12
	TRANSACTION_ID                 uint16 = 6666
	EARLY_DOMAIN                          = "osav.ruiruitest.online"
	RAND_NUM_LEN                          = 9
	TTL_LEN                               = 2
	RANGE_LEN                             = 2
	IPV4_ENCODE_LEN                       = 8
	IS_NORMAL_LEN                         = 1
	BUF_SIZE                              = 1024
	LOG_INTV                              = 10000
)

var (
	STATELESS_IPV4_TTL_DOMAIN_LEN_SLOW = STATELESS_RAND_LEN_SLOW + FORMAT_TTL_LEN + STATELESS_FORMAT_IPV4_LEN_SLOW + len(STATELESS_DOMAIN) + 4
	STATELESS_IPV4_LEN_SLOW            = uint16(IPV4_HDR_SIZE + UDP_HDR_SIZE + DNS_HDR_SIZE + STATELESS_QRY_SIZE_SLOW)
	IPV4_LEN                           = IPV4_HDR_SIZE + UDP_HDR_SIZE + DNS_HDR_SIZE + 1 + RAND_NUM_LEN + 1 + TTL_LEN + 1 + IPV4_ENCODE_LEN + 1 + IS_NORMAL_LEN + 1 + len(EARLY_DOMAIN) + 5
)
