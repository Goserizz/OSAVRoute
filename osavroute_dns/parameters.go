package main

const (
	CHARS                                 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
	CHARS_NUM                             = "0123456789"
	FORMAT_TTL_LEN                        = 2
	BASE_PORT                      uint16 = 50000
	STATELESS_RAND_LEN_SLOW               = 4
	STATELESS_FORMAT_IPV4_LEN_SLOW        = 15
	STATELESS_FORMAT_IPV4_SLOW            = "000:000:000:000"
	MAC_HDR_SIZE                          = 14
	IPV4_HDR_SIZE                         = 20
	UDP_HDR_SIZE                          = 8
	DNS_HDR_SIZE                          = 12
	TRANSACTION_ID                 uint16 = 6666
	RAND_NUM_LEN                          = 9
	TTL_LEN                               = 2
	RANGE_LEN                             = 2
	IPV4_ENCODE_LEN                       = 8
	IS_NORMAL_LEN                         = 1
	BUF_SIZE                              = 1024
	LOG_INTV                              = 10000
)
