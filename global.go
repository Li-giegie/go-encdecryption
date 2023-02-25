package go_encdecryption

type Method byte

const (
	Method_AES_CBC Method = iota
	Method_AES_CFB
	Method_AES_CRT
	Method_AES_ECB
	Method_AES_OFB
	Method_DES
	Method_RSA
)
