package go_encdecryption

import (
	"fmt"
	"log"
	"testing"
)

func Test_AesCBC192(t *testing.T) {
	log.Println("test--aec--cbc192")
	var k = New_AESKey_192([]byte("--==key"))
	buf, err := AesEncryptCBC([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesDecryptCBC(buf, k)

	fmt.Println(data, err, string(data))

}

func Test_AesCBC128(t *testing.T) {
	log.Println("test--aec--cbc128")
	var k = New_AESKey_128([]byte("--==key"))
	fmt.Println(k)
	buf, err := AesEncryptCBC([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesDecryptCBC(buf, k)

	fmt.Println(data, err, string(data))

}

func Test_AesCBCKey_256(t *testing.T) {
	log.Println("test--aec--cbc256")
	var k = New_AESKey_256([]byte("--==key"))
	fmt.Println("key ", len(k), k)
	buf, err := AesEncryptCBC([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesDecryptCBC(buf, k)

	fmt.Println(data, err, string(data))

}

func Test_AesCFB192(t *testing.T) {
	log.Println("test--aec--cfb192")
	var k = New_AESKey_192([]byte("--==key"))
	buf, err := AesEncryptCFB([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesDecryptCFB(buf, k)

	fmt.Println(data, err, string(data))

}

func Test_AesCFB128(t *testing.T) {
	log.Println("test--aec--cfb128")
	var k = New_AESKey_128([]byte("--==key"))
	fmt.Println(k)
	buf, err := AesEncryptCFB([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesDecryptCFB(buf, k)

	fmt.Println(data, err, string(data))

}

func Test_AesCFB256(t *testing.T) {
	log.Println("test--aec--cfb256")
	var k = New_AESKey_256([]byte("--==key"))
	fmt.Println("key ", len(k), k)
	buf, err := AesEncryptCFB([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesDecryptCFB(buf, k)

	fmt.Println(data, err, string(data))

}

func Test_AesCRT192(t *testing.T) {
	log.Println("test--crt--cfb192")
	var k = New_AESKey_192([]byte("--==key"))

	buf, err := AesCtrCrypt([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}
	data, err := AesCtrCrypt(buf, k)

	fmt.Println(data, err, string(data))

}

func Test_AesCRT128(t *testing.T) {
	log.Println("test--aec--crt128")
	var k = New_AESKey_128([]byte("--==key"))
	fmt.Println(k)
	buf, err := AesCtrCrypt([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesCtrCrypt(buf, k)

	fmt.Println(data, err, string(data))

}

func Test_AesCRT256(t *testing.T) {
	log.Println("test--aec--crt256")
	var k = New_AESKey_256([]byte("--==key"))
	fmt.Println("key ", len(k), k)
	buf, err := AesCtrCrypt([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesCtrCrypt(buf, k)

	fmt.Println(data, err, string(data))

}

func Test_AesECB192(t *testing.T) {
	log.Println("test--ecb--crt192")
	var k = New_AESKey_192([]byte("--==key"))

	buf, err := AesEncryptECB([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesDecryptECB(buf, k)

	fmt.Println(data, err, string(data))
}

func Test_AesECB128(t *testing.T) {
	log.Println("test--ecb--crt128")
	var k = New_AESKey_128([]byte("--==key"))
	fmt.Println(k)
	buf, err := AesEncryptECB([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesDecryptECB(buf, k)

	fmt.Println(data, err, string(data))

}

func Test_AesECB256(t *testing.T) {
	log.Println("test--ecb--crt256")
	var k = New_AESKey_256([]byte("--==key"))
	fmt.Println("key ", len(k), k)
	buf, err := AesEncryptECB([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesDecryptECB(buf, k)

	fmt.Println(data, err, string(data))

}

func Test_AesOFB192(t *testing.T) {
	log.Println("test--ecb--ofb192")
	var k = New_AESKey_192([]byte("--==key"))

	buf, err := AesEncryptOFB([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesDecryptOFB(buf, k)

	fmt.Println(data, err, string(data))

}

func Test_AesOFB128(t *testing.T) {
	log.Println("test--ecb--ofb128")
	var k = New_AESKey_128([]byte("--==key"))
	fmt.Println(k)
	buf, err := AesEncryptOFB([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesDecryptOFB(buf, k)

	fmt.Println(data, err, string(data))

}

func Test_AesOFB256(t *testing.T) {
	log.Println("test--ecb--ofb256")
	var k = New_AESKey_256([]byte("--==key"))
	fmt.Println("key ", len(k), k)
	buf, err := AesEncryptOFB([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := AesDecryptOFB(buf, k)

	fmt.Println(data, err, string(data))
}

func Test_Des64(t *testing.T) {
	log.Println("test--ecb--des64")
	var k = New_DESKey_64([]byte("--==key"))
	fmt.Println("key ", len(k), k)
	buf, err := DesEncrypt([]byte("hello word!"), k)
	fmt.Println(buf, err)
	if err != nil {
		t.Error(err)
		return
	}

	data, err := DesDecrypt(buf, k)

	fmt.Println(data, err, string(data))
}

func TestNew_AESKey_128(t *testing.T) {
	fmt.Println(New_AESKey_128([]byte("hello123hello12")))    //15byte
	fmt.Println(New_AESKey_128([]byte("hello123hello123")))   //16byte
	fmt.Println(New_AESKey_128([]byte("hello1234hello1234"))) //17byte

	fmt.Println(len(New_AESKey_128([]byte("hello123hello12"))))    //15byte
	fmt.Println(len(New_AESKey_128([]byte("hello123hello123"))))   //16byte
	fmt.Println(len(New_AESKey_128([]byte("hello1234hello1234")))) //17byte
}

func TestNew_AESKey_192(t *testing.T) {
	fmt.Println(New_AESKey_192([]byte("12345678123456781234567")))   //15byte
	fmt.Println(New_AESKey_192([]byte("123456781234567812345678")))  //16byte
	fmt.Println(New_AESKey_192([]byte("1234567812345678123456789"))) //17byte

	fmt.Println(len(New_AESKey_192([]byte("12345678123456781234567"))))   //15byte
	fmt.Println(len(New_AESKey_192([]byte("123456781234567812345678"))))  //16byte
	fmt.Println(len(New_AESKey_192([]byte("1234567812345678123456789")))) //17byte
}

func TestNew_AESKey_256(t *testing.T) {
	fmt.Println(New_AESKey_256([]byte("1234567812345678123456781234567")))   //15byte
	fmt.Println(New_AESKey_256([]byte("12345678123456781234567812345678")))  //16byte
	fmt.Println(New_AESKey_256([]byte("123456781234567812345678123456789"))) //17byte

	fmt.Println(len(New_AESKey_256([]byte("1234567812345678123456781234567"))))   //15byte
	fmt.Println(len(New_AESKey_256([]byte("12345678123456781234567812345678"))))  //16byte
	fmt.Println(len(New_AESKey_256([]byte("123456781234567812345678123456789")))) //17byte
}

func TestNew_DESKey_64(t *testing.T) {
	fmt.Println(New_DESKey_64([]byte("1234567")))
	fmt.Println(New_DESKey_64([]byte("12345678")))
	fmt.Println(New_DESKey_64([]byte("123456789")))

	fmt.Println(len(New_DESKey_64([]byte("1234567"))))
	fmt.Println(len(New_DESKey_64([]byte("12345678"))))
	fmt.Println(len(New_DESKey_64([]byte("123456789"))))
}
