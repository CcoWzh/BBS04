package bbs

import (
	"BBS04/file"
	"fmt"
	"github.com/Nik-U/pbc"
	"os"
	"testing"
)

func EncodePrivateKeyInit() {
	file.FileRemove("params")
	file.FileRemove("groupPublicKey")
	file.FileRemove("groupPrivateKey")

	params := pbc.GenerateA(160, 512)
	// serialization params
	str := params.String()
	file.Byte2File("params", []byte(str))
}

func TestEncodePrivateKey(t *testing.T) {
	EncodePrivateKeyInit()
	// read file
	str := file.File2Byte("params")
	newParams, _ := pbc.NewPairingFromString(string(str))
	// get g1 and g2
	pairing := newParams
	g1 := pairing.NewG1().Rand()
	g2 := pairing.NewG2().Rand()
	privateKey := GenerateGroup(g1, g2, pairing)

	// 编码群公钥，转换成byte数组
	groupPK := EncodeGroup(privateKey.Group)
	groupPrivateKey := EncodePrivateKey(privateKey)
	file.Byte2File("groupPublicKey", groupPK)
	file.Byte2File("groupPrivateKey", groupPrivateKey)

	PK := DecodeGroup(file.File2Byte("groupPublicKey"), pairing)
	myPrivateKey := DecodePrivateKey(file.File2Byte("groupPrivateKey"), PK)

	if myPrivateKey.xi1.Equals(privateKey.xi1) && myPrivateKey.xi2.Equals(privateKey.xi2) {
		fmt.Println("true")
	} else {
		fmt.Println("false")
	}

}

func DecodeCertKeyInit() {
	checkError(os.Remove("memberSign"))
	checkError(os.Remove("memberPrivateKey"))
}

func TestDecodeCertKey(t *testing.T) {
	str := file.File2Byte("params")
	newParams, _ := pbc.NewPairingFromString(string(str))
	// get g1 and g2
	pairing := newParams
	PK := DecodeGroup(file.File2Byte("groupPublicKey"), pairing)
	myPrivateKey := DecodePrivateKey(file.File2Byte("groupPrivateKey"), PK)

	cert1 := myPrivateKey.Cert()
	sign := Sign(cert1, "hello world")

	file.Byte2File("memberSign", EncodeSign(sign))
	file.Byte2File("memberPrivateKey", EncodeCertKey(cert1))
	memberKey := DecodeCertKey(file.File2Byte("memberPrivateKey"), PK)
	memberSig := DecodeSign(file.File2Byte("memberSign"), pairing)

	memberKey.Verify_sign(memberSig)
	memberKey.Verify_sign(sign)
}

func checkError(err error) {
	if err != nil {
		fmt.Printf("\033[1;31m%s\033[0m\n", err.Error())
		return
	}
}
