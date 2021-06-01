package bbs

import (
	"crypto/sha256"
	"fmt"
	"github.com/Nik-U/pbc"
	"testing"
)

func TestSign(t *testing.T) {
	params := pbc.GenerateA(160, 512)
	// serialization params
	str := params.String()
	//fmt.Println("params is : ", str)
	newParams, _ := pbc.NewPairingFromString(str)
	// get g1 and g2
	pairing := newParams
	g1 := pairing.NewG1().Rand()
	g2 := pairing.NewG2().Rand()
	// generate Group
	priv := GenerateGroup(g1, g2, pairing)
	// 编码群公钥，转换成byte数组
	testGroup := EncodeGroup(priv.Group)
	//generate  new  member
	cert := priv.Cert()
	fmt.Printf("member 1 is : %X\n", sha256.Sum256(cert.A.Bytes()))
	//generate  new  member
	cert1 := priv.Cert()
	fmt.Printf("member 2 is : %X\n", sha256.Sum256(cert1.A.Bytes()))
	//verify  cert
	Verify_cert(cert)
	Verify_cert(cert1)
	// signature message
	m := "hello world"
	//generate  signature
	sig := Sign(cert, m)
	sig1 := Sign(cert1, m)
	// 编码签名，转换成byte数组
	enSig := EncodeSign(sig)
	deSig := DecodeSign(enSig, newParams)
	//get Group
	enGroup := DecodeGroup(testGroup, newParams)
	// verify sign
	enGroup.Verify_sign(deSig)
	enGroup.Verify_sign(sig1)
	// open sign
	priv.Open(sig)
	priv.Open(sig1)
}
