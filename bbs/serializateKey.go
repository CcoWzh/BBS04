package bbs

import (
	"log"
)

// encode PrivateKey
func EncodePrivateKey(key *PrivateKey) []byte {
	xi1 := key.xi1.Bytes()
	xi2 := key.xi2.Bytes()
	gamma := key.gamma.Bytes()

	result := append(xi1, xi2...)
	result = append(result, gamma...)

	result = append(result, byte(len(xi1)))
	result = append(result, byte(len(xi2)))
	result = append(result, byte(len(gamma)))

	return result
}

// decode PrivateKey
func DecodePrivateKey(key []byte, group *Group) *PrivateKey {
	privateKey := new(PrivateKey)
	privateKey.Group = group

	total_len := len(key) - 3

	len1 := int(key[total_len])
	len2 := int(key[total_len+1])
	len3 := int(key[total_len+2])
	if len1+len2+len3 != total_len {
		log.Fatal("DecodeSign 数组长度错误")
	}

	privateKey.xi1 = group.pairing.NewZr().SetBytes(key[:len1])
	left := len1
	privateKey.xi2 = group.pairing.NewZr().SetBytes(key[left:(left + len2)])
	left += len2
	privateKey.gamma = group.pairing.NewZr().SetBytes(key[left:(left + len3)])

	return privateKey
}

func EncodeCertKey(cert *Cert) []byte {
	A := cert.A.Bytes()
	a := cert.a.Bytes()

	result := append(A, a...)
	result = append(result, byte(len(A)))
	result = append(result, byte(len(a)))

	return result
}

func DecodeCertKey(cert []byte, group *Group) *Cert {
	member := new(Cert)
	member.Group = group

	total_len := len(cert) - 2

	len1 := int(cert[total_len])
	len2 := int(cert[total_len+1])
	if len1+len2 != total_len {
		log.Fatal("DecodeSign 数组长度错误")
	}

	member.A = group.pairing.NewG1().SetBytes(cert[:len1])
	left := len1
	member.a = group.pairing.NewZr().SetBytes(cert[left:(left + len2)])
	return member
}
