package bbs

import (
	"github.com/Nik-U/pbc"
	"log"
)

// encode sign
func EncodeSign(sig *Sig) []byte {
	bt1 := []byte(sig.m)

	t1 := sig.t1.Bytes()
	t2 := sig.t2.Bytes()
	t3 := sig.t3.Bytes()
	c := sig.c.Bytes()
	salpha := sig.salpha.Bytes()
	sbeta := sig.sbeta.Bytes()
	sa := sig.sa.Bytes()
	sdelta1 := sig.sdelta1.Bytes()
	sdelta2 := sig.sdelta2.Bytes()

	result := append(bt1, t1...)
	result = append(result, t2...)
	result = append(result, t3...)
	result = append(result, c...)
	result = append(result, salpha...)
	result = append(result, sbeta...)
	result = append(result, sa...)
	result = append(result, sdelta1...)
	result = append(result, sdelta2...)

	result = append(result, byte(len(bt1)))
	result = append(result, byte(len(t1)))
	result = append(result, byte(len(t2)))
	result = append(result, byte(len(t3)))
	result = append(result, byte(len(c)))
	result = append(result, byte(len(salpha)))
	result = append(result, byte(len(sbeta)))
	result = append(result, byte(len(sa)))
	result = append(result, byte(len(sdelta1)))
	result = append(result, byte(len(sdelta2)))

	return result
}

// decode sign
func DecodeSign(sig []byte, pairing *pbc.Pairing) *Sig {
	mySig := new(Sig)
	total_len := len(sig) - 10

	len1 := int(sig[total_len])
	len2 := int(sig[total_len+1])
	len3 := int(sig[total_len+2])
	len4 := int(sig[total_len+3])
	len5 := int(sig[total_len+4])
	len6 := int(sig[total_len+5])
	len7 := int(sig[total_len+6])
	len8 := int(sig[total_len+7])
	len9 := int(sig[total_len+8])
	len10 := int(sig[total_len+9])
	if len1+len2+len3+len4+len5+len6+len7+len8+len9+len10 != total_len {
		log.Fatal("DecodeSign 数组长度错误")
	}

	mySig.m = string(sig[:len1])
	left := len1
	mySig.t1 = pairing.NewG1().SetBytes(sig[left:(left + len2)])
	left += len2
	mySig.t2 = pairing.NewG1().SetBytes(sig[left:(left + len3)])
	left += len3
	mySig.t3 = pairing.NewG1().SetBytes(sig[left:(left + len4)])
	left += len4
	mySig.c = pairing.NewZr().SetBytes(sig[left:(left + len5)])
	left += len5
	mySig.salpha = pairing.NewZr().SetBytes(sig[left:(left + len6)])
	left += len6
	mySig.sbeta = pairing.NewZr().SetBytes(sig[left:(left + len7)])
	left += len7
	mySig.sa = pairing.NewZr().SetBytes(sig[left:(left + len8)])
	left += len8
	mySig.sdelta1 = pairing.NewZr().SetBytes(sig[left:(left + len9)])
	left += len9
	mySig.sdelta2 = pairing.NewZr().SetBytes(sig[left:(left + len10)])

	return mySig
}

// encode group public key
func EncodeGroup(group *Group) []byte {
	g1 := group.g1.Bytes()
	g2 := group.g2.Bytes()
	h := group.h.Bytes()
	u := group.u.Bytes()
	v := group.v.Bytes()
	w := group.w.Bytes()
	ehw := group.ehw.Bytes()
	ehg2 := group.ehg2.Bytes()
	minusEg1g2 := group.minusEg1g2.Bytes()

	result := append(g1, g2...)
	result = append(result, h...)
	result = append(result, u...)
	result = append(result, v...)
	result = append(result, w...)
	result = append(result, ehw...)
	result = append(result, ehg2...)
	result = append(result, minusEg1g2...)

	result = append(result, byte(len(g1)))
	result = append(result, byte(len(g2)))
	result = append(result, byte(len(h)))
	result = append(result, byte(len(u)))
	result = append(result, byte(len(v)))
	result = append(result, byte(len(w)))
	result = append(result, byte(len(ehw)))
	result = append(result, byte(len(ehg2)))
	result = append(result, byte(len(minusEg1g2)))

	return result
}

// decode group public key
func DecodeGroup(group []byte, pairing *pbc.Pairing) *Group {
	myGroup := new(Group)
	myGroup.pairing = pairing

	total_len := len(group) - 9

	len1 := int(group[total_len])
	len2 := int(group[total_len+1])
	len3 := int(group[total_len+2])
	len4 := int(group[total_len+3])
	len5 := int(group[total_len+4])
	len6 := int(group[total_len+5])
	len7 := int(group[total_len+6])
	len8 := int(group[total_len+7])
	len9 := int(group[total_len+8])
	if len1+len2+len3+len4+len5+len6+len7+len8+len9 != total_len {
		log.Fatal("DecodeGroup 数组长度错误")
	}

	myGroup.g1 = pairing.NewG1().SetBytes(group[:len1])
	left := len1
	myGroup.g2 = pairing.NewG2().SetBytes(group[left:(left + len2)])
	left += len2
	myGroup.h = pairing.NewG1().SetBytes(group[left:(left + len3)])
	left += len3
	myGroup.u = pairing.NewG1().SetBytes(group[left:(left + len4)])
	left += len4
	myGroup.v = pairing.NewG1().SetBytes(group[left:(left + len5)])
	left += len5
	myGroup.w = pairing.NewG2().SetBytes(group[left:(left + len6)])
	left += len6
	myGroup.ehw = pairing.NewGT().SetBytes(group[left:(left + len7)])
	left += len7
	myGroup.ehg2 = pairing.NewGT().SetBytes(group[left:(left + len8)])
	left += len8
	myGroup.minusEg1g2 = pairing.NewGT().SetBytes(group[left:(left + len9)])

	return myGroup
}