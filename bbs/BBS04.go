package bbs

import (
	"crypto/sha256"
	"fmt"
	"github.com/Nik-U/pbc"
)

// 群公钥
type Group struct {
	g1, h, u, v, g2, w, ehw, ehg2, minusEg1g2 *pbc.Element
	pairing                                   *pbc.Pairing
}

// 群主的私钥
type PrivateKey struct {
	*Group
	xi1, xi2, gamma *pbc.Element
}

// 群成员的私钥,群成员的私钥中，有保护群公钥
type Cert struct {
	*Group
	A, a *pbc.Element
}

// 签名
type Sig struct {
	m                                                  string
	t1, t2, t3, c, salpha, sbeta, sa, sdelta1, sdelta2 *pbc.Element
}

// GenerateGroup generates a new group and group private key.
func GenerateGroup(g_1, g_2 *pbc.Element, pairing_ *pbc.Pairing) *PrivateKey {
	priv := new(PrivateKey)
	priv.Group = new(Group)
	priv.pairing = pairing_
	priv.g1 = g_1
	priv.h = priv.pairing.NewG1().Rand()
	priv.g2 = g_2
	priv.xi1 = priv.pairing.NewZr().Rand()
	priv.xi2 = priv.pairing.NewZr().Rand()
	temp1 := priv.pairing.NewZr().Invert(priv.xi1)
	temp2 := priv.pairing.NewZr().Invert(priv.xi2)
	priv.u = priv.pairing.NewG1().PowZn(priv.h, temp1)
	priv.v = priv.pairing.NewG1().PowZn(priv.h, temp2)
	priv.gamma = priv.pairing.NewZr().Rand()
	priv.w = priv.pairing.NewG2().PowZn(priv.g2, priv.gamma)
	priv.precompute()

	return priv
}
func (g *Group) precompute() {
	g.ehw = g.pairing.NewGT().Pair(g.h, g.w)
	g.ehg2 = g.pairing.NewGT().Pair(g.h, g.g2)
	t := g.pairing.NewGT().Pair(g.g1, g.g2)
	g.minusEg1g2 = g.pairing.NewGT().Neg(t) //question
}

func (priv *PrivateKey) Cert() *Cert {
	cert := new(Cert)
	cert.Group = priv.Group
	cert.a = priv.pairing.NewZr().Rand()

	temp3 := priv.pairing.NewZr().Add(priv.gamma, cert.a)
	temp4 := priv.pairing.NewZr().Invert(temp3)
	cert.A = priv.pairing.NewG1().PowZn(priv.g1, temp4)
	return cert
}

func Verify_cert(cert *Cert) bool {
	temp1 := cert.pairing.NewG2().PowZn(cert.g2, cert.a)
	temp2 := cert.pairing.NewG2().Mul(cert.w, temp1)
	e1 := cert.pairing.NewGT().Pair(cert.A, temp2)

	ttt2 := cert.pairing.NewGT().Pair(cert.g1, cert.g2)
	if e1.Equals(ttt2) {
		fmt.Println("群成员私钥有效 true")
		return true
	} else {
		fmt.Println("群成员私钥无效 false")
		return false
	}
}

func Sign(cert *Cert, m string) *Sig {
	sig := new(Sig)
	alpha := cert.pairing.NewZr().Rand()
	beta := cert.pairing.NewZr().Rand()
	t1 := cert.pairing.NewG1().PowZn(cert.u, alpha)
	t2 := cert.pairing.NewG1().PowZn(cert.v, beta)
	tmp := cert.pairing.NewZr().Add(alpha, beta)
	tmp1 := cert.pairing.NewG1().PowZn(cert.h, tmp)
	t3 := cert.pairing.NewG1().Mul(cert.A, tmp1) //question
	delta1 := cert.pairing.NewZr().Mul(cert.a, alpha)
	delta2 := cert.pairing.NewZr().Mul(cert.a, beta)
	ralpha := cert.pairing.NewZr().Rand()
	rbeta := cert.pairing.NewZr().Rand()
	//rx := cert.pairing.NewZr().Rand()
	rdelta1 := cert.pairing.NewZr().Rand()
	rdelta2 := cert.pairing.NewZr().Rand()
	ra := cert.pairing.NewZr().Rand()
	r1 := cert.pairing.NewG1().PowZn(cert.u, ralpha)
	r2 := cert.pairing.NewG1().PowZn(cert.v, rbeta)
	//**********************************************************//
	temp1 := cert.pairing.NewGT().Pair(t3, cert.g2)
	r3_e1 := cert.pairing.NewGT().PowZn(temp1, ra)
	uuu := cert.pairing.NewZr().Neg(ralpha)
	www := cert.pairing.NewZr().Neg(rbeta)
	xxx := cert.pairing.NewZr().Add(uuu, www)
	r3_e2 := cert.pairing.NewGT().PowZn(cert.ehw, xxx)
	uuu1 := cert.pairing.NewZr().Neg(rdelta1)
	www1 := cert.pairing.NewZr().Neg(rdelta2)
	xxx1 := cert.pairing.NewZr().Add(uuu1, www1)
	r3_e3 := cert.pairing.NewGT().PowZn(cert.ehg2, xxx1)

	//eh3g2:=cert.pairing.NewGT().Pair(cert.h_,cert.g2)
	//r3_e4:=cert.pairing.NewGT().PowZn(eh3g2,rx)
	r3 := cert.pairing.NewGT().Mul(cert.pairing.NewGT().Mul(r3_e1, r3_e2), r3_e3)

	tt_temp2 := cert.pairing.NewG1().PowZn(t1, ra)
	tt_temp := cert.pairing.NewZr().Neg(rdelta1)
	tt := cert.pairing.NewG1().PowZn(cert.u, tt_temp)
	r4 := cert.pairing.NewG1().Mul(tt, tt_temp2)
	rr_temp2 := cert.pairing.NewG1().PowZn(t2, ra)
	rr_temp := cert.pairing.NewZr().Neg(rdelta2)
	rr := cert.pairing.NewG1().PowZn(cert.v, rr_temp)
	r5 := cert.pairing.NewG1().Mul(rr, rr_temp2)
	var s string
	s += t1.String()
	s += t2.String()
	s += t3.String()
	s += r1.String()
	s += r2.String()
	s += r3.String()
	s += r4.String()
	s += r5.String()
	s += m

	c := cert.pairing.NewZr().SetFromStringHash(s, sha256.New())
	sig.m = m
	sig.c = c
	sig.t1 = t1
	sig.t2 = t2
	sig.t3 = t3
	sig.salpha = cert.pairing.NewZr().Add(ralpha, cert.pairing.NewZr().Mul(c, alpha))
	sig.sbeta = cert.pairing.NewZr().Add(rbeta, cert.pairing.NewZr().Mul(c, beta))
	sig.sa = cert.pairing.NewZr().Add(ra, cert.pairing.NewZr().Mul(c, cert.a))
	//sig.sx=cert.pairing.NewZr().Add(rx,cert.pairing.NewZr().Mul(c,cert.x_))
	sig.sdelta1 = cert.pairing.NewZr().Add(rdelta1, cert.pairing.NewZr().Mul(c, delta1))
	sig.sdelta2 = cert.pairing.NewZr().Add(rdelta2, cert.pairing.NewZr().Mul(c, delta2))
	return sig
}

func (g *Group) Verify_sign(sig *Sig) bool {
	r1 := g.pairing.NewG1().Mul(g.pairing.NewG1().PowZn(g.u, sig.salpha), g.pairing.NewG1().PowZn(sig.t1, g.pairing.NewZr().Neg(sig.c)))
	r2 := g.pairing.NewG1().Mul(g.pairing.NewG1().PowZn(g.v, sig.sbeta), g.pairing.NewG1().PowZn(sig.t2, g.pairing.NewZr().Neg(sig.c)))
	//******************************************
	temp1 := g.pairing.NewGT().Pair(sig.t3, g.g2)
	r3_e1 := g.pairing.NewGT().PowZn(temp1, sig.sa)
	uuu := g.pairing.NewZr().Neg(sig.salpha)
	www := g.pairing.NewZr().Neg(sig.sbeta)
	xxx := g.pairing.NewZr().Add(uuu, www)
	r3_e2 := g.pairing.NewGT().PowZn(g.ehw, xxx)
	uuu1 := g.pairing.NewZr().Neg(sig.sdelta1)
	www1 := g.pairing.NewZr().Neg(sig.sdelta2)
	xxx1 := g.pairing.NewZr().Add(uuu1, www1)
	r3_e3 := g.pairing.NewGT().PowZn(g.ehg2, xxx1)

	//eh3g2:=g.pairing.NewGT().Pair(h3,g.g2)
	//r3_e4:=g.pairing.NewGT().PowZn(eh3g2,sig.sx)

	r3_tep := g.pairing.NewGT().Mul(g.pairing.NewGT().Mul(r3_e1, r3_e2), r3_e3)
	yyy := g.pairing.NewGT().Pair(sig.t3, g.w)
	ggg := g.pairing.NewGT().Pair(g.g1, g.g2)
	hhh := g.pairing.NewGT().Invert(ggg)
	r3 := g.pairing.NewGT().Mul(r3_tep, g.pairing.NewGT().PowZn(g.pairing.NewGT().Mul(yyy, hhh), sig.c))
	//*******************************************
	tt_temp2 := g.pairing.NewG1().PowZn(sig.t1, sig.sa)
	tt_temp := g.pairing.NewZr().Neg(sig.sdelta1)
	tt := g.pairing.NewG1().PowZn(g.u, tt_temp)
	r4 := g.pairing.NewG1().Mul(tt, tt_temp2)
	rr_temp2 := g.pairing.NewG1().PowZn(sig.t2, sig.sa)
	rr_temp := g.pairing.NewZr().Neg(sig.sdelta2)
	rr := g.pairing.NewG1().PowZn(g.v, rr_temp)
	r5 := g.pairing.NewG1().Mul(rr, rr_temp2)
	var s string
	s += sig.t1.String()
	s += sig.t2.String()
	s += sig.t3.String()
	s += r1.String()
	s += r2.String()
	s += r3.String()
	s += r4.String()
	s += r5.String()
	s += sig.m

	c_ := g.pairing.NewZr().SetFromStringHash(s, sha256.New())
	if c_.Equals(sig.c) {
		fmt.Println("verify_sign   true")
		return true
	} else {
		fmt.Println("verify_sign   false")
		return false
	}
}

func (priv *PrivateKey) Open(sig *Sig) *pbc.Element {
	temp1 := priv.pairing.NewG1().PowZn(sig.t1, priv.xi1)
	temp2 := priv.pairing.NewG1().PowZn(sig.t2, priv.xi2)
	temp3 := priv.pairing.NewG1().Mul(sig.t3, priv.pairing.NewG1().Invert(priv.pairing.NewG1().Mul(temp1, temp2)))
	//fmt.Println(temp3.String())
	fmt.Printf("签名人为：%X\n", sha256.Sum256(temp3.Bytes()))
	return temp3
}
