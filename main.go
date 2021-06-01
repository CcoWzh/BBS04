package main

import (
	"BBS04/bbs"
	"BBS04/file"
	"BBS04/route"
	"github.com/Nik-U/pbc"
	"github.com/gin-gonic/gin"
)

func init() {
	file.FileRemove("params")
	file.FileRemove("groupPublicKey")
	file.FileRemove("groupPrivateKey")

	params := pbc.GenerateA(160, 512)
	// serialization params
	str := params.String()
	file.Byte2File("params", []byte(str))
	str1 := file.File2Byte("params")
	pairing, _ := pbc.NewPairingFromString(string(str1))
	// get g1 and g2
	g1 := pairing.NewG1().Rand()
	g2 := pairing.NewG2().Rand()
	privateKey := bbs.GenerateGroup(g1, g2, pairing)
	// 编码群公钥，转换成byte数组
	groupPK := bbs.EncodeGroup(privateKey.Group)
	groupPrivateKey := bbs.EncodePrivateKey(privateKey)
	file.Byte2File("groupPublicKey", groupPK)
	file.Byte2File("groupPrivateKey", groupPrivateKey)
}

func main() {
	r := gin.Default()

	r.POST("/group/genKey/:user", route.GenerateNewMember)
	r.GET("/group/file/:file", route.DownloadFile)
	r.POST("/group/verify", route.VerifySign)
	r.POST("/group/sign", route.Sign)
	r.POST("/group/open", route.Open)

	_ = r.Run(":8080") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
