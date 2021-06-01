package route

import (
	"BBS04/bbs"
	"BBS04/file"
	"fmt"
	"github.com/Nik-U/pbc"
	"github.com/gin-gonic/gin"
)

func GenerateNewMember(c *gin.Context) {
	user := c.Param("user")
	fmt.Println("URL IS /group/:user,and get param is : ", user)

	str := file.File2Byte("params")
	newParams, _ := pbc.NewPairingFromString(string(str))
	pairing := newParams
	PK := bbs.DecodeGroup(file.File2Byte("groupPublicKey"), pairing)
	groupPrivateKey := bbs.DecodePrivateKey(file.File2Byte("groupPrivateKey"), PK)

	cert := groupPrivateKey.Cert()

	fileName := user + "memberPrivateKey"
	file.Byte2File(fileName, bbs.EncodeCertKey(cert))
	fmt.Println("===========================================================")

	c.File(fileName)
	file.FileRemove(fileName)
}

func DownloadFile(c *gin.Context) {
	fileName := c.Param("file")
	if fileName == "groupPrivateKey" {
		c.JSON(404, gin.H{
			"message": "groupPrivateKey is No access ",
		})
	}

	c.File(fileName)
}
