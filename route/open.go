package route

import (
	"BBS04/bbs"
	"BBS04/file"
	"crypto/sha256"
	"fmt"
	"github.com/Nik-U/pbc"
	"github.com/gin-gonic/gin"
	"log"
)

func Open(c *gin.Context) {
	// single file
	signFile, _ := c.FormFile("sign")
	log.Println(signFile.Filename)
	// Upload the file to specific dst.
	err := c.SaveUploadedFile(signFile, "resources/"+signFile.Filename)
	if err != nil {
		fmt.Printf("\033[1;31m%s\033[0m\n", "VerifySign:"+err.Error())
		c.String(404, fmt.Sprintf("'%s' can not uploaded!", signFile.Filename))
	}

	str := file.File2Byte("params")
	//fmt.Println("params is : ", sha256.Sum256(str))
	newParams, _ := pbc.NewPairingFromString(string(str))
	pairing := newParams
	PK := bbs.DecodeGroup(file.File2Byte("groupPublicKey"), pairing)
	//fmt.Println("PK is : ", sha256.Sum256(file.File2Byte("groupPublicKey")))
	groupPrivateKey := bbs.DecodePrivateKey(file.File2Byte("groupPrivateKey"), PK)

	mySign := bbs.DecodeSign(file.File2Byte("resources/"+signFile.Filename), pairing)
	person := groupPrivateKey.Open(mySign)

	file.FileRemove("resources/" + signFile.Filename)
	c.JSON(200, gin.H{
		"person": fmt.Sprintf("%X", sha256.Sum256(person.Bytes())),
	})
}
