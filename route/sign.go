package route

import (
	"BBS04/bbs"
	"BBS04/file"
	"fmt"
	"github.com/Nik-U/pbc"
	"github.com/gin-gonic/gin"
	"log"
	"os"
	"strconv"
)

// 传入用户的密钥和需要签名的数据
func Sign(c *gin.Context) {
	// single file
	singleFile, _ := c.FormFile("file")
	log.Println(singleFile.Filename)

	// Upload the file to specific dst.
	err := c.SaveUploadedFile(singleFile, "resources/"+singleFile.Filename)
	if err != nil {
		fmt.Printf("\033[1;31m%s\033[0m\n", "VerifySign:"+err.Error())
		c.String(404, fmt.Sprintf("'%s' can not uploaded!", singleFile.Filename))
	}

	// get params
	str := file.File2Byte("params")
	pairing, _ := pbc.NewPairingFromString(string(str))
	PK := bbs.DecodeGroup(file.File2Byte("groupPublicKey"), pairing)
	memberKey := bbs.DecodeCertKey(file.File2Byte("resources/"+singleFile.Filename), PK)

	mysign := bbs.Sign(memberKey, "hello world")
	fmt.Println(mysign)
	fmt.Println("result is : ", PK.Verify_sign(mysign))
	fmt.Println("===========================================================")
	file.Mkdir(singleFile.Filename) //创建多级目录
	if err != nil {
		fmt.Printf("\033[1;31m%s\033[0m\n", "MkdirAll:"+err.Error())
	}
	for i := 0; i < 8; i++ {
		sign1 := bbs.Sign(memberKey,
			c.PostForm("message"+strconv.Itoa(i)))
		file.Byte2File(singleFile.Filename+"/"+
			"memberSign"+strconv.Itoa(i), bbs.EncodeSign(sign1))
	}
	file.Zip(singleFile.Filename, singleFile.Filename+".zip")

	c.File(singleFile.Filename + ".zip")
	_ = os.RemoveAll(singleFile.Filename)
	_ = os.Remove(singleFile.Filename + ".zip")
	file.FileRemove("resources/" + singleFile.Filename)
}

// message
func VerifySign(c *gin.Context) {
	// single file
	sign, _ := c.FormFile("file")
	log.Println(sign.Filename)
	// Upload the file to specific dst.
	err := c.SaveUploadedFile(sign, "resources/"+sign.Filename)
	if err != nil {
		fmt.Printf("\033[1;31m%s\033[0m\n", "VerifySign:"+err.Error())
		c.String(404, fmt.Sprintf("'%s' can not uploaded!", sign.Filename))
	}
	// get params
	str := file.File2Byte("params")
	pairing, _ := pbc.NewPairingFromString(string(str))
	// get group public key
	PK := bbs.DecodeGroup(file.File2Byte("groupPublicKey"), pairing)
	newSign := bbs.DecodeSign(file.File2Byte("resources/"+sign.Filename), pairing)

	result := PK.Verify_sign(newSign)

	file.FileRemove("resources/" + sign.Filename)
	c.JSON(200, gin.H{
		"result": result,
	})
}
