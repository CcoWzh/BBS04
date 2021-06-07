package route

import (
	"BBS04/bbs"
	"BBS04/file"
	"crypto/sha256"
	"fmt"
	"github.com/Nik-U/pbc"
	"github.com/gin-gonic/gin"
	"runtime"
)

func GenerateNewMember(c *gin.Context) {
	// 延迟处理的函数
	defer func() {
		// 发生宕机时，获取panic传递的上下文并打印
		err := recover()
		switch err.(type) {
		case runtime.Error: // 运行时错误
			fmt.Println("runtime error:", err)
		default: // 非运行时错误
			fmt.Println("error:", err)
		}
	}()

	//user := c.Param("user")
	//fmt.Println("URL IS /group/:user,and get param is : ", user)

	str := file.File2Byte("params")
	newParams, _ := pbc.NewPairingFromString(string(str))
	pairing := newParams
	PK := bbs.DecodeGroup(file.File2Byte("groupPublicKey"), pairing)
	groupPrivateKey := bbs.DecodePrivateKey(file.File2Byte("groupPrivateKey"), PK)

	cert := groupPrivateKey.Cert()

	fileName :=  "memberPrivateKey"
	file.Byte2File(fileName, bbs.EncodeCertKey(cert))
	fmt.Println("===========================================================")

	//c.JSON(200, gin.H{
	//	"person": fmt.Sprintf("%X", sha256.Sum256(cert.A.Bytes())),
	//})
	c.Header("Person", fmt.Sprintf("%X", sha256.Sum256(cert.A.Bytes())))
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
