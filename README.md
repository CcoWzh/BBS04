# BBS04(群签名)和Go语言实现

基于PBC库实现的BBS04群签名，以HTTP服务的形式呈现。

主要方法：

```go
	r.POST("/group/genKey/:user", route.GenerateNewMember)
	r.GET("/group/file/:file", route.DownloadFile)
	r.POST("/group/verify", route.VerifySign)
	r.POST("/group/sign", route.Sign)
	r.POST("/group/open", route.Open)
```

目录结构：

```bash
.
├── bbs
│   ├── BBS04.go
│   ├── BBS04_test.go
│   ├── serializateKey.go
│   ├── serializateKey_test.go
│   └── Serialization.go
├── file
│   ├── file.go
│   ├── file_test.go
│   ├── zip.go
│   └── zip_test.go
├── go.mod
├── go.sum
├── main.go
├── resources
│   └── groupPublicKey
└── route
    ├── genKey.go
    ├── open.go
    └── sign.go
```

BBS04群签名的详细介绍：`./bbs/群签名和Go语言实现细节(BBS04).md` 文件。