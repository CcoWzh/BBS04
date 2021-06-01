package file

import (
	"fmt"
	"io/ioutil"
	"os"
)

func Byte2File(fileName string, message []byte) {
	//打开文件，没有此文件则创建文件，将写入的内容append进去
	w, openError := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	checkError(openError, "文件打开异常:")
	defer w.Close()

	_, err1 := w.Write(message)
	checkError(err1, "文件write异常:")
}

func File2Byte(fileName string) []byte {
	file, inputError := os.Open(fileName)
	if inputError != nil {
		fmt.Printf("\033[1;31m%s\033[0m\n", "文件打开异常："+inputError.Error())
		return nil
	}
	defer file.Close()

	//读取内容
	fd, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Printf("\033[1;31m%s\033[0m\n", "文件read异常："+err.Error())
		return nil
	}

	return fd
}

func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func FileRemove(fileName string) {
	r, e := FileExists(fileName)
	checkError(e, "FileExists:")
	if r {
		checkError(os.Remove(fileName), "remove file :")
		fmt.Println(fileName + "  move success !!!")
	}
}

func checkError(err error, message string) {
	if err != nil {
		fmt.Printf("\033[1;31m%s\033[0m\n", message+err.Error())
		return
	}
}

func Mkdir(dir string) {
	err := os.MkdirAll(dir, os.ModePerm) //创建多级目录
	if err != nil {
		fmt.Printf("\033[1;31m%s\033[0m\n", "MkdirAll:"+err.Error())
	}
}
