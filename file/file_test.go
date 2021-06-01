package file

import (
	"fmt"
	"testing"
)

func TestByte2File(t *testing.T) {
	message := "hello world"
	Byte2File("params", []byte(message))

	contest := File2Byte("params")
	fmt.Println(string(contest))
}
