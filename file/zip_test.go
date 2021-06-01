package file

import "testing"

func TestZip(t *testing.T) {
	Zip("../resources", "hello.zip")
}

func TestMkdir(t *testing.T) {
	Mkdir("../resources/cc")
}
