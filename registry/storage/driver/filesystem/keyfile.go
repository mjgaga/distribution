package filesystem

import (
	"embed"
)

//go:embed key
var content embed.FS

func readKey() []byte {
	fileBytes, err := content.ReadFile("key")
	if err != nil {
		panic(err)
	}

	return fileBytes
}
