package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/internal/e2store"
	"github.com/ethereum/go-ethereum/internal/era"
)

func main() {
	if len(os.Args) != 2 {
		exit(errors.New("usage: era <FILE>"))
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		exit(err)
	}
	defer f.Close()

	r := e2store.NewReader(f)
	for {
		entry, err := r.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			exit(err)
		}
		// fmt.Printf("%x: %d\n", entry.Type, len(entry.Value))
		if entry.Type == era.TypeAccumulator {
			fmt.Printf("root: %s\n", common.Bytes2Hex(entry.Value))
		}
	}
}

func exit(err error) {
	fmt.Fprintf(os.Stderr, "%v", err)
	os.Exit(1)
}
