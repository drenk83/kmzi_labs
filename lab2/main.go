package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	lab1 := flag.String("lab1", "../lab1", "каталог первой лабораторной: инструкция, in/ и key/")
	job := flag.String("job", "1job_Var8", "каталог варианта: mode*.in и IV1.in…IV10.in")
	out := flag.String("out", "out", "куда писать test1.out…test10.out")
	flag.Parse()

	if err := encryptJob(*lab1, *job, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
