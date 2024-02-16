package main

import (
	"log"
	"os"
	"runtime/pprof"

	"github.com/kubewarden/audit-scanner/cmd"
)

func main() {
	f, err := os.Create("mem.prof")
	if err != nil {
		log.Fatal("could not create memory profile: ", err)
	}
	defer f.Close()

	cmd.Execute()

	if err := pprof.WriteHeapProfile(f); err != nil {
		log.Fatal("could not write memory profile: ", err)
	}
}
