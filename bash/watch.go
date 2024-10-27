package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var objs watchObjects
	if err := loadWatchObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable(`/bin/bash`)
	if err != nil {
		log.Fatal("open excutable:", err)
	}

	up, err := ex.Uretprobe(`readline`, objs.WatchBash, nil)
	if err != nil {
		log.Fatal("Uretprobe:", err)
	}
	defer up.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		bashInfo := watchBashInfo{}
		if err := objs.BashInput.LookupAndDelete(nil, &bashInfo); err != nil {
			fmt.Printf("Loading eBPF objects: %+v\n", err)
		}
		fmt.Printf("get pid: %d, content: %s\n", bashInfo.Pid,
			unix.ByteSliceToString(bashInfo.Content[:]))
	}
}
