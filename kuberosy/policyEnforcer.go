package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

func delayedSigterm(stopper chan os.Signal) {
	time.Sleep(60 * time.Second)

}

func consoleCommands() {

	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("kuberosy$ ")
		text, _ := reader.ReadString('\n')
		cmd := strings.Split(text[0:len(text)-1], " ")

		switch cmd[0] {
		case "add":
			continue
		case "update":
			continue
		case "remove":
			continue
		}
	}
}
