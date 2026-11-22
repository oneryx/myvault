package main

import (
	"flag"
	"log"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/updater/native"
)

var demoFlag = flag.Bool("demo", false, "run with an in-memory sample vault")

func main() {
	flag.Parse()
	mygo.App.SetName("MyVault")
	mygo.Use(native.Plugin)
	mygo.App.WhenReady(func() {
		if *demoFlag {
			newDemoShell()
			return
		}
		NewDesktopShell()
	})
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
