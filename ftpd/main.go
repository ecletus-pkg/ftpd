package main

import (
	"os"

	"github.com/ecletus-pkg/ftpd"
	"gopkg.in/yaml.v2"
)

func main() {
	driver := ftpd.New("ftpd/ftpd.yaml")
	err := driver.GetSettings()
	if err != nil {
		panic(err)
	}
	yaml.NewEncoder(os.Stdout).Encode(driver.Config)
}
