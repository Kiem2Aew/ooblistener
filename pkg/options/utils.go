package options

import (
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

const banner = `
               _      _  _       _                            
              | |    | |(_)     | |                           
  ___    ___  | |__  | | _  ___ | |_   ___  _ __    ___  _ __ 
 / _ \  / _ \ | '_ \ | || |/ __|| __| / _ \| '_ \  / _ \| '__|
| (_) || (_) || |_) || || |\__ \| |_ |  __/| | | ||  __/| |   
 \___/  \___/ |_.__/ |_||_||___/ \__| \___||_| |_| \___||_|(.ru/.online) 
`
// Создание словаря из переданных программе аргументов вида: {"input":{"Domain":...}, "services":{"DnsPort":...},"debug":{"debug":...}}
func CreateGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}

func ShowBanner() {
	gologger.Print().Msgf("%s\n", banner)
}
