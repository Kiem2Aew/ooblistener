package main

import (
	"bytes"
	jsonpkg "encoding/json"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/Kiem2Aew/ooblistener/pkg/client"
	"github.com/Kiem2Aew/ooblistener/pkg/options"
	"github.com/Kiem2Aew/ooblistener/pkg/server"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

func main() {
	// Установка настроек клиента по умолчанию: сервера для подключения задан как - ooblistener.ru
	defaultOptions := client.DefaultOptions
	// Синтаксический разбор аргументов, переданных программе на старте (НАЧАЛО).
	cliClientOptions := &options.CLIClientOptions{}
	// Установка правил парсинга аргументов: задавание имен параметров, их краткого описания, возможных и по умолчанию значений.
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`ooblistener client - Go client to generate ooblistener payloads and display interaction data.`)
	options.CreateGroup(flagSet, "input", "Input",
		flagSet.StringVarP(&cliClientOptions.ServerURL, "server", "s", defaultOptions.ServerURL, "ooblistener server(s) to use"),
	)
	options.CreateGroup(flagSet, "config", "config",
		flagSet.IntVarP(&cliClientOptions.NumberOfPayloads, "number", "n", 1, "number of ooblistener payload to generate"),
		flagSet.StringVarP(&cliClientOptions.Token, "token", "t", "", "authentication token to connect protected ooblistener server"),
		flagSet.IntVarP(&cliClientOptions.PollInterval, "poll-interval", "pi", 5, "poll interval in seconds to pull interaction data"),
		flagSet.BoolVarP(&cliClientOptions.DisableHTTPFallback, "no-http-fallback", "nf", false, "disable http fallback registration"),
		flagSet.BoolVar(&cliClientOptions.Persistent, "persist", false, "enables persistent ooblistener sessions"),
	)
	options.CreateGroup(flagSet, "filter", "Filter",
		flagSet.BoolVar(&cliClientOptions.DNSOnly, "dns-only", false, "display only dns interaction in CLI output"),
		flagSet.BoolVar(&cliClientOptions.HTTPOnly, "http-only", false, "display only http interaction in CLI output"),
		flagSet.BoolVar(&cliClientOptions.SmtpOnly, "smtp-only", false, "display only smtp interactions in CLI output"),
	)
	options.CreateGroup(flagSet, "output", "Output",
		flagSet.StringVar(&cliClientOptions.Output, "o", "", "output file to write interaction data"),
		flagSet.BoolVar(&cliClientOptions.JSON, "json", false, "write output in JSONL(ines) format"),
		flagSet.BoolVar(&cliClientOptions.Verbose, "v", false, "display verbose interaction"),
	)

	// Если разобрать, переданные программе на вход, аргументы не удалось, то завершить выполнение программы, выдать сообщение об ошибке
	// Парсинг польз. ввода согласно созданным правилам
	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse options: %s\n", err)
	}
	// Синтаксический разбор аргументов, переданных программе на старте (КОНЕЦ).

	// Показать баннер с названием программы
	options.ShowBanner()

	// Если задан файл, в который писать выходные значения программы, то создать файл локально на диске
	var outputFile *os.File
	var err error
	if cliClientOptions.Output != "" {
		if outputFile, err = os.Create(cliClientOptions.Output); err != nil {
			gologger.Fatal().Msgf("Could not create output file: %s\n", err)
		}
		defer outputFile.Close()
	}

	// Создать клиента (произвести регистрацию на сервере)
	client, err := client.New(&client.Options{
		ServerURL:           cliClientOptions.ServerURL,
		PersistentSession:   cliClientOptions.Persistent,
		Token:               cliClientOptions.Token,
		DisableHTTPFallback: cliClientOptions.DisableHTTPFallback,
	})
	if err != nil {
		gologger.Fatal().Msgf("Could not create client: %s\n", err)
	}

	// Запросить у сервера n URL-адресов, которые можно использовать для выполнения запросов внешнего взаимодействия.
	gologger.Info().Msgf("Listing %d payload for OOB Testing\n", cliClientOptions.NumberOfPayloads)
	for i := 0; i < cliClientOptions.NumberOfPayloads; i++ {
		gologger.Info().Msgf("%s\n", client.URL())
	}

	// Если не заданы фильтры по отслеживаемому трафику (только DNS/HTTP/SMTP взаимодвествие), то показывать все взаимодействия клиенту
	noFilter := !cliClientOptions.DNSOnly && !cliClientOptions.HTTPOnly && !cliClientOptions.SmtpOnly

	client.StartPolling(time.Duration(cliClientOptions.PollInterval)*time.Second, func(interaction *server.Interaction) {
		if !cliClientOptions.JSON {
			builder := &bytes.Buffer{}
			switch interaction.Protocol {
			case "dns":
				if noFilter || cliClientOptions.DNSOnly {
					builder.WriteString(fmt.Sprintf("[%s] Received DNS interaction (%s) from %s at %s", interaction.FullId, interaction.QType, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliClientOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n-----------\nDNS Request\n-----------\n\n%s\n\n------------\nDNS Response\n------------\n\n%s\n\n", interaction.RawRequest, interaction.RawResponse))
					}
					writeOutput(outputFile, builder)
				}
			case "http":
				if noFilter || cliClientOptions.HTTPOnly {
					builder.WriteString(fmt.Sprintf("[%s] Received HTTP interaction from %s at %s", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliClientOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nHTTP Request\n------------\n\n%s\n\n-------------\nHTTP Response\n-------------\n\n%s\n\n", interaction.RawRequest, interaction.RawResponse))
					}
					writeOutput(outputFile, builder)
				}
			case "smtp":
				if noFilter || cliClientOptions.SmtpOnly {
					builder.WriteString(fmt.Sprintf("[%s] Received SMTP interaction from %s at %s", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp.Format("2006-01-02 15:04:05")))
					if cliClientOptions.Verbose {
						builder.WriteString(fmt.Sprintf("\n------------\nSMTP Interaction\n------------\n\n%s\n\n", interaction.RawRequest))
					}
					writeOutput(outputFile, builder)
				}
			}
		} else {
			b, err := jsonpkg.Marshal(interaction)
			if err != nil {
				gologger.Error().Msgf("Could not marshal json output: %s\n", err)
			} else {
				os.Stdout.Write(b)
				os.Stdout.Write([]byte("\n"))
			}
			if outputFile != nil {
				_, _ = outputFile.Write(b)
				_, _ = outputFile.Write([]byte("\n"))
			}
		}
	})

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		client.StopPolling()
		client.Close()
		os.Exit(1)
	}
}

func writeOutput(outputFile *os.File, builder *bytes.Buffer) {
	if outputFile != nil {
		_, _ = outputFile.Write(builder.Bytes())
		_, _ = outputFile.Write([]byte("\n"))
	}
	gologger.Silent().Msgf("%s", builder.String())
}
