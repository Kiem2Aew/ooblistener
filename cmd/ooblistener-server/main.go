package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Kiem2Aew/ooblistener/pkg/options"
	"github.com/Kiem2Aew/ooblistener/pkg/server"
	"github.com/Kiem2Aew/ooblistener/pkg/server/acme"
	"github.com/Kiem2Aew/ooblistener/pkg/storage"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func main() {
	// Синтаксический разбор аргументов, переданных программе на старте (НАЧАЛО).
	cliServerOptions := &options.CLIServerOptions{}
	flagSet := goflags.NewFlagSet()                                                                    // Пакет goflags реализует синтаксический анализ (разбор) флагов командной строки. (Package goflags implements command-line flag parsing).
	flagSet.SetDescription(`ooblistener server - Go client to configure and host ooblistener server.`) // SetDescription устанавливает поле описания для flagSet (SetDescription sets the description field for a flagSet to a value).

	options.CreateGroup(flagSet, "input", "Input",
		flagSet.StringVarP(&cliServerOptions.Domain, "domain", "d", "", "configured domain to use with ooblistener server"),
		flagSet.StringVar(&cliServerOptions.IPAddress, "ip", "", "public ip address to use for ooblistener server"),
		flagSet.StringVarP(&cliServerOptions.ListenIP, "listen-ip", "lip", "0.0.0.0", "public ip address to listen on"),
		flagSet.IntVarP(&cliServerOptions.Eviction, "eviction", "e", 30, "number of days to persist interaction data in memory"),
		flagSet.BoolVarP(&cliServerOptions.Auth, "auth", "a", false, "enable authentication to server using random generated token"),
		flagSet.StringVarP(&cliServerOptions.Token, "token", "t", "", "enable authentication to server using given token"),
		flagSet.StringVar(&cliServerOptions.OriginURL, "acao-url", "https://app.ooblistener.com", "origin url to send in acao header (required to use web-client)"),
		flagSet.BoolVarP(&cliServerOptions.SkipAcme, "skip-acme", "sa", false, "skip acme registration (certificate checks/handshake + TLS protocols will be disabled)"),
	)
	options.CreateGroup(flagSet, "services", "Services",
		flagSet.IntVar(&cliServerOptions.DnsPort, "dns-port", 53, "port to use for dns service"),
		flagSet.IntVar(&cliServerOptions.HttpPort, "http-port", 80, "port to use for http service"),
		flagSet.IntVar(&cliServerOptions.HttpsPort, "https-port", 443, "port to use for https service"),
		flagSet.IntVar(&cliServerOptions.SmtpPort, "smtp-port", 25, "port to use for smtp service"),
		flagSet.IntVar(&cliServerOptions.SmtpsPort, "smtps-port", 465, "port to use for smtps service"),
		flagSet.IntVar(&cliServerOptions.SmtpAutoTLSPort, "smtp-autotls-port", 587, "port to use for smtps autotls service"),
		flagSet.BoolVarP(&cliServerOptions.RootTLD, "wildcard", "wc", false, "enable wildcard interaction for ooblistener domain (authenticated)"),
	)
	options.CreateGroup(flagSet, "debug", "Debug",
		flagSet.BoolVar(&cliServerOptions.Debug, "debug", false, "start ooblistener server in debug mode"),
	)
	// Если разобрать, переданные программе на вход, аргументы не удалось, то завершить выполнение программы, выдать сообщение об ошибке
	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse options: %s\n", err)
	}
	// Синтаксический разбор аргументов, переданных программе на старте (КОНЕЦ).

	// Показать баннер с названием программы
	options.ShowBanner()

	// Разбор аргументов, переданных программе на старте (НАЧАЛО).
	if cliServerOptions.IPAddress == "" && cliServerOptions.ListenIP == "0.0.0.0" {
		ip := getPublicIP()
		cliServerOptions.IPAddress = ip
		cliServerOptions.ListenIP = ip
	}

	// Установка основных настроек сервера, на основе предоставленных аргументов
	serverOptions := cliServerOptions.AsServerOptions()

	// Установка уровня логирования, если debug, то max.
	if cliServerOptions.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}

	// Если использовать *.ooblistener (ака wildcard interaction), то требуется аутентификация, но тогда будет возможность забирать данные из оперативной памяти сервера даже спустя 30 дней (по умолчванию) - на любое взаимодействие (if root-tld is enabled we enable auth - This ensure that any client has the token)
	// или если задан аргумент Token (of in case a custom token is specified).
	if serverOptions.RootTLD || serverOptions.Token != "" {
		serverOptions.Auth = true
	}

	// Если в настройках сервера установлен флаг Auth = True, или задан аргумент Token, то создать токен длиной 32 байта
	if serverOptions.Auth && serverOptions.Token == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			gologger.Fatal().Msgf("Could not generate token\n")
		}
		serverOptions.Token = hex.EncodeToString(b)
		// Вывести сгенерированный токен в консоль
		gologger.Info().Msgf("Client Token: %s\n", serverOptions.Token)
	}

	// Создание шифрованного пространства в оперативной памяти сервера для хранения информации о вх. подключениях
	store := storage.New(time.Duration(cliServerOptions.Eviction) * time.Hour * 24)
	serverOptions.Storage = store
	// Если RootTLD включен, создайте одноэлементную незашифрованную запись в хранилище (If RootTLD is enabled create a singleton unencrypted record in the store).
	// Установить ID шифруемого пространства равным значению аргумента Domain
	if serverOptions.RootTLD {
		_ = store.SetID(serverOptions.Domain)
	}

	//// Создать доверенное хранилище для ACME клиента
	//acmeStore := acme.NewProvider()

	// Указать в настройках сервера "указатель" на созданное хранилище
	//serverOptions.ACMEStore = acmeStore

	// Создать GO-рутины с DNS серверами, поддерживающими взаимодействия по TCP, UDP протоколам
	dnsTcpServer := server.NewDNSServer("tcp", serverOptions)
	dnsUdpServer := server.NewDNSServer("udp", serverOptions)
	dnsTcpAlive := make(chan bool, 1)
	dnsUdpAlive := make(chan bool, 1)
	go dnsTcpServer.ListenAndServe(dnsTcpAlive)
	go dnsUdpServer.ListenAndServe(dnsUdpAlive)

	// Отбросить точку на конце в имени домена
	trimmedDomain := strings.TrimSuffix(serverOptions.Domain, ".")

	// Получить сертификат Let’s Encrypt, с помощью протокола ACME
	var tlsConfig *tls.Config
	if !cliServerOptions.SkipAcme && cliServerOptions.Domain != "" {
		// Создание почтового ящика, на который можно отправлять письма, например admin@ooblistener.ru (увидеть их можно при использовании флага -debug)
		cliServerOptions.Hostmaster = fmt.Sprintf("admin@%s", cliServerOptions.Domain)
		// Создать доверенное хранилище для ACME клиента
		acmeStore := acme.NewProvider()
		// Указать в настройках сервера "указатель" на созданное хранилище
		serverOptions.ACMEStore = acmeStore
		acmeTLSManager, acmeErr := acme.HandleWildcardCertificates(fmt.Sprintf("*.%s", trimmedDomain), serverOptions.Hostmaster, acmeStore, cliServerOptions.Debug)
		if acmeErr != nil {
			gologger.Error().Msgf("An error occurred while applying for an certificate, error: %v", acmeErr)
			gologger.Error().Msgf("Could not generate certs for auto TLS, https will be disabled")
		} else {
			tlsConfig = acmeTLSManager
		}
	}

	// Создать GO-рутину с HTTP(S) сервером
	httpServer, err := server.NewHTTPServer(serverOptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create HTTP server")
	}
	httpAlive := make(chan bool)
	httpsAlive := make(chan bool)
	go httpServer.ListenAndServe(tlsConfig, httpAlive, httpsAlive)

	// Создать GO-рутину с SMTP сервером
	// Создать GO-рутину с SMTP сервером
	smtpServer, err := server.NewSMTPServer(serverOptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create SMTP server")
	}
	smtpAlive := make(chan bool)
	smtpsAlive := make(chan bool)
	smtpsAutoTlsAlive := make(chan bool)
	go smtpServer.ListenAndServe(tlsConfig, smtpAlive, smtpsAlive, smtpsAutoTlsAlive)

	// Вывод информации о запущенных процессах
	gologger.Info().Msgf("Running services:\n")
	go func() {
		for {
			service := ""
			network := ""
			port := 0
			status := true
			fatal := false
			select {
			case status = <-dnsUdpAlive:
				service = "DNS"
				network = "UDP"
				port = serverOptions.DnsPort
				fatal = true
			case status = <-dnsTcpAlive:
				service = "DNS"
				network = "TCP"
				port = serverOptions.DnsPort
			case status = <-httpAlive:
				service = "HTTP"
				network = "TCP"
				port = serverOptions.HttpPort
				fatal = true
			case status = <-httpsAlive:
				service = "HTTPS"
				network = "TCP"
				port = serverOptions.HttpsPort
			case status = <-smtpAlive:
				service = "SMTP (no TLS)"
				network = "TCP"
				port = serverOptions.SmtpPort
			case status = <-smtpsAlive:
				service = "SMTPS (only TLS)"
				network = "TCP"
				port = serverOptions.SmtpsPort
			case status = <-smtpsAutoTlsAlive:
				service = "SMTP(S) (STARTTLS)"
				network = "TCP"
				port = serverOptions.SmtpAutoTLSPort
			}
			// Завершение работы в случае возникновения критических сбоев ПО
			if status {
				gologger.Silent().Msgf("[%s] Listening on %s %s:%d", service, network, serverOptions.ListenIP, port)
			} else if fatal {
				gologger.Fatal().Msgf("The %s %s service has unexpectedly stopped", network, service)
			} else {
				gologger.Warning().Msgf("The %s %s service has unexpectedly stopped", network, service)
			}
		}
	}()

	// Завершение приложения при нажатии на Ctrl+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		os.Exit(1)
	}
}

// Функция определения публичного IPv4 адреса
func getPublicIP() string {
	url := "https://api.ipify.org?format=text" // we are using a pulib IP API, we're using ipify here, below are some others

	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(ip)
}
