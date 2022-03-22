package options

import "github.com/Kiem2Aew/ooblistener/pkg/server"

type CLIServerOptions struct {
	Debug           bool
	Domain          string
	DnsPort         int
	IPAddress       string
	ListenIP        string
	HttpPort        int
	HttpsPort       int
	Hostmaster      string
	Eviction        int
	SmtpPort        int
	SmtpsPort       int
	SmtpAutoTLSPort int
	Auth            bool
	Token           string
	OriginURL       string
	RootTLD         bool
	SkipAcme        bool
}

func (cliServerOptions *CLIServerOptions) AsServerOptions() *server.Options {
	return &server.Options{
		Domain:          cliServerOptions.Domain,
		DnsPort:         cliServerOptions.DnsPort,
		IPAddress:       cliServerOptions.IPAddress,
		ListenIP:        cliServerOptions.ListenIP,
		HttpPort:        cliServerOptions.HttpPort,
		HttpsPort:       cliServerOptions.HttpsPort,
		Hostmaster:      cliServerOptions.Hostmaster,
		SmtpPort:        cliServerOptions.SmtpPort,
		SmtpsPort:       cliServerOptions.SmtpsPort,
		SmtpAutoTLSPort: cliServerOptions.SmtpAutoTLSPort,
		Auth:            cliServerOptions.Auth,
		Token:           cliServerOptions.Token,
		OriginURL:       cliServerOptions.OriginURL,
		RootTLD:         cliServerOptions.RootTLD,
	}
}
