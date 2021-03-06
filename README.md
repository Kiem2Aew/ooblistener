<h1 align="center">
  <br>
<img src="https://user-images.githubusercontent.com/8293321/150756129-df9990c2-cdc0-4c6e-b3ae-3d17079968c5.png" width="200px" alt="ooblistener"></a>
</h1>
<h4 align="center">An OOB interaction gathering server and client library</h4>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://github.com/Kiem2Aew/ooblistener/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://goreportcard.com/badge/github.com/Kiem2Aew/ooblistener"><img src="https://goreportcard.com/badge/github.com/Kiem2Aew/ooblistener"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#usage">Usage</a> •
  <a href="#ooblistener-client">ooblistener Client</a> •
  <a href="#ooblistener-server">ooblistener Server</a> •
  <a href="#ooblistener-integration">ooblistener Integration</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>

---

**ooblistener** is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions.

# Features

- DNS/HTTP(S)/SMTP(S)/LDAP Interaction support
- NTLM/SMB/FTP/RESPONDER Listener support **(self-hosted)**
- Wildcard Interaction support **(self-hosted)**
- CLI / Web / Burp / ZAP / Docker client support
- Self hosted ooblistener server support
- AES encryption with zero logging
- Automatic ACME based Wildcard TLS w/ Auto Renewal
- DNS Entries for Cloud Metadata service

# ooblistener Client

## Usage

```sh
ooblistener-client -h
```

This will display help for the tool. Here are all the switches it supports.

```yaml
Usage:
  ./ooblistener-client [flags]

Flags:
INPUT:
   -s, -server string  ooblistener server(s) to use (default "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me")

CONFIG:
   -n, -number int          number of ooblistener payload to generate (default 1)
   -t, -token string        authentication token to connect protected ooblistener server
   -pi, -poll-interval int  poll interval in seconds to pull interaction data (default 5)
   -nf, -no-http-fallback   disable http fallback registration
   -persist                 enables persistent ooblistener sessions

FILTER:
   -dns-only   display only dns interaction in CLI output
   -http-only  display only http interaction in CLI output
   -smtp-only  display only smtp interactions in CLI output

OUTPUT:
   -o string  output file to write interaction data
   -json      write output in JSONL(ines) format
   -v         display verbose interaction
```

## ooblistener CLI Client

ooblistener Cli client requires **go1.17+** to install successfully. Run the following command to get the repo - 

```sh
go install -v github.com/Kiem2Aew/ooblistener/cmd/ooblistener-client@latest
```

### Default Run

This will generate a unique payload that can be used for OOB testing with minimal interaction information in the ouput.

```console
ooblistener-client

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v0.0.5

        projectdiscovery.io

[INF] Listing 1 payload for OOB Testing
[INF] c23b2la0kl1krjcrdj10cndmnioyyyyyn.oast.pro

[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (A) from 172.253.226.100 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (AAAA) from 32.3.34.129 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received HTTP interaction from 43.22.22.50 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (MX) from 43.3.192.3 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (TXT) from 74.32.183.135 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received SMTP interaction from 32.85.166.50 at 2021-26-26 12:26
```

### Verbose Mode


Running the `ooblistener-client` in **verbose mode** (v) to see the whole request and response, along with an output file to analyze afterwards.

```console
ooblistener-client -v -o ooblistener-logs.txt

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v1.0.0

    projectdiscovery.io

[INF] Listing 1 payload for OOB Testing
[INF] c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro

[c58bduhe008dovpvhvugcfemp9yyyyyyn] Received HTTP interaction from 103.22.142.211 at 2021-09-26 18:08:07
------------
HTTP Request
------------

GET /favicon.ico HTTP/2.0
Host: c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro
Referer: https://c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36


-------------
HTTP Response
-------------

HTTP/1.1 200 OK
Connection: close
Content-Type: text/html; charset=utf-8
Server: oast.pro

<html><head></head><body>nyyyyyy9pmefcguvhvpvod800ehudb85c</body></html>
```

### Using Self-Hosted server

Using the `server` flag, `ooblistener-client` can be configured to connect with a self-hosted ooblistener server, this flag accepts single or multiple server separated by comma.

```sh
ooblistener-client -server hackwithautomation.com
```

We maintain a list of default ooblistener servers to use with `ooblistener-client`:

- oast.pro
- oast.live
- oast.site
- oast.online
- oast.fun
- oast.me

Default servers are subject to change/rotate/down at any time, thus we recommend using a self-hosted ooblistener server if you are experiencing issues with the default server.

### Using Protected Self-Hosted server

Using the `token` flag, `ooblistener-client` can connect to a self-hosted ooblistener server that is protected with authentication.

```sh
ooblistener-client -server hackwithautomation.com -token XXX
```

### Using with Notify

If you are away from your terminal, you may use [notify](https://github.com/projectdiscovery/notify) to send a real-time interaction notification to any supported platform.

```sh
ooblistener-client | notify
```

![image](https://user-images.githubusercontent.com/8293321/116283535-9bcac180-a7a9-11eb-94d5-0313d4812fef.png)


## ooblistener Web Client

[ooblistener-web](https://github.com/Kiem2Aew/ooblistener-web) is a free and open-source web client that displays ooblistener interactions in a well-managed dashboard in your browser. It uses the browser's local storage to store and display all incoming interactions. By default, the web client is configured to use **interact.sh** as default ooblistener server, and supports other self-hosted public/authencaited ooblistener servers as well.

A hosted instance of **ooblistener-web** client is available at https://app.ooblistener.com

<img width="2032" alt="ooblistener-web" src="https://user-images.githubusercontent.com/8293321/136621531-d72c9ece-0076-4db1-98c9-21dcba4ba09c.png">

## ooblistener Docker Client

A [Docker image](https://hub.docker.com/r/ooblistener-client) is also provided with ooblistener client that is ready to run and can be used in the following way:

```sh
docker run ooblistener-client:latest
```

```console
docker run ooblistener-client:latest

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v1.0.0

        projectdiscovery.io

[INF] Listing 1 payload for OOB Testing
[INF] c59e3crp82ke7bcnedq0cfjqdpeyyyyyn.oast.pro
```

## Burp Suite Extension

[ooblistener-collaborator](https://github.com/wdahlenburg/ooblistener-collaborator) is Burp Suite extension developed and maintained by [@wdahlenb](https://twitter.com/wdahlenb)

- Download latest JAR file from [releases](https://github.com/wdahlenburg/ooblistener-collaborator/releases) page.
- Open Burp Suite &rarr; Extender &rarr; Add &rarr; Java &rarr; Select JAR file &rarr; Next
- New tab named **ooblistener** will be appeared upon successful installation.
- See the [ooblistener-collaborator](https://github.com/wdahlenburg/ooblistener-collaborator) project for more info.

<img width="2032" alt="burp" src="https://user-images.githubusercontent.com/8293321/135176099-0e3fa01c-bdce-4f04-a94f-de0a34c7abf6.png">

## OWASP ZAP Add-On

ooblistener can be used with OWASP ZAP via the [OAST add-on for ZAP](https://www.zaproxy.org/docs/desktop/addons/oast-support/). With ZAP's scripting capabilities, you can create powerful out-of-band scan rules that leverage ooblistener's features. A standalone script template has been provided as an example (it is added automatically when you install the add-on).

- Install the OAST add-on from the [ZAP Marketplace](https://www.zaproxy.org/addons/).
- Go to Tools &rarr; Options &rarr; OAST and select **ooblistener**.
- Configure [the options](https://www.zaproxy.org/docs/desktop/addons/oast-support/services/ooblistener/options/) for the client and click on "New Payload" to generate a new payload.
- OOB interactions will appear in the [OAST Tab](https://www.zaproxy.org/docs/desktop/addons/oast-support/tab/) and you can click on any of them to view the full request and response.
- See the [OAST add-on documentation](https://www.zaproxy.org/docs/desktop/addons/oast-support/) for more info.

![zap](https://user-images.githubusercontent.com/16446369/135211920-ed24ba5a-5547-4cd4-b6d8-656af9592c20.png)

-------


# ooblistener Server

ooblistener server runs multiple services and captures all the incoming requests. To host an instance of ooblistener-server, you are required to have the follow requirements:

1. Domain name with custom **host names** and **nameservers**.
2. Basic droplet running 24/7 in the background.

# Usage

```sh
ooblistener-server -h
```

This will display help for the tool. Here are all the switches it supports.

```yaml
Usage:
  ./ooblistener-server [flags]

Flags:
INPUT:
   -d, -domain string       configured domain to use with ooblistener server
   -ip string               public ip address to use for ooblistener server
   -lip, -listen-ip string  public ip address to listen on (default "0.0.0.0")
   -e, -eviction int        number of days to persist interaction data in memory (default 30)
   -a, -auth                enable authentication to server using random generated token
   -t, -token string        enable authentication to server using given token
   -acao-url string         origin url to send in acao header (required to use web-client) (default "https://app.ooblistener.com")
   -sa, -skip-acme          skip acme registration (certificate checks/handshake + TLS protocols will be disabled)

SERVICES:
   -dns-port int           port to use for dns service (default 53)
   -http-port int          port to use for http service (default 80)
   -https-port int         port to use for https service (default 443)
   -smtp-port int          port to use for smtp service (default 25)
   -smtps-port int         port to use for smtps service (default 587)
   -smtp-autotls-port int  port to use for smtps autotls service (default 465)
   -ldap-port int          port to use for ldap service (default 389)
   -ldap                   enable ldap server with full logging (authenticated)
   -wc, -wildcard          enable wildcard interaction for ooblistener domain (authenticated)
   -smb                    start smb agent - impacket and python 3 must be installed (authenticated)
   -responder              start responder agent - docker must be installed (authenticated)
   -ftp                    start ftp agent (authenticated)
   -smb-port int           port to use for smb service (default 445)
   -ftp-port int           port to use for ftp service (default 21)
   -ftp-dir string         ftp directory - temporary if not specified

DEBUG:
   -debug  start ooblistener server in debug mode
```

We are using GoDaddy for domain name and DigitalOcean droplet for the server, a basic $5 droplet should be sufficient to run self-hosted ooblistener server. If you are not using GoDaddy, follow your registrar's process for creating / updating DNS entries.

<table>
<td>

## Configuring ooblistener domain

- Navigate to `https://dcc.godaddy.com/manage/{{domain}}/dns/hosts`
- Advanced Features &rarr; Host names &rarr; Add &rarr; Submit `ns1`, `ns2` with your `SERVER_IP` as value

<img width="1288" alt="gdd-hostname" src="https://user-images.githubusercontent.com/8293321/135175512-135259fb-0490-4038-845a-0b62b1b8f549.png">

- Navigate to `https://dns.godaddy.com/{{domain}}/nameservers`
- I'll use my own nameservers &rarr; Submit `ns1.INTERACTSH_DOMAIN`, `ns2.INTERACTSH_DOMAIN`

<img width="1288" alt="gdd-ns" src="https://user-images.githubusercontent.com/8293321/135175627-ea9639fd-353d-441b-a9a4-dae7f540d0ae.png">

</td>
</table>

<table>
<td>

## Configuring ooblistener server

Install `ooblistener-server` on your **VPS**

```bash
go install -v github.com/Kiem2Aew/ooblistener/cmd/ooblistener-server@latest
```

Considering domain name setup is **completed**, run the below command to run `ooblistener-server`

```bash
ooblistener-server -domain INTERACTSH_DOMAIN
```

Following is an example of a successful installation and operation of a self-hosted server:

![ooblistener-server](https://user-images.githubusercontent.com/8293321/150676089-b5638c19-33a3-426a-987c-3ac6fa227012.png)

A number of needed flags are configured automatically to run `ooblistener-server` with default settings. For example, `ip` and `listen-ip` flags set with the Public IP address of the system when possible.

</td>
</table>

## Running ooblistener Server

```console
ooblistener-server -domain interact.sh

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v1.0.0

                projectdiscovery.io

[INF] Listening with the following services:
[HTTPS] Listening on TCP 46.101.25.250:443
[HTTP] Listening on TCP 46.101.25.250:80
[SMTPS] Listening on TCP 46.101.25.250:587
[LDAP] Listening on TCP 46.101.25.250:389
[SMTP] Listening on TCP 46.101.25.250:25
[DNS] Listening on TCP 46.101.25.250:53
[DNS] Listening on UDP 46.101.25.250:53
```

There are more useful capabilities supported by `ooblistener-server` that are not enabled by default and are intended to be used only by **self-hosted** servers.

## Wildcard Interaction

To enable `wildcard` interaction for configured ooblistener domain `wildcard` flag can be used with implicit authentication protection via the `auth` flag if the `token` flag is omitted.

```console
ooblistener-server -domain hackwithautomation.com -wildcard

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v1.0.0

        projectdiscovery.io

[INF] Client Token: 699c55544ce1604c63edb769e51190acaad1f239589a35671ccabd664385cfc7
[INF] Listening with the following services:
[HTTPS] Listening on TCP 157.230.223.165:443
[HTTP] Listening on TCP 157.230.223.165:80
[SMTPS] Listening on TCP 157.230.223.165:587
[LDAP] Listening on TCP 157.230.223.165:389
[SMTP] Listening on TCP 157.230.223.165:25
[DNS] Listening on TCP 157.230.223.165:53
[DNS] Listening on UDP 157.230.223.165:53
```

## LDAP Interaction

As default, ooblistener server support LDAP interaction for the payload included in [search query](https://ldapwiki.com/wiki/LDAP%20Query%20Examples), additionally `ldap` flag can be used for complete logging.

```console
ooblistener-server -domain hackwithautomation.com -sa -ldap

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v1.0.0

        projectdiscovery.io

[INF] Client Token: deb58fc151e6f0e53d448be3eb14cd7a11590d8950d142b9cd1abac3c2e3e7bc
[INF] Listening with the following services:
[DNS] Listening on UDP 157.230.223.165:53
[LDAP] Listening on TCP 157.230.223.165:389
[HTTP] Listening on TCP 157.230.223.165:80
[SMTP] Listening on TCP 157.230.223.165:25
[DNS] Listening on TCP 157.230.223.165:53
```

# ooblistener Integration

### Nuclei - OAST

[Nuclei](https://github.com/projectdiscovery/nuclei) vulnerability scanner utilize **ooblistener** for automated payload generation and detection of out of band based security vulnerabilities.

See [Nuclei + ooblistener](https://blog.projectdiscovery.io/nuclei-ooblistener-integration/) Integration blog and [guide document](https://nuclei.projectdiscovery.io/templating-guide/ooblistener/) for more information.

# Cloud Metadata

ooblistener server supports DNS records for cloud metadata services, which is useful for testing SSRF-related vulnerabilities.

Currently supported metadata services:

- [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [Alibaba](https://www.alibabacloud.com/blog/alibaba-cloud-ecs-metadata-user-data-and-dynamic-data_594351)

Example:

* **aws.interact.sh** points to 169.254.169.254
* **alibaba.interact.sh** points to 100.100.100.200

-----

### Acknowledgement

ooblistener is inspired from [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator).

### License

ooblistener is distributed under [MIT License](https://github.com/Kiem2Aew/ooblistener/blob/master/LICENSE.md) and made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team.# ooblistener
