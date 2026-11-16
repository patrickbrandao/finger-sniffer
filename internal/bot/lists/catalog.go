package lists

import (
	"fmt"
	"strings"
)

// Formatos dos arquivos baixados (um parser por formato, parse.go).
const (
	FormatGoogle     = "google"     // {"prefixes":[{"ipv4Prefix":..}|{"ipv6Prefix":..}]} (Google, Bing, Apple, OpenAI, DuckDuckGo)
	FormatAWS        = "aws"        // ip-ranges.json da AWS
	FormatAzure      = "azure"      // Service Tags da Azure (página de download ou o JSON semanal)
	FormatOracle     = "oracle"     // public_ip_ranges.json da Oracle Cloud
	FormatCSV        = "csv"        // primeira coluna é o prefixo (DigitalOcean geo feed)
	FormatCloudflare = "cloudflare" // API /client/v4/ips da Cloudflare
	FormatJA4DB      = "ja4db"      // ja4db da FoxIO
)

// Usos de uma lista de IP (ADR 0050 item 3).
const (
	KindGoodBot = "good_bot" // robô verificável
	KindCloud   = "ip_cloud" // nuvem ou datacenter
	KindJA4DB   = "ja4db"
)

// JA4DBName é o nome da ja4db no catálogo.
const JA4DBName = "ja4db"

// JA4DBDefaultURL é o padrão de FS_BOT_JA4DB_URL (ADR 0056 item 1).
const JA4DBDefaultURL = "https://ja4db.com/api/read/"

// Source é uma lista do catálogo fixo (ADR 0050 item 3); a URL é trocável por FS_BOT_LIST_<NOME>_URL.
type Source struct {
	Name   string
	URL    string
	Format string
	Kind   string
	// Robot é o robô de uma lista good_bot (o nome do crawler da tabela de UA, spec 018 RF-06).
	Robot string
}

// Catalog é o catálogo fixo das listas de IP, na ordem de atualização. Lista nova exige mudança de código.
var Catalog = []Source{
	{Name: "googlebot", URL: "https://developers.google.com/static/search/apis/ipranges/googlebot.json", Format: FormatGoogle, Kind: KindGoodBot, Robot: "googlebot"},
	{Name: "google_special_crawlers", URL: "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json", Format: FormatGoogle, Kind: KindGoodBot, Robot: "googlebot"},
	{Name: "google_user_triggered", URL: "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json", Format: FormatGoogle, Kind: KindGoodBot, Robot: "googlebot"},
	{Name: "bingbot", URL: "https://www.bing.com/toolbox/bingbot.json", Format: FormatGoogle, Kind: KindGoodBot, Robot: "bingbot"},
	{Name: "applebot", URL: "https://search.developer.apple.com/applebot.json", Format: FormatGoogle, Kind: KindGoodBot, Robot: "applebot"},
	{Name: "openai_gptbot", URL: "https://openai.com/gptbot.json", Format: FormatGoogle, Kind: KindGoodBot, Robot: "gptbot"},
	{Name: "openai_searchbot", URL: "https://openai.com/searchbot.json", Format: FormatGoogle, Kind: KindGoodBot, Robot: "oai-searchbot"},
	{Name: "duckduckbot", URL: "https://duckduckgo.com/duckduckbot.json", Format: FormatGoogle, Kind: KindGoodBot, Robot: "duckduckbot"},
	{Name: "aws", URL: "https://ip-ranges.amazonaws.com/ip-ranges.json", Format: FormatAWS, Kind: KindCloud},
	{Name: "gcp", URL: "https://www.gstatic.com/ipranges/cloud.json", Format: FormatGoogle, Kind: KindCloud},
	{Name: "azure", URL: "https://www.microsoft.com/en-us/download/details.aspx?id=56519", Format: FormatAzure, Kind: KindCloud},
	{Name: "oracle", URL: "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", Format: FormatOracle, Kind: KindCloud},
	{Name: "digitalocean", URL: "https://digitalocean.com/geo/google.csv", Format: FormatCSV, Kind: KindCloud},
	{Name: "cloudflare", URL: "https://api.cloudflare.com/client/v4/ips", Format: FormatCloudflare, Kind: KindCloud},
}

// EnvKey é a variável que troca a URL da lista (FS_BOT_LIST_<NOME>_URL).
func EnvKey(name string) string { return fmt.Sprintf("FS_BOT_LIST_%s_URL", strings.ToUpper(name)) }

// robotSuffixes são os sufixos de DNS reverso aceitos por robô (ADR 0050 item 4). Robô sem sufixo publicado
// (GPTBot, OAI-SearchBot, DuckDuckBot) é verificado só pela lista de IP: a verificação por DNS dá "unknown".
var robotSuffixes = map[string][]string{
	"googlebot": {"googlebot.com", "google.com", "googleusercontent.com"},
	"bingbot":   {"search.msn.com"},
	"applebot":  {"applebot.apple.com"},
}

// Robots lista os robôs do catálogo.
func Robots() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range Catalog {
		if s.Robot != "" && !seen[s.Robot] {
			seen[s.Robot] = true
			out = append(out, s.Robot)
		}
	}
	return out
}
