package web

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
)

// staticTypes é a lista fechada de extensões servidas e o Content-Type de cada uma (spec 014 RF-01). Tabela
// fixa em vez de mime.TypeByExtension, que depende do /etc/mime.types da máquina.
var staticTypes = map[string]string{
	".html":  "text/html; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".json":  "application/json",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".webp":  "image/webp",
	".ico":   "image/x-icon",
	".woff2": "font/woff2",
	".txt":   "text/plain; charset=utf-8",
}

// maxStaticFile limita o arquivo servido (o site é pequeno; nada dinâmico).
const maxStaticFile = 16 << 20

// static serve os arquivos de FS_HTDOCS: sem listagem de diretório, sem "..", sem arquivos ocultos, só as
// extensões da lista, index.html para diretórios. O acesso passa por os.Root, que também barra links
// simbólicos para fora da pasta.
type static struct {
	root string
}

// resolve converte o caminho da URL no nome relativo dentro de htdocs. ok false = 404.
func resolve(urlPath string) (string, bool) {
	p, err := url.PathUnescape(urlPath)
	if err != nil || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\\") {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		// ".." (e ocultos, como .git) nunca são servidos, mesmo que path.Clean os resolvesse.
		if strings.HasPrefix(seg, ".") {
			return "", false
		}
	}
	name := strings.TrimPrefix(path.Clean(p), "/")
	if strings.HasSuffix(p, "/") || name == "" {
		name = path.Join(name, "index.html")
	}
	return name, true
}

// serve monta a resposta de GET/HEAD para o caminho.
func (st *static) serve(method, urlPath string) response {
	if method != http.MethodGet && method != http.MethodHead {
		r := textResponse(http.StatusMethodNotAllowed, "405 method not allowed\n")
		r.head.Fields = append(r.head.Fields, h1.HeaderField{Name: "Allow", Value: "GET, HEAD"})
		return r
	}
	name, ok := resolve(urlPath)
	if !ok {
		return notFound()
	}
	root, err := os.OpenRoot(st.root)
	if err != nil {
		return notFound()
	}
	defer func() { _ = root.Close() }()
	f, info, ok := openFile(root, name)
	if !ok {
		return notFound()
	}
	ctype, ok := staticTypes[strings.ToLower(path.Ext(info.Name()))]
	if !ok || info.Size() > maxStaticFile {
		_ = f.Close()
		return notFound()
	}
	head := &h1.Response{
		Status:  http.StatusOK,
		Fields:  []h1.HeaderField{{Name: "Content-Type", Value: ctype}, {Name: "Cache-Control", Value: "no-cache"}},
		Framing: h1.FramingContentLength,
		BodyLen: info.Size(),
	}
	if method == http.MethodHead {
		_ = f.Close()
		head.Fields = append(head.Fields, h1.HeaderField{Name: "Content-Length", Value: strconv.FormatInt(info.Size(), 10)})
		head.Framing, head.BodyLen = h1.FramingNone, 0
		return response{head: head}
	}
	return response{head: head, body: io.Reader(f), closer: f}
}

// openFile abre name dentro de root; um diretório vira o index.html dele (sem listagem).
func openFile(root *os.Root, name string) (*os.File, os.FileInfo, bool) {
	for range 2 {
		f, err := root.Open(name)
		if err != nil {
			return nil, nil, false
		}
		info, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, nil, false
		}
		if !info.IsDir() {
			if !info.Mode().IsRegular() {
				_ = f.Close()
				return nil, nil, false
			}
			return f, info, true
		}
		_ = f.Close()
		name = path.Join(name, "index.html")
	}
	return nil, nil, false
}

func notFound() response { return textResponse(http.StatusNotFound, "404 not found\n") }
