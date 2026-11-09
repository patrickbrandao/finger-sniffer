package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/patrickbrandao/finger-sniffer/pkg/h1"
	"github.com/patrickbrandao/finger-sniffer/pkg/probe"
)

// Rotas do espelho (spec 005 RF-05).
type routeKind int

const (
	routeStatic    routeKind = iota // arquivo de FS_HTDOCS ou 404
	routeMirror                     // /p/<id>/
	routeControl                    // /r e /p/<id>/r (controles, respond.go)
	routeACME                       // /.well-known/acme-challenge/<token>
	routeBadTarget                  // alvo que não é caminho (authority/asterisk)
)

// acmePrefix é o caminho do desafio HTTP-01 (RFC 8555 §8.3).
const acmePrefix = "/.well-known/acme-challenge/"

// target separa caminho e query do alvo (origin-form ou absolute-form). ok false para authority/asterisk.
func target(rl h1.RequestLine) (path, rawQuery string, ok bool) {
	t := rl.Target
	switch rl.Form {
	case h1.FormOrigin:
	case h1.FormAbsolute:
		_, rest, _ := strings.Cut(t, "://")
		i := strings.IndexAny(rest, "/?")
		if i < 0 {
			return "/", "", true
		}
		t = rest[i:]
		if t[0] == '?' {
			t = "/" + t
		}
	default:
		return "", "", false
	}
	if i := strings.IndexByte(t, '#'); i >= 0 {
		t = t[:i]
	}
	path, rawQuery, _ = strings.Cut(t, "?")
	return path, rawQuery, true
}

// classify decide a rota pelo caminho.
func classify(path string) routeKind {
	switch {
	case path == "/r":
		return routeControl
	case strings.HasPrefix(path, acmePrefix):
		return routeACME
	}
	if rest, ok := strings.CutPrefix(path, "/p/"); ok {
		id, sub, slash := strings.Cut(rest, "/")
		if probe.Valid(id) && slash {
			switch sub {
			case "":
				return routeMirror
			case "r":
				return routeControl
			}
		}
	}
	return routeStatic
}

// route escolhe e monta a resposta da requisição.
func (s *h1Session) route(req *h1.Request, probeID string) response {
	path, rawQuery, ok := target(req.RequestLine)
	kind := routeBadTarget
	if ok {
		kind = classify(path)
	}
	switch kind {
	case routeMirror:
		return s.mirror(req, probeID, rawQuery)
	case routeControl:
		return s.control(req, probeID, rawQuery)
	case routeACME:
		return s.acme(req, strings.TrimPrefix(path, acmePrefix))
	case routeStatic:
		return s.c.srv.static.serve(req.RequestLine.Method, path)
	default:
		if req.RequestLine.Method == http.MethodConnect {
			// O espelho não é proxy: CONNECT recebe 405 (e fica registrado como sinal no evento).
			r := textResponse(http.StatusMethodNotAllowed, "this server is not a proxy\n")
			r.head.Fields = append(r.head.Fields, h1.HeaderField{Name: "Allow", Value: "GET, HEAD"})
			return r
		}
		return textResponse(http.StatusBadRequest, "unsupported request target\n")
	}
}

// mirror é a resposta padrão de /p/<id>/ (RF-06): conn_id e índice da requisição, ou o JSON da
// própria requisição com ?inline=1.
func (s *h1Session) mirror(req *h1.Request, probeID, rawQuery string) response {
	q, _ := url.ParseQuery(rawQuery)
	body, contentType := s.mirrorBody(req, probeID, q.Get("inline") == "1")
	r := textResponse(http.StatusOK, body)
	r.head.Fields[0].Value = contentType
	if req.RequestLine.Method == http.MethodHead {
		headOnly(r.head)
	}
	return r
}

// acme responde o desafio HTTP-01 pelo gancho (task 027); sem gancho ou token desconhecido, 404.
func (s *h1Session) acme(req *h1.Request, token string) response {
	if f := s.c.srv.deps.ACME; f != nil && token != "" && !strings.Contains(token, "/") {
		if body, ok := f(token); ok {
			r := textResponse(http.StatusOK, string(body))
			r.head.Fields = r.head.Fields[:1]
			r.head.Fields[0].Value = "application/octet-stream"
			if req.RequestLine.Method == http.MethodHead {
				headOnly(r.head)
			}
			return r
		}
	}
	return textResponse(http.StatusNotFound, "404 not found\n")
}

// headOnly transforma a resposta em resposta a HEAD: mesmo Content-Length, sem corpo.
func headOnly(r *h1.Response) {
	if r.Framing == h1.FramingContentLength {
		r.Fields = append(r.Fields, h1.HeaderField{Name: "Content-Length", Value: fmt.Sprint(r.BodyLen)})
	}
	r.Framing = h1.FramingNone
	r.BodyLen = 0
}
