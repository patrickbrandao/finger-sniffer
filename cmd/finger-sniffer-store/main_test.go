package main

import (
	"bytes"
	"testing"
)

func TestOpenAPIEmbedded(t *testing.T) {
	// O contrato precisa estar embutido no binário e ser OpenAPI 3.1.
	if !bytes.HasPrefix(openAPISpec, []byte("openapi: 3.1")) {
		t.Fatalf("embedded openapi.yaml missing or not OpenAPI 3.1 (len=%d)", len(openAPISpec))
	}
}
