package handler

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRenderHTML_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	tmpl := template.Must(template.New("ok").Parse(`hello {{.Name}}`))
	renderHTML(c, http.StatusOK, tmpl, struct{ Name string }{Name: "world"}, map[string]string{
		"Content-Type": "text/plain; charset=utf-8",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Body.String(); got != "hello world" {
		t.Fatalf("body = %q, want %q", got, "hello world")
	}
	if got := w.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want %q", got, "text/plain; charset=utf-8")
	}
}

func TestRenderHTML_TemplateError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	tmpl := template.Must(template.New("boom").Funcs(template.FuncMap{
		"boom": func() (string, error) {
			return "", errors.New("boom")
		},
	}).Parse(`{{boom}}`))

	renderHTML(c, http.StatusOK, tmpl, nil, nil)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if body := w.Body.String(); body == "" {
		t.Fatal("expected error response body")
	}
}
