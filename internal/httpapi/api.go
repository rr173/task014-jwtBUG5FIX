// Package httpapi 提供 JWT 签发验证服务的 HTTP 接口。
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"task014-jwt/internal/jwt"
)

// ErrBadJSON 表示请求体不是单个合法 JSON 对象。
var ErrBadJSON = errors.New("请求体不是合法的单个 JSON 对象")

// API 是 JWT 服务的 HTTP 接口实现。
type API struct {
	secret []byte
	leeway time.Duration
	now    func() time.Time
}

// New 创建使用给定密钥与容差的服务实例，时钟为系统当前时刻。
func New(secret []byte, leeway time.Duration) *API {
	return &API{secret: secret, leeway: leeway, now: time.Now}
}

// NewWithClock 创建服务实例并使用指定时钟，便于自测。
func NewWithClock(secret []byte, leeway time.Duration, now func() time.Time) *API {
	return &API{secret: secret, leeway: leeway, now: now}
}

// Handler 返回 HTTP 路由。
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("POST /sign", a.sign)
	mux.HandleFunc("POST /verify", a.verify)
	return mux
}

func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return ErrBadJSON
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrBadJSON, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return ErrBadJSON
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type signRequest struct {
	Claims jwt.Claims `json:"claims"`
}

func (a *API) sign(w http.ResponseWriter, r *http.Request) {
	var req signRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "status": http.StatusBadRequest})
		return
	}
	// 调用方未提供签发时间时，由服务按当前时刻补填。
	if req.Claims.IssuedAt == nil {
		t := a.now()
		req.Claims.IssuedAt = &t
	}
	token, err := jwt.Sign(req.Claims, a.secret)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "status": http.StatusBadRequest})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token})
}

type verifyRequest struct {
	Token string `json:"token"`
}

func (a *API) verify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "status": http.StatusBadRequest})
		return
	}
	if req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少 token 字段", "status": http.StatusBadRequest})
		return
	}
	v := jwt.Verifier{Secret: a.secret, Leeway: a.leeway, Now: a.now}
	claims, err := v.Verify(req.Token)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "claims": claims})
}
