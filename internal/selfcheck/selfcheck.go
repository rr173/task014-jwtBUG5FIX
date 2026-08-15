package selfcheck

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"task014-jwt/internal/httpapi"
)

const smokeSecret = "smoke-secret-key"
const smokeLeeway = 5 * time.Second

// clock 是可控时钟，便于精确测试过期/生效边界。
type clock struct {
	mu sync.RWMutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.RLock(); defer c.mu.RUnlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

func Run() int {
	passed, failed := 0, 0
	check := func(name string, fn func() error) {
		if err := fn(); err != nil {
			failed++
			fmt.Printf("FAIL %-32s %v\n", name, err)
		} else {
			passed++
			fmt.Printf("PASS %s\n", name)
		}
	}

	clk := &clock{t: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
	api := httpapi.NewWithClock([]byte(smokeSecret), smokeLeeway, clk.now)
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	do := func(method, path, body string) (*http.Response, []byte, error) {
		var r io.Reader
		if body != "" {
			r = bytes.NewReader([]byte(body))
		}
		req, err := http.NewRequest(method, srv.URL+path, r)
		if err != nil {
			return nil, nil, err
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, nil, err
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, data, readErr
	}

	signBody := func(claims map[string]any) string {
		b, _ := json.Marshal(map[string]any{"claims": claims})
		return string(b)
	}

	sign := func(claims map[string]any) (string, error) {
		resp, body, err := do(http.MethodPost, "/sign", signBody(claims))
		if err != nil {
			return "", err
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("sign status=%d body=%s", resp.StatusCode, body)
		}
		var out struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return "", err
		}
		return out.Token, nil
	}

	verifyReq := func(token string) (bool, map[string]any, string, int) {
		b, _ := json.Marshal(map[string]any{"token": token})
		resp, body, _ := do(http.MethodPost, "/verify", string(b))
		var out struct {
			Valid  bool           `json:"valid"`
			Claims map[string]any `json:"claims"`
			Error  string         `json:"error"`
		}
		_ = json.Unmarshal(body, &out)
		return out.Valid, out.Claims, out.Error, resp.StatusCode
	}

	check("健康检查", func() error {
		resp, _, err := do(http.MethodGet, "/healthz", "")
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status=%d", resp.StatusCode)
		}
		return nil
	})

	var standardToken string
	check("签发并验证标准令牌", func() error {
		tok, err := sign(map[string]any{
			"iss": "issuer", "sub": "alice", "aud": "aud-1", "jti": "id-1",
			"exp": clk.now().Unix() + 3600,
		})
		if err != nil {
			return err
		}
		standardToken = tok
		valid, claims, errMsg, status := verifyReq(tok)
		if status != http.StatusOK || !valid {
			return fmt.Errorf("status=%d valid=%v err=%s", status, valid, errMsg)
		}
		if claims["sub"] != "alice" || claims["iss"] != "issuer" {
			return fmt.Errorf("standard claims lost: %+v", claims)
		}
		return nil
	})

	check("自定义声明原样透传", func() error {
		tok, err := sign(map[string]any{
			"sub":    "bob",
			"role":   "admin",
			"tier":   3,
			"active": true,
		})
		if err != nil {
			return err
		}
		valid, claims, errMsg, status := verifyReq(tok)
		if status != http.StatusOK || !valid {
			return fmt.Errorf("status=%d valid=%v err=%s", status, valid, errMsg)
		}
		if claims["role"] != "admin" {
			return fmt.Errorf("role lost: %+v", claims)
		}
		if claims["tier"] != float64(3) {
			return fmt.Errorf("tier lost: %+v", claims)
		}
		if claims["active"] != true {
			return fmt.Errorf("active lost: %+v", claims)
		}
		return nil
	})

	check("未提供签发时间由服务补填", func() error {
		tok, err := sign(map[string]any{"sub": "carol"})
		if err != nil {
			return err
		}
		valid, claims, errMsg, status := verifyReq(tok)
		if status != http.StatusOK || !valid {
			return fmt.Errorf("status=%d valid=%v err=%s", status, valid, errMsg)
		}
		iat, ok := claims["iat"]
		if !ok {
			return fmt.Errorf("iat missing: %+v", claims)
		}
		if int64(iat.(float64)) != clk.now().Unix() {
			return fmt.Errorf("iat=%v want=%d", iat, clk.now().Unix())
		}
		return nil
	})

	check("拒绝 alg=none 令牌", func() error {
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		pl := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"evil"}`))
		sig := base64.RawURLEncoding.EncodeToString([]byte("fake"))
		valid, _, errMsg, status := verifyReq(hdr + "." + pl + "." + sig)
		if status != http.StatusOK || valid {
			return fmt.Errorf("none token accepted: status=%d valid=%v err=%s", status, valid, errMsg)
		}
		if !strings.Contains(errMsg, "none") {
			return fmt.Errorf("error should mention none: %s", errMsg)
		}
		return nil
	})

	check("拒绝 alg=none 空签名令牌", func() error {
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		pl := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"evil"}`))
		valid, _, errMsg, status := verifyReq(hdr + "." + pl + ".")
		if status != http.StatusOK || valid {
			return fmt.Errorf("empty-sig none token accepted: status=%d valid=%v err=%s", status, valid, errMsg)
		}
		return nil
	})

	check("篡改载荷签名失配", func() error {
		parts := strings.Split(standardToken, ".")
		parts[1] = parts[1] + "A"
		valid, _, errMsg, status := verifyReq(strings.Join(parts, "."))
		if status != http.StatusOK || valid {
			return fmt.Errorf("tampered token accepted: status=%d valid=%v err=%s", status, valid, errMsg)
		}
		if !strings.Contains(errMsg, "签名") {
			return fmt.Errorf("error should mention signature: %s", errMsg)
		}
		return nil
	})

	check("过期且超出容差判非法", func() error {
		tok, err := sign(map[string]any{"exp": clk.now().Unix() - 100})
		if err != nil {
			return err
		}
		valid, _, errMsg, status := verifyReq(tok)
		if status != http.StatusOK || valid {
			return fmt.Errorf("expired token accepted: status=%d valid=%v err=%s", status, valid, errMsg)
		}
		if !strings.Contains(errMsg, "过期") {
			return fmt.Errorf("error should mention expired: %s", errMsg)
		}
		return nil
	})

	check("过期但在容差内仍合法", func() error {
		tok, err := sign(map[string]any{"exp": clk.now().Unix() - 3})
		if err != nil {
			return err
		}
		valid, _, errMsg, status := verifyReq(tok)
		if status != http.StatusOK || !valid {
			return fmt.Errorf("token within leeway rejected: status=%d valid=%v err=%s", status, valid, errMsg)
		}
		return nil
	})

	check("生效未到且超出容差判非法", func() error {
		tok, err := sign(map[string]any{"nbf": clk.now().Unix() + 100})
		if err != nil {
			return err
		}
		valid, _, errMsg, status := verifyReq(tok)
		if status != http.StatusOK || valid {
			return fmt.Errorf("not-yet-valid token accepted: status=%d valid=%v err=%s", status, valid, errMsg)
		}
		if !strings.Contains(errMsg, "生效") {
			return fmt.Errorf("error should mention not-yet-valid: %s", errMsg)
		}
		return nil
	})

	check("生效未到但在容差内仍合法", func() error {
		tok, err := sign(map[string]any{"nbf": clk.now().Unix() + 3})
		if err != nil {
			return err
		}
		valid, _, errMsg, status := verifyReq(tok)
		if status != http.StatusOK || !valid {
			return fmt.Errorf("nbf within leeway rejected: status=%d valid=%v err=%s", status, valid, errMsg)
		}
		return nil
	})

	check("不同密钥签发的令牌验签失败", func() error {
		// 用另一组实例以不同密钥签发，再由本服务验证。
		other := httpapi.NewWithClock([]byte("other-secret"), smokeLeeway, clk.now)
		otherSrv := httptest.NewServer(other.Handler())
		defer otherSrv.Close()
		b, _ := json.Marshal(map[string]any{"claims": map[string]any{"sub": "spy"}})
		req, _ := http.NewRequest(http.MethodPost, otherSrv.URL+"/sign", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		oResp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		oBody, _ := io.ReadAll(oResp.Body)
		oResp.Body.Close()
		if oResp.StatusCode != http.StatusOK {
			return fmt.Errorf("other sign status=%d body=%s", oResp.StatusCode, oBody)
		}
		var out struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(oBody, &out)
		valid, _, errMsg, status := verifyReq(out.Token)
		if status != http.StatusOK || valid {
			return fmt.Errorf("other-secret token accepted: status=%d valid=%v err=%s", status, valid, errMsg)
		}
		return nil
	})

	check("格式错误令牌判非法", func() error {
		for _, tok := range []string{"not-a-token", "a.b", "a.b.c.d"} {
			valid, _, _, status := verifyReq(tok)
			if status != http.StatusOK || valid {
				return fmt.Errorf("malformed token %q accepted: status=%d valid=%v", tok, status, valid)
			}
		}
		return nil
	})

	check("多段 JSON 请求被拒绝", func() error {
		body := signBody(map[string]any{"sub": "x"}) + " {}"
		resp, _, err := do(http.MethodPost, "/sign", body)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusBadRequest {
			return fmt.Errorf("status=%d", resp.StatusCode)
		}
		return nil
	})

	check("verify 缺 token 字段返回 400", func() error {
		b, _ := json.Marshal(map[string]any{})
		resp, _, err := do(http.MethodPost, "/verify", string(b))
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusBadRequest {
			return fmt.Errorf("status=%d", resp.StatusCode)
		}
		return nil
	})

	fmt.Printf("\n%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}
