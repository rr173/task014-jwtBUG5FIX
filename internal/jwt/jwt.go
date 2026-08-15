// Package jwt 实现手工的 HMAC-SHA256（HS256）JSON Web Token 签发与验证。
// 仅使用标准库，不引入任何第三方 JWT 库。
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AlgHS256 是本实现唯一支持的算法声明。
const AlgHS256 = "HS256"

// 校验过程中可能返回的错误。每个错误对应一种独立的失败原因，
// 调用方可通过 errors.Is 精确区分，而不必解析字符串。
var (
	ErrEmptySecret      = errors.New("jwt: 密钥不能为空")
	ErrMalformed        = errors.New("jwt: 令牌格式错误")
	ErrInvalidHeader    = errors.New("jwt: 令牌头部非法")
	ErrAlgNone          = errors.New("jwt: 拒绝 alg 为 none 的令牌")
	ErrAlgNotSupported  = errors.New("jwt: 仅支持 HS256 算法")
	ErrSignatureInvalid = errors.New("jwt: 签名不匹配")
	ErrTokenExpired     = errors.New("jwt: 令牌已过期")
	ErrTokenNotYetValid = errors.New("jwt: 令牌尚未生效")
)

// Claims 表示 JWT 载荷声明。标准字段单独存放以便类型安全访问，
// Extra 承载所有自定义声明，签发与验证后可原样还原。
// 时间类字段以指针表示，缺省即未设置。
type Claims struct {
	Issuer    string
	Subject   string
	Audience  string
	ID        string
	ExpiresAt *time.Time
	NotBefore *time.Time
	IssuedAt  *time.Time
	Extra     map[string]any
}

// 标准声明在 JSON 中的键名。
const (
	keyIss = "iss"
	keySub = "sub"
	keyAud = "aud"
	keyJti = "jti"
	keyExp = "exp"
	keyNbf = "nbf"
	keyIat = "iat"
)

// MarshalJSON 将 Claims 编码为 JWT 载荷 JSON：标准字段使用约定键名，
// 时间字段以自 Unix 纪元起的秒数表示，自定义声明合并进来。
func (c Claims) MarshalJSON() ([]byte, error) {
	m := make(map[string]any)
	for k, v := range c.Extra {
		m[k] = v
	}
	if c.Issuer != "" {
		m[keyIss] = c.Issuer
	}
	if c.Subject != "" {
		m[keySub] = c.Subject
	}
	if c.Audience != "" {
		m[keyAud] = c.Audience
	}
	if c.ID != "" {
		m[keyJti] = c.ID
	}
	if c.ExpiresAt != nil {
		m[keyExp] = c.ExpiresAt.Unix()
	}
	if c.NotBefore != nil {
		m[keyNbf] = c.NotBefore.Unix()
	}
	if c.IssuedAt != nil {
		m[keyIat] = c.IssuedAt.Unix()
	}
	return json.Marshal(m)
}

// UnmarshalJSON 从 JWT 载荷 JSON 还原 Claims：标准字段按约定键名提取，
// 其余键全部放入 Extra。
func (c *Claims) UnmarshalJSON(data []byte) error {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	c.Extra = make(map[string]any, len(m))
	for k, v := range m {
		switch k {
		case keyIss:
			if s, ok := v.(string); ok {
				c.Issuer = s
			}
		case keySub:
			if s, ok := v.(string); ok {
				c.Subject = s
			}
		case keyAud:
			if s, ok := v.(string); ok {
				c.Audience = s
			}
		case keyJti:
			if s, ok := v.(string); ok {
				c.ID = s
			}
		case keyExp:
			t, err := numToDate(v)
			if err != nil {
				return err
			}
			c.ExpiresAt = t
		case keyNbf:
			t, err := numToDate(v)
			if err != nil {
				return err
			}
			c.NotBefore = t
		case keyIat:
			t, err := numToDate(v)
			if err != nil {
				return err
			}
			c.IssuedAt = t
		default:
			c.Extra[k] = v
		}
	}
	return nil
}

// numToDate 将 JSON 还原出的数值（可能是 float64、int64 或 json.Number）
// 解释为 Unix 秒并返回对应的 UTC 时间指针。
func numToDate(v any) (*time.Time, error) {
	switch n := v.(type) {
	case float64:
		t := time.Unix(int64(n), 0).UTC()
		return &t, nil
	case int64:
		t := time.Unix(n, 0).UTC()
		return &t, nil
	case int:
		t := time.Unix(int64(n), 0).UTC()
		return &t, nil
	case json.Number:
		sec, err := n.Int64()
		if err != nil {
			return nil, fmt.Errorf("jwt: 非法的时间声明值 %v", v)
		}
		t := time.Unix(sec, 0).UTC()
		return &t, nil
	}
	return nil, fmt.Errorf("jwt: 非法的时间声明值 %v", v)
}

// b64Encode 对字节做 base64url 编码（URL 安全字母表、去除填充）。
func b64Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// b64Decode 对 base64url 字符串解码，要求无填充。
func b64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// Sign 使用给定密钥对声明签发一个 HS256 令牌。
// 密钥为空时返回 ErrEmptySecret。调用方负责在签发前填充时间声明，
// 本函数不会自动补填任何字段。
func Sign(claims Claims, secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", ErrEmptySecret
	}
	header := map[string]string{"alg": AlgHS256, "typ": "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := claims.MarshalJSON()
	if err != nil {
		return "", err
	}
	signingInput := b64Encode(hb) + "." + b64Encode(pb)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	return signingInput + "." + b64Encode(sig), nil
}

// Verifier 封装验证令牌所需的固定参数。
type Verifier struct {
	Secret []byte
	// Leeway 是时间声明校验的容差，单位纳秒。
	Leeway time.Duration
	// Now 返回当前时刻，缺省为 time.Now。
	Now func() time.Time
}

// Verify 校验令牌的签名与时间声明，成功时返回还原出的声明。
func (v Verifier) Verify(token string) (Claims, error) {
	if len(v.Secret) == 0 {
		return Claims{}, ErrEmptySecret
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformed
	}
	// 头部段必须非空，否则视为格式错误。
	if parts[0] == "" {
		return Claims{}, ErrMalformed
	}

	// 先解码头部并确认算法，再校验其余结构，确保 alg=none 即便签名段为空也被拒绝。
	hb, err := b64Decode(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidHeader, err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidHeader, err)
	}
	if header.Alg == "none" {
		return Claims{}, ErrAlgNone
	}
	if header.Alg != AlgHS256 {
		return Claims{}, fmt.Errorf("%w: %s", ErrAlgNotSupported, header.Alg)
	}

	// 载荷与签名段必须非空。
	if parts[1] == "" || parts[2] == "" {
		return Claims{}, ErrMalformed
	}

	// 以恒定时间方式比对签名。
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, v.Secret)
	mac.Write([]byte(signingInput))
	want := mac.Sum(nil)
	got, err := b64Decode(parts[2])
	if err != nil {
		return Claims{}, ErrSignatureInvalid
	}
	if !hmac.Equal(want, got) {
		return Claims{}, ErrSignatureInvalid
	}

	// 签名通过后再解码载荷。
	pb, err := b64Decode(parts[1])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var c Claims
	if err := c.UnmarshalJSON(pb); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	// 校验时间声明（带容差）。
	var now time.Time
	if v.Now != nil {
		now = v.Now()
	} else {
		now = time.Now()
	}
	if c.ExpiresAt != nil && now.After(c.ExpiresAt.Add(v.Leeway)) {
		return c, ErrTokenExpired
	}
	if c.NotBefore != nil && now.Add(v.Leeway).Before(*c.NotBefore) {
		return c, ErrTokenNotYetValid
	}
	return c, nil
}
