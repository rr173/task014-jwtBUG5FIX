package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
var testSecret = []byte("super-secret-key")

func verifier(leeway time.Duration) Verifier {
	return Verifier{Secret: testSecret, Leeway: leeway, Now: func() time.Time { return fixedNow }}
}

func TestSignRejectsEmptySecret(t *testing.T) {
	if _, err := Sign(Claims{Subject: "alice"}, nil); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("want ErrEmptySecret, got %v", err)
	}
}

func TestVerifyRejectsEmptySecret(t *testing.T) {
	v := Verifier{Secret: nil, Now: func() time.Time { return fixedNow }}
	if _, err := v.Verify("a.b.c"); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("want ErrEmptySecret, got %v", err)
	}
}

func TestSignVerifyRoundTripStandardClaims(t *testing.T) {
	exp := fixedNow.Add(time.Hour)
	nbf := fixedNow.Add(-time.Minute)
	token, err := Sign(Claims{
		Issuer: "issuer", Subject: "alice", Audience: "aud", ID: "id-1",
		ExpiresAt: &exp, NotBefore: &nbf, IssuedAt: &fixedNow,
	}, testSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token must have exactly 2 dots, got %q", token)
	}
	c, err := verifier(0).Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Issuer != "issuer" || c.Subject != "alice" || c.Audience != "aud" || c.ID != "id-1" {
		t.Fatalf("standard claims lost: %+v", c)
	}
	if c.ExpiresAt == nil || !c.ExpiresAt.Equal(exp) {
		t.Fatalf("exp not round-tripped: want %v got %v", exp, c.ExpiresAt)
	}
	if c.IssuedAt == nil || !c.IssuedAt.Equal(fixedNow) {
		t.Fatalf("iat not round-tripped: want %v got %v", fixedNow, c.IssuedAt)
	}
}

func TestCustomClaimsRoundTrip(t *testing.T) {
	token, err := Sign(Claims{
		Subject: "bob",
		Extra:   map[string]any{"role": "admin", "tier": float64(3), "active": true},
	}, testSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	c, err := verifier(0).Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Extra["role"] != "admin" {
		t.Fatalf("role lost: %v", c.Extra)
	}
	if c.Extra["tier"] != float64(3) {
		t.Fatalf("tier lost: %v", c.Extra)
	}
	if c.Extra["active"] != true {
		t.Fatalf("active lost: %v", c.Extra)
	}
}

func TestAlgNoneRejected(t *testing.T) {
	// 构造 alg=none 的令牌，签名段非空，确保走算法校验分支而非空段分支。
	hdr := b64Encode([]byte(`{"alg":"none","typ":"JWT"}`))
	pl := b64Encode([]byte(`{"sub":"evil"}`))
	sig := b64Encode([]byte("fake"))
	noneToken := hdr + "." + pl + "." + sig
	if _, err := verifier(0).Verify(noneToken); !errors.Is(err, ErrAlgNone) {
		t.Fatalf("want ErrAlgNone, got %v", err)
	}
}

func TestAlgNoneWithEmptySignatureRejected(t *testing.T) {
	// alg=none 且签名段为空也必须被拒绝为 none，而非格式错误。
	hdr := b64Encode([]byte(`{"alg":"none","typ":"JWT"}`))
	pl := b64Encode([]byte(`{"sub":"evil"}`))
	noneToken := hdr + "." + pl + "."
	if _, err := verifier(0).Verify(noneToken); !errors.Is(err, ErrAlgNone) {
		t.Fatalf("want ErrAlgNone for empty-sig none token, got %v", err)
	}
}

func TestUnsupportedAlgRejected(t *testing.T) {
	hdr := b64Encode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	pl := b64Encode([]byte(`{"sub":"x"}`))
	sig := b64Encode([]byte("fake"))
	if _, err := verifier(0).Verify(hdr + "." + pl + "." + sig); !errors.Is(err, ErrAlgNotSupported) {
		t.Fatalf("want ErrAlgNotSupported, got %v", err)
	}
}

func TestTamperedPayloadFailsSignature(t *testing.T) {
	token, _ := Sign(Claims{Subject: "alice"}, testSecret)
	parts := strings.Split(token, ".")
	parts[1] = parts[1] + "A" // 篡改载荷段
	if _, err := verifier(0).Verify(strings.Join(parts, ".")); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("want ErrSignatureInvalid, got %v", err)
	}
}

func TestWrongSecretFailsSignature(t *testing.T) {
	token, _ := Sign(Claims{Subject: "alice"}, testSecret)
	v := Verifier{Secret: []byte("other-secret"), Now: func() time.Time { return fixedNow }}
	if _, err := v.Verify(token); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("want ErrSignatureInvalid, got %v", err)
	}
}

func TestMalformedStructure(t *testing.T) {
	cases := []string{
		"",                 // 空
		"onlyone",          // 无点
		"a.b",              // 两段
		"a.b.c.d",          // 四段
		".b.c",             // 头部段为空
		"header..sig",      // 载荷段为空（HS256）
		"header.payload.",  // 签名段为空（HS256）
	}
	v := verifier(0)
	for _, tok := range cases {
		// 头部段为空 / 段数错误应判格式错误；空签名 HS256 也应判格式错误。
		// 这里只断言“被拒绝”，不细究具体错误码，因为部分用例头部无法解码。
		if _, err := v.Verify(tok); err == nil {
			t.Fatalf("expected error for token %q, got nil", tok)
		}
	}
}

func TestInvalidBase64Header(t *testing.T) {
	// 头部段不是合法 base64url（含非法字符），应判头部非法或格式错误。
	tok := "!!!!.payload.sig"
	if _, err := verifier(0).Verify(tok); err == nil {
		t.Fatalf("expected error for bad base64 header")
	}
}

// hmacSha256 用给定密钥对输入计算 HMAC-SHA256，供测试构造令牌。
func hmacSha256(secret []byte, data string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func TestExpiredWithoutLeeway(t *testing.T) {
	exp := fixedNow.Add(-1 * time.Second) // 早 1 秒
	token, _ := Sign(Claims{ExpiresAt: &exp}, testSecret)
	if _, err := verifier(0).Verify(token); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
}

func TestExpiredWithinLeeway(t *testing.T) {
	exp := fixedNow.Add(-3 * time.Second) // 早 3 秒，容差 5 秒内
	token, _ := Sign(Claims{ExpiresAt: &exp}, testSecret)
	if _, err := verifier(5 * time.Second).Verify(token); err != nil {
		t.Fatalf("expected valid within leeway, got %v", err)
	}
}

func TestNotYetValidWithoutLeeway(t *testing.T) {
	nbf := fixedNow.Add(1 * time.Second) // 晚 1 秒
	token, _ := Sign(Claims{NotBefore: &nbf}, testSecret)
	if _, err := verifier(0).Verify(token); !errors.Is(err, ErrTokenNotYetValid) {
		t.Fatalf("want ErrTokenNotYetValid, got %v", err)
	}
}

func TestNotYetValidWithinLeeway(t *testing.T) {
	nbf := fixedNow.Add(3 * time.Second) // 晚 3 秒，容差 5 秒内
	token, _ := Sign(Claims{NotBefore: &nbf}, testSecret)
	if _, err := verifier(5 * time.Second).Verify(token); err != nil {
		t.Fatalf("expected valid within leeway, got %v", err)
	}
}

func TestNoTimeClaimsAlwaysValid(t *testing.T) {
	token, _ := Sign(Claims{Subject: "alice"}, testSecret)
	if _, err := verifier(0).Verify(token); err != nil {
		t.Fatalf("token without time claims should be valid, got %v", err)
	}
}

func TestPayloadNotJSONFails(t *testing.T) {
	// 头部合法、签名由真实密钥对非法载荷计算，但载荷解码后非 JSON。
	hdr := b64Encode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pl := b64Encode([]byte("not-json-at-all"))
	sig := b64Encode(hmacSha256(testSecret, hdr+"."+pl))
	if _, err := verifier(0).Verify(hdr + "." + pl + "." + sig); err == nil {
		t.Fatalf("expected error for non-JSON payload")
	}
}
