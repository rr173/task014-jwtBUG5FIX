# task014-jwt

JWT 手工签发与验证服务，仅使用标准库实现 HMAC-SHA256（HS256）令牌的签发与验证，不依赖任何第三方 JWT 库、数据库或外部服务。

## 本地运行

```bash
go run . server --addr :8080 --secret your-secret --leeway 5
go run . --smoke-test
```

主要接口：

- `GET /healthz`：健康检查。
- `POST /sign`：提交 `{"claims":{...}}`，返回 `{"token":"..."}`。未提供签发时间时由服务补填。
- `POST /verify`：提交 `{"token":"..."}`，合法返回 `{"valid":true,"claims":{...}}`，非法返回 `{"valid":false,"error":"..."}`。

## Docker

镜像使用国内 DaoCloud Go 1.26.3 Bookworm builder 和 Alpine 3.20 runtime；支持 `linux/amd64` 与 `linux/arm64` 双架构。
