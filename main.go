package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"task014-jwt/internal/httpapi"
	"task014-jwt/internal/selfcheck"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--smoke-test" {
		os.Exit(selfcheck.Run())
	}

	sub := "server"
	if len(args) > 0 {
		sub = args[0]
	}
	if sub != "server" {
		fmt.Fprintf(os.Stderr, "未知命令 %q\n用法: task014-jwt [server|--smoke-test]\n", sub)
		os.Exit(2)
	}

	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	addr := ":8080"
	secret := ""
	leeway := 0
	fs.StringVar(&addr, "addr", ":8080", "HTTP 监听地址")
	fs.StringVar(&secret, "secret", "", "HMAC 签名密钥（必填）")
	fs.IntVar(&leeway, "leeway", 0, "时间声明校验容差（秒）")
	if err := fs.Parse(args[1:]); err != nil {
		os.Exit(2)
	}
	if secret == "" {
		fmt.Fprintln(os.Stderr, "缺少必填参数 --secret")
		os.Exit(2)
	}

	api := httpapi.New([]byte(secret), time.Duration(leeway)*time.Second)
	srv := &http.Server{
		Addr:              addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
	}
	log.Printf("JWT 签发验证服务已启动，监听 %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "服务启动失败:", err)
		os.Exit(1)
	}
}
