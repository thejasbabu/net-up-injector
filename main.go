package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/kelseyhightower/envconfig"
	"github.com/thejasbabu/net-up-injector/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func getLogLevel(logLevel string) zapcore.Level {
	switch strings.ToLower(logLevel) {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warning":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

func initLogger(config config.WebHook) {
	logger, _ := zap.Config{
		Encoding:         "json",
		Level:            zap.NewAtomicLevelAt(getLogLevel(config.LogLevel)),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig:    zapcore.EncoderConfig{MessageKey: "message", LevelKey: "level", EncodeLevel: zapcore.LowercaseLevelEncoder},
	}.Build()
	zap.ReplaceGlobals(logger)
}

func main() {
	var webHookConf config.WebHook
	err := envconfig.Process("", &webHookConf)
	if err != nil {
		fmt.Println("error reading env variables")
		log.Fatal(err.Error())
	}
	initLogger(webHookConf)
	certificatePair, err := tls.X509KeyPair([]byte(webHookConf.CertFile), []byte(webHookConf.CertKey))
	if err != nil {
		zap.S().Fatalf("error reading the cert file %s and key %s", webHookConf.CertFile, webHookConf.CertKey)
	}

	server := &http.Server{
		Addr:      fmt.Sprintf(":%v", webHookConf.Port),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificatePair}},
	}

	webhook := NewWebHookServer(server, webHookConf.SideCarTemplateFile, webHookConf.SidecarContainerImage)
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", webhook.serve)
	webhook.server.Handler = mux
	go func() {
		if err := webhook.server.ListenAndServeTLS("", ""); err != nil {
			zap.S().Fatalf("Failed to listen and serve webhook server: %v", err)
		}
	}()

	zap.S().Infof("Webhook started at port %v", webHookConf.Port)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	zap.L().Info("Got OS shutdown signal, shutting down webhook server gracefully...")
	webhook.server.Shutdown(context.Background())
}
