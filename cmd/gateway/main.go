package main

import (
"log/slog"
"os"
)

func main() {
logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
slog.SetDefault(logger)

slog.Info("mcp-gateway starting")
// TODO: загрузить конфиг, инициализировать сервер, запустить
}