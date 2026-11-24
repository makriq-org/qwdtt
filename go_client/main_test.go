package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestFailConfigExits проверяет, что ошибка применения конфигурации туннеля
// завершает процесс с ненулевым кодом. Иначе супервизор видит живой процесс,
// локальный порт занят, а SOCKS5-сервер так и не запущен.
func TestFailConfigExits(t *testing.T) {
	if os.Getenv("QWDTT_TEST_FAIL_CONFIG") == "1" {
		failConfig(context.Background(), "тестовый сбой конфигурации")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestFailConfigExits")
	cmd.Env = append(os.Environ(), "QWDTT_TEST_FAIL_CONFIG=1")
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("failConfig did not exit with code 1: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "Конфигурация туннеля не применена") {
		t.Fatalf("missing failure reason in output: %s", output)
	}
}
