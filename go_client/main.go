package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// CaptchaResultChan — канал для получения токена капчи из внешнего решателя (WebView)
var CaptchaResultChan = make(chan string, 1)

var captchaModeValue atomic.Value

func init() {
	captchaModeValue.Store("auto")
}

func normalizeCaptchaMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "auto", "native", "rjs", "wv":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "auto"
	}
}

func setCaptchaMode(mode string) string {
	normalized := normalizeCaptchaMode(mode)
	captchaModeValue.Store(normalized)
	return normalized
}

func getCaptchaMode() string {
	mode, _ := captchaModeValue.Load().(string)
	if mode == "" {
		return "auto"
	}
	return mode
}

// drainCaptchaResult удаляет устаревший результат капчи из канала
func drainCaptchaResult() {
	select {
	case <-CaptchaResultChan:
	default:
	}
}

func runHashChecks(ctx context.Context, hashes []string) {
	log.Printf("[CHECK] Проверка VK-хешей: %d", len(hashes))
	for i, hash := range hashes {
		fmt.Printf("HASH_CHECK_START|%d|%s\n", i+1, hash)
		checkCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		_, _, turnURLs, err := GetCreds(checkCtx, hash, 9000+i)
		cancel()

		status, message := classifyHashCheckError(err)
		if err == nil {
			status = "ok"
			message = fmt.Sprintf("TURN urls=%d", len(turnURLs))
		}
		fmt.Printf("HASH_CHECK|%d|%s|%s|%s\n", i+1, hash, status, sanitizeHashCheckMessage(message))
	}
}

func classifyHashCheckError(err error) (string, string) {
	if err == nil {
		return "ok", ""
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "captcha_required") || strings.Contains(text, "captcha_wait_required"):
		return "captcha", "VK просит капчу"
	case strings.Contains(text, "call not found") ||
		strings.Contains(text, "joinconversationbylink") ||
		strings.Contains(text, "missing turn_server") ||
		strings.Contains(text, "9000") ||
		strings.Contains(text, "callunavailable"):
		return "dead", "Звонок не найден или закрыт"
	case strings.Contains(text, "flood") || strings.Contains(text, "rate limit") || strings.Contains(text, "error_code:29"):
		return "limited", "VK временно ограничил запросы"
	case strings.Contains(text, "timeout") || strings.Contains(text, "deadline") || strings.Contains(text, "lookup") || strings.Contains(text, "network"):
		return "network", "Сетевая ошибка"
	default:
		return "error", err.Error()
	}
}

func sanitizeHashCheckMessage(message string) string {
	message = strings.ReplaceAll(message, "\n", " ")
	message = strings.ReplaceAll(message, "\r", " ")
	message = strings.ReplaceAll(message, "|", "/")
	if len(message) > 180 {
		return message[:180]
	}
	return message
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Сигналы
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		select {
		case s := <-sig:
			log.Printf("[КЛИЕНТ] Сигнал %v, завершаю...", s)
			cancel()
		case <-ctx.Done():
			return
		}
		select {
		case s := <-sig:
			log.Printf("[КЛИЕНТ] Повторный %v, принудительный выход", s)
			os.Exit(1)
		case <-ctx.Done():
		}
	}()

	var pauseFlag int32

	// STDIN для PAUSE/RESUME/STOP и CAPTCHA_RESULT
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.Contains(line, "error:tunnel stopped") {
				log.Printf("[STDIN] %s", line)
			}
			switch {
			case line == "PAUSE":
				atomic.StoreInt32(&pauseFlag, 1)
			case line == "RESUME":
				atomic.StoreInt32(&pauseFlag, 0)
			case line == "SCREEN_OFF":
				// Экран выключен: реже keepalive, чтобы радио спало (liveness.go).
				lowPowerMode.Store(true)
			case line == "SCREEN_ON":
				lowPowerMode.Store(false)
			case line == "STOP":
				cancel()
				return
			case strings.HasPrefix(line, "CAPTCHA_RESULT|"):
				result := strings.TrimPrefix(line, "CAPTCHA_RESULT|")
				drainCaptchaResult()
				CaptchaResultChan <- result
				log.Printf("[КАПЧА] Результат от Kotlin записан в канал")
			case strings.HasPrefix(line, "TURN_CREDS|"):
				handleTurnCredsStdinLine(line)
			}
		}
	}()

	opts := &clientOptions{}
	bindClientFlags(opts)
	flag.Parse()
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if opts.Config != "" {
		cfg, err := readClientConfig(opts.Config)
		if err != nil {
			log.Fatalf("[КЛИЕНТ] Конфигурация: %v", err)
		}
		if err = cfg.apply(opts, explicit); err != nil {
			log.Fatalf("[КЛИЕНТ] Конфигурация: %v", err)
		}
		// Процесс из конфигурации работает без пользователя и WebView:
		// единственный допустимый решатель — нативный.
		if !explicit["captcha-mode"] {
			opts.CaptchaMode = "native"
		}
		if !explicit["listen"] && !opts.listenConfigured {
			opts.Listen = "127.0.0.1:0"
		}
		if opts.Mode == "socks" && !opts.SocksAuth {
			log.Fatal("[SOCKS] Локальный SOCKS5 обязан требовать логин и пароль")
		}
	}
	if err := opts.validate(); err != nil {
		log.Fatalf("[КЛИЕНТ] %v", err)
	}
	tunnelMode, err := opts.tunnelMode()
	if err != nil {
		log.Fatalf("[КЛИЕНТ] %v", err)
	}
	rawMode := tunnelMode == tunnelRawIP
	noDTLSMode := tunnelMode == tunnelWireGuardDirect || rawMode

	host := &opts.Turn
	port := &opts.Port
	listen := &opts.Listen
	vkHash := &opts.VKHash
	peerAddr := &opts.Peer
	numW := &opts.Workers
	pingOnly := &opts.PingOnly
	deviceID := &opts.DeviceID
	connPassword := &opts.Password
	captchaMode := &opts.CaptchaMode
	vkAuthMode := &opts.VKAuth
	vkAnonPath := &opts.VKAnonPath
	vkCredsFile := &opts.VKCredsFile
	goDNS := &opts.GoDNS
	dnsFallback := &opts.DNSFallback
	obfsMode := &opts.Obfs
	checkHashes := &opts.CheckHashes
	connMode := &opts.Mode
	socksAddr := &opts.SocksAddr
	socksAuth := &opts.SocksAuth
	socksUser := &opts.SocksUser
	socksPass := &opts.SocksPass
	turnTCP := &opts.TurnTCP
	turnTransport := &opts.TurnTransport
	tunFdSock := &opts.TunFdSock
	diagOnly := &opts.DiagOnly
	diagKeyToken := &opts.DiagKey
	diagPortsFlag := &opts.DiagPorts
	diagAuto := &opts.DiagAuto
	diagTrigger := &opts.DiagTrigger

	activeConnMode := strings.ToLower(strings.TrimSpace(*connMode))
	if activeConnMode != "socks" && activeConnMode != "rawtun" {
		activeConnMode = "vpn"
	}
	if activeConnMode == "socks" && *socksAuth {
		if *socksUser == "" || *socksPass == "" {
			log.Fatal("[SOCKS] Для авторизации нужны логин и пароль")
		}
		if len([]byte(*socksUser)) > 255 || len([]byte(*socksPass)) > 255 {
			log.Fatal("[SOCKS] Логин и пароль должны быть не длиннее 255 байт")
		}
	}
	setupGlobalResolver(*goDNS, parseDNSFallback(*dnsFallback))
	activeCaptchaMode := setCaptchaMode(*captchaMode)
	activeVkAuthMode := setVkAuthMode(*vkAuthMode)
	activeVkAnonPath := setVkAnonPath(*vkAnonPath)

	if err := loadVkCredsFile(*vkCredsFile); err != nil {
		log.Fatalf("[КЛИЕНТ] Ошибка чтения vk-creds-file: %v", err)
	}

	hashes := ParseHashes(*vkHash)
	if *checkHashes {
		if len(hashes) == 0 {
			log.Fatal("[CHECK] Нужен -vk со списком хешей")
		}
		log.Printf("[КЛИЕНТ] VK auth mode: %s (hash-check)", activeVkAuthMode)
		if activeVkAuthMode == "anonymous" {
			log.Printf("[КЛИЕНТ] VK anon path: %s", activeVkAnonPath)
		}
		log.Printf("[КЛИЕНТ] Captcha mode: %s", activeCaptchaMode)
		runHashChecks(ctx, hashes)
		return
	}

	log.Printf("[КЛИЕНТ] VK auth mode: %s", activeVkAuthMode)
	if activeVkAuthMode == "anonymous" {
		log.Printf("[КЛИЕНТ] VK anon path: %s", activeVkAnonPath)
	}

	if *peerAddr == "" || *vkHash == "" {
		log.Fatal("[КЛИЕНТ] Нужны -peer и -vk")
	}

	peer, err := net.ResolveUDPAddr("udp", *peerAddr)
	if err != nil {
		log.Fatalf("[КЛИЕНТ] Ошибка разбора пира: %v", err)
	}

	if len(hashes) == 0 {
		log.Fatal("[КЛИЕНТ] Нет хешей VK")
	}

	if *connPassword == "" {
		log.Fatal("[КЛИЕНТ] Нужен -password: WRAP ключ теперь выводится из пароля подключения")
	}

	// WRAP key
	wrapKey, err := deriveWrapKey(*connPassword)
	if err != nil {
		log.Fatalf("[КЛИЕНТ] WRAP key derive: %v", err)
	}

	// Лимит воркеров: 27 на хеш × 6 хешей (SettingsStore.MAX_TOTAL_WORKERS).
	maxWorkers := maxWorkersPerHash * maxWorkerHashes
	if opts.Config != "" && len(hashes) > maxWorkerHashes {
		log.Fatalf("[КЛИЕНТ] Поддерживается не более %d VK-хешей", maxWorkerHashes)
	}
	if getVkAuthMode() == "account" {
		const accountMaxWorkers = 4
		if *numW > accountMaxWorkers {
			log.Printf("[КЛИЕНТ] Аккаунт VK: TURN-квота ~%d relay на сессию, потоков %d -> %d", accountMaxWorkers, *numW, accountMaxWorkers)
			*numW = accountMaxWorkers
		}
		if *numW < 1 {
			*numW = 1
		}
	} else if *numW > maxWorkers {
		log.Fatalf("[КЛИЕНТ] Воркеров %d больше предела %d", *numW, maxWorkers)
	} else if limit := maxWorkersPerHash * len(hashes); *numW > limit {
		log.Fatalf("[КЛИЕНТ] Воркеров %d больше предела %d (27 на каждый из %d хешей)", *numW, limit, len(hashes))
	}
	if *numW < 1 {
		*numW = 1
	}

	activeTurnTransport := normalizeTurnTransport(*turnTransport)
	if strings.TrimSpace(*turnTransport) == "" && *turnTCP {
		activeTurnTransport = turnTransportTCP
	}

	tp := &TurnParams{
		Hosts:     parseTurnHosts(*host),
		Port:      *port,
		Hashes:    hashes,
		WrapKey:   wrapKey,
		ObfsMode:  normalizeObfsMode(*obfsMode),
		NoDTLS:    noDTLSMode,
		RawMode:   rawMode,
		Transport: activeTurnTransport,
	}

	diagCfg := &diagConfig{
		TP:       tp,
		Peer:     peer,
		Listener: diagTargetListener(tp),
		Ports:    parseDiagPorts(*diagPortsFlag),
		Password: *connPassword,
		DeviceID: *deviceID,
	}
	if secret, err := parseDiagToken(*diagKeyToken); err != nil {
		log.Printf("[ДИАГ] %v — проверка будет без ключа сервера", err)
	} else if secret != nil {
		if key, err := deriveDiagKey(secret); err == nil {
			diagCfg.DiagKey = key
		}
	}
	diagHash := hashes[0]
	diagCfg.Creds = func(ctx context.Context, fresh bool) (*Credentials, error) {
		// Обычно — креды первой группы из кэша (без лишнего запроса к VK);
		// fresh — отдельный поток, если квоту на них уже выбрали воркеры.
		stream := 100
		if fresh {
			stream = 990
			getStreamCache(stream).invalidate(stream)
		}
		u, p, urls, err := GetCreds(ctx, diagHash, stream)
		if err != nil {
			return nil, err
		}
		return &Credentials{User: u, Pass: p, TurnURLs: urls, CacheStreamID: stream}, nil
	}

	if *diagOnly {
		v := runDiagnostics(ctx, diagCfg, "manual")
		if v.Sev == "error" {
			os.Exit(2)
		}
		return
	}

	if *pingOnly {
		var lastErr error
		for i, hash := range hashes {
			user, pass, turnURLs, err := GetCreds(ctx, hash, 999)
			if err != nil {
				lastErr = fmt.Errorf("GetCreds hash %d: %v", i, err)
				continue
			}
			creds := &Credentials{User: user, Pass: pass, TurnURLs: turnURLs, CacheStreamID: 999}
			rtt, err := RunPing(ctx, tp, peer, creds)
			if err != nil {
				lastErr = fmt.Errorf("RunPing hash %d: %v", i, err)
				continue
			}
			fmt.Printf("PING_RESULT|%d\n", rtt)
			os.Exit(0)
		}
		// Если все хеши провалились
		fmt.Printf("PING_ERROR|All hashes failed. Last error: %v\n", lastErr)
		os.Exit(1)
	}

	// Локальный UDP-сокет — это Endpoint из WireGuard-конфига. В raw-IP
	// режиме WireGuard нет, слушатель не нужен.
	var localConn net.PacketConn
	localPort := "9000"
	if !rawMode {
		var err error
		localConn, err = listenUDP(*listen)
		if err != nil {
			log.Fatalf("[КЛИЕНТ] Ошибка слушателя %s: %v", *listen, err)
		}
		if uc, ok := localConn.(*net.UDPConn); ok {
			_ = uc.SetReadBuffer(socketBufSize)
			_ = uc.SetWriteBuffer(socketBufSize)
		}
		stopLocalConn := context.AfterFunc(ctx, func() { _ = localConn.Close() })
		defer stopLocalConn()
		// Порт 0 означает «выбрать свободный»: двум узлам qwdtt нельзя
		// делить один WireGuard-loopback, а FlClashM запускает их параллельно.
		if _, port, err := net.SplitHostPort(localConn.LocalAddr().String()); err == nil && port != "" {
			localPort = port
		}
	}

	groupPlan := groupSizes(*numW)
	numGroups := len(groupPlan)

	wrapStatus := "OFF"
	if len(wrapKey) == wrapKeyLen {
		wrapStatus = "ON (password HKDF + RTP AEAD)"
	}

	captchaStatus := "AUTO: Go v2 x2 -> WBV Auto x2 -> Go v2 x1 -> Manual WBV"
	switch activeCaptchaMode {
	case "wv":
		captchaStatus = "WBV selected in Android"
	case "rjs":
		captchaStatus = "RJS Go v2 with WBV Auto fallback"
	case "native":
		captchaStatus = "NATIVE: Go v2 only (no WebView)"
	}

	log.Println("[КЛИЕНТ] ═══════════════════════════════════════")
	log.Printf("[КЛИЕНТ] VK Creds: 2 stable app_id с циклическим fallback")
	log.Printf("[КЛИЕНТ] TLS: Chrome 146 fingerprint")
	log.Printf("[КЛИЕНТ] Воркеров: %d (групп: %d, до %d)", *numW, numGroups, workersPerGroup)
	log.Printf("[КЛИЕНТ] Хешей: %d", len(hashes))
	if !rawMode {
		log.Printf("[КЛИЕНТ] Слушаю: %s | Пир: %s", *listen, *peerAddr)
	} else {
		log.Printf("[КЛИЕНТ] Пир: %s", *peerAddr)
	}
	log.Printf("[КЛИЕНТ] TUNNEL: %s", tunnelMode)
	log.Printf("[КЛИЕНТ] TURN-транспорт: %s", strings.ToUpper(tp.Transport))
	if len(tp.Hosts) > 0 {
		log.Printf("[КЛИЕНТ] Свои TURN-адреса: %s", strings.Join(tp.Hosts, ", "))
	}
	log.Printf("[КЛИЕНТ] Режим: %s", activeConnMode)
	if activeConnMode == "socks" {
		log.Printf("[КЛИЕНТ] SOCKS5: %s (udp=%v, token=%v)", *socksAddr, opts.UDP, opts.UDPToken)
		if *socksAuth {
			log.Printf("[КЛИЕНТ] SOCKS5: авторизация по логину и паролю включена")
		}
	}
	log.Printf("[КЛИЕНТ] WRAP: %s", wrapStatus)
	log.Printf("[WRAP] Ключ выведен из пароля, режим RTP AEAD активен")
	log.Printf("[КЛИЕНТ] Device ID: %s", *deviceID)
	log.Printf("[КЛИЕНТ] Captcha: %s", captchaStatus)
	log.Println("[КЛИЕНТ] ═══════════════════════════════════════")

	stats := NewStats()
	shutdownCh := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(shutdownCh)
	}()
	go stats.RunLoop(shutdownCh)
	diagCfg.TunnelReceiving = tunnelReceivingRecently
	go diagWatchdog(ctx, diagCfg, stats, &pauseFlag, *diagAuto, *diagTrigger)

	var socksListener net.Listener
	if activeConnMode == "socks" {
		socksListener, err = listenTCP(*socksAddr)
		if err != nil {
			log.Fatalf("[SOCKS] Не удалось занять порт %s: %v", *socksAddr, err)
		}
		stop := context.AfterFunc(ctx, func() { _ = socksListener.Close() })
		defer stop()
	}

	var disp *Dispatcher
	if rawMode {
		// netstack TUN подключается после RAWCONF; до этого диспетчер ждёт.
		disp = NewDispatcherPendingTUN(ctx, stats)
	} else {
		disp = NewDispatcher(ctx, localConn, stats)
	}
	defer disp.Shutdown()

	configCh := make(chan string, 1)
	configDone := make(chan struct{})
	go func() {
		defer close(configDone)
		select {
		case tunnelConf, ok := <-configCh:
			if !ok || tunnelConf == "" {
				return
			}

			if strings.HasPrefix(tunnelConf, "RAWCONF:") {
				ip, tunnelDNS, mtu, err := parseRawConf(tunnelConf)
				if err != nil {
					log.Printf("[RAW] %v", err)
					return
				}
				log.Printf("[RAW] Конфиг получен: IP=%s MTU=%d", ip, mtu)

				if activeConnMode == "rawtun" {
					if *tunFdSock == "" {
						log.Println("[RAW] Ошибка: -tun-fd-sock не указан")
						return
					}
					log.Println("[RAW] Ожидание TUN fd от Android...")
					var tunFile *os.File
					var fdErr error
					attempt := 0
					for {
						attempt++
						tunFile, fdErr = recvTunFD(*tunFdSock)
						if fdErr == nil {
							break
						}
						rawDiagf("recvTunFD попытка #%d неудачна: %v (повтор через 200мс)", attempt, fdErr)
						select {
						case <-ctx.Done():
							rawDiagf("recvTunFD: ctx отменён, прекращаю попытки")
							return
						case <-time.After(200 * time.Millisecond):
						}
					}
					rawDiagf("recvTunFD успешен на попытке #%d, fd=%v", attempt, tunFile.Fd())
					disp.AttachTUN(tunFile)
					log.Println("[RAW] TUN подключён, трафик пошёл")
					return
				}
				if activeConnMode != "socks" {
					return
				}
				endpoints, err := effectiveDNS(opts.DNSServer, opts.DNSFallback, tunnelDNS)
				if err != nil {
					log.Printf("[SOCKS] DNS: %v", err)
					return
				}
				tunnel, err := createNetstackTunnel([]netip.Addr{ip}, dnsAddresses(endpoints), mtu)
				if err != nil {
					log.Printf("[SOCKS] netstack: %v", err)
					return
				}
				defer tunnel.Close()
				disp.AttachPacketConn(newTunPacketConn(tunnel))
				resolver := newTunnelResolver(tunnel.Net, endpoints)
				log.Printf("[SOCKS] raw-IP netstack готов (addr=%s dns=%v mtu=%d)", ip, endpoints, mtu)
				if err := startSocksServer(ctx, opts, socksListener, tunnel.Net, resolver); err != nil {
					log.Printf("[SOCKS] Сервер остановлен: %v", err)
				}
				return
			}

			finalConf := tunnelConf
			if !strings.Contains(finalConf, "MTU =") {
				lines := strings.Split(finalConf, "\n")
				var newLines []string
				for _, line := range lines {
					newLines = append(newLines, line)
					if strings.TrimSpace(line) == "[Interface]" {
						newLines = append(newLines, "MTU = 1280")
					}
				}
				finalConf = strings.Join(newLines, "\n")
			}
			// Android-приложение разбирает этот блок из stdout, чтобы поднять
			// системный VPN. В headless-режиме (конфиг-файл) приватные ключи
			// в лог не выводятся.
			if opts.Config == "" {
				fmt.Println()
				fmt.Println("╔══════════════ WireGuard Конфиг ══════════════╗")
				for _, line := range strings.Split(finalConf, "\n") {
					fmt.Printf("║ %-44s ║\n", line)
				}
				fmt.Println("╚══════════════════════════════════════════════╝")
				if err := os.WriteFile("wg-turn.conf", []byte(finalConf+"\n"), 0600); err != nil {
					log.Printf("[КОНФИГ] Ошибка сохранения: %v", err)
				} else {
					log.Println("[КОНФИГ] Сохранён в wg-turn.conf")
				}
			}

			if activeConnMode == "socks" {
				wgConf, err := parseWgQuick(finalConf)
				if err != nil {
					log.Printf("[SOCKS] Ошибка WG-конфига: %v", err)
					return
				}
				endpoints, err := effectiveDNS(opts.DNSServer, opts.DNSFallback, wgConf.dns)
				if err != nil {
					log.Printf("[SOCKS] DNS: %v", err)
					return
				}
				dev, tnet, err := startUserspaceWireGuardConfig(wgConf, dnsAddresses(endpoints))
				if err != nil {
					log.Printf("[SOCKS] Ошибка userspace WG: %v", err)
					return
				}
				defer dev.Close()
				resolver := newTunnelResolver(tnet, endpoints)
				log.Printf("[SOCKS] WireGuard netstack готов (addr=%v dns=%v)", wgConf.addresses, endpoints)
				if err := startSocksServer(ctx, opts, socksListener, tnet, resolver); err != nil {
					log.Printf("[SOCKS] Сервер остановлен: %v", err)
				}
			}
		case <-ctx.Done():
		}
	}()

	var wg sync.WaitGroup
	workerIDCounter := 1

	var prevWaitReady <-chan struct{}

	for g := 0; g < numGroups; g++ {
		isFirst := (g == 0)

		var myWaitReady <-chan struct{}
		var mySignalReady chan<- struct{}

		if g > 0 {
			myWaitReady = prevWaitReady
		}
		if g < numGroups-1 {
			ch := make(chan struct{})
			mySignalReady = ch
			prevWaitReady = ch
		}

		groupSize := groupPlan[g]
		if groupSize <= 0 {
			continue
		}

		ids := make([]int, groupSize)
		for i := range ids {
			ids[i] = workerIDCounter
			workerIDCounter++
		}

		gID := g + 1
		var cc chan<- string
		if isFirst {
			cc = configCh
		}

		wg.Add(1)
		go func(groupID int, isFirstGroup bool, configChan chan<- string, workerIds []int, startHashIndex int, waitR <-chan struct{}, sigR chan<- struct{}) {
			defer wg.Done()
			WorkerGroup(ctx, groupID, startHashIndex, tp, peer, disp, localPort,
				isFirstGroup, configChan, workerIds, &pauseFlag, *deviceID, *connPassword, stats, waitR, sigR)
		}(gID, isFirst, cc, ids, g, myWaitReady, mySignalReady)
	}

	wg.Wait()
	close(configCh)
	<-configDone
	log.Println("[КЛИЕНТ] Все воркеры завершены")
}
