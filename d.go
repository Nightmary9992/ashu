package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/oschwald/geoip2-golang"
)

// -------------------- Global constants & maps (expanded) --------------------
var (
	cityDB    *geoip2.Reader
	asnDB     *geoip2.Reader
	cidrRegex = regexp.MustCompile(`([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}`)
)

type Result struct {
	IP               string  `json:"ip"`
	Port             int     `json:"port"`
	BandwidthGbps    float64 `json:"bandwidth_gbps"`
	RAMGB            float64 `json:"ram_gb"`
	CPUcores         int     `json:"cpu_cores"`
	DiskCapacityGB   float64 `json:"disk_capacity_gb"`
	DiskFreeGB       float64 `json:"disk_free_gb"`
	ISP              string  `json:"isp"`
	Country          string  `json:"country"`
	HasXDP           bool    `json:"has_xdp"`
	Category         string  `json:"category"`
	ProtectionStatus string  `json:"protection_status"`
	ProtectionReason string  `json:"protection_reason"`
	OpenPorts        []int   `json:"open_ports"`
}

type Job struct {
	IP   string
	Port int
}

type protEntry struct {
	status string
	reason string
	clr    color.Attribute
}

// ---------- Protection maps (expanded) ----------
var (
	protectedMap   map[string]protEntry
	unprotectedMap map[string]protEntry
	cloudMap       map[string]protEntry
)

func init() {
	protectedMap = buildMap(color.FgRed, "PROTECTED", []struct{ k, r string }{
		{"path network", "Path Network (DDoS Scrubbed)"},
		{"path.net", "Path Network (DDoS Scrubbed)"},
		{"ovh", "OVH Cloud (DDoS Protected)"},
		{"soyoustart", "OVH/SYS (DDoS Protected)"},
		{"kimsufi", "OVH/Kimsufi (DDoS Protected)"},
		{"voxility", "Voxility (DDoS Scrubbed)"},
		{"cosmic", "Cosmic Global (DDoS Protected)"},
		{"psychz", "Psychz Networks (DDoS Protected)"},
		{"ddos-guard", "DDoS-Guard (DDoS Scrubbed)"},
		{"datacamp", "Datacamp Limited (DDoS Protected)"},
		{"cloudflare", "Cloudflare (DDoS Protected)"},
		{"gsl networks", "GSL Networks (DDoS Protected)"},
		{"imperva", "Imperva (DDoS Protected)"},
		{"fastly", "Fastly (DDoS Protected)"},
		{"akamai", "Akamai (DDoS Protected)"},
		{"limelight", "Limelight (DDoS Protected)"},
		{"clouvider", "Clouvider (Corero DDoS Protected)"},
		{"buyvm", "BuyVM/Frantech (DDoS Filtered)"},
		{"frantech", "BuyVM/Frantech (DDoS Filtered)"},
		{"tempesta", "Tempesta (DDoS Protected)"},
		{"hydra", "Hydra Communications (DDoS Protected)"},
		{"corero", "Corero (DDoS Protected)"},
		{"combahton", "combahton (DDoS Protected)"},
		{"link11", "Link11 (DDoS Scrubbed)"},
		{"prolexic", "Prolexic (DDoS Scrubbed)"},
		{"radware", "Radware (DDoS Scrubbed)"},
		{"incapsula", "Incapsula (DDoS Scrubbed)"},
		{"neustar", "Neustar (DDoS Scrubbed)"},
		{"staminus", "Staminus (DDoS Protected)"},
		{"sharktech", "Sharktech (DDoS Protected)"},
		{"x4b", "X4B (DDoS Protected)"},
		{"layer7", "Layer7 (DDoS Protected)"},
		{"cdn77", "CDN77/Datacamp (Unprotected/Standard)"},
		{"sucuri", "Sucuri (DDoS Protected)"},
		{"f5 networks", "F5 Silverline (DDoS Protected)"},
		{"arbor", "Arbor Networks (DDoS Protected)"},
		{"gcore", "G-Core Labs (DDoS Protected)"},
		{"stormwall", "StormWall (DDoS Protected)"},
		{"qrator", "Qrator (DDoS Protected)"},
	})

	unprotectedMap = buildMap(color.FgGreen, "UNPROTECTED", []struct{ k, r string }{
		{"latitude.sh", "Latitude.sh (Unprotected/Spoofable)"},
		{"maxihost", "Latitude.sh/Maxihost (Unprotected/Spoofable)"},
		{"hetzner", "Hetzner (Unprotected/No DDoS Scrub)"},
		{"leaseweb", "Leaseweb (Unprotected/Standard)"},
		{"kamatera", "Kamatera (Unprotected/No Filtering)"},
		{"genesis adaptive", "Genesis Adaptive (Unprotected/High Bandwidth)"},
		{"m247", "M247 (Unprotected/Standard)"},
		{"hostkey", "HostKey (Unprotected)"},
		{"contabo", "Contabo (Unprotected/Standard)"},
		{"interserver", "Interserver (Unprotected)"},
		{"selectel", "Selectel (Unprotected)"},
		{"hostinger", "Hostinger (Unprotected)"},
		{"iweb", "iWeb (Unprotected)"},
		{"servers.com", "Servers.com (Unprotected)"},
		{"scaleway", "Scaleway (Unprotected/Standard)"},
		{"liteserver", "LiteServer (Unprotected)"},
		{"novogara", "Novogara (Unprotected)"},
		{"quintex", "Quintex (Unprotected)"},
		{"pehost", "PEHost (Unprotected)"},
		{"terrahost", "Terrahost (Unprotected/Standard)"},
		{"cherry servers", "Cherry Servers (Unprotected)"},
		{"edis", "EDIS (Unprotected)"},
		{"ipvolume", "IPVolume (Unprotected)"},
		{"evolink", "Evolink (Unprotected)"},
		{"pax.net", "Pax.net (Unprotected)"},
		{"paperspace", "Paperspace (Unprotected)"},
	})

	cloudMap = buildMap(color.FgYellow, "PARTIAL", []struct{ k, r string }{
		{"google", "Google Cloud (Standard Firewall)"},
		{"amazon", "AWS (Standard Shield)"},
		{"aws", "AWS (Standard Shield)"},
		{"microsoft", "Azure (Standard Firewall)"},
		{"azure", "Azure (Standard Firewall)"},
		{"digitalocean", "DigitalOcean (Standard Firewall)"},
		{"digital ocean", "DigitalOcean (Standard Firewall)"},
		{"vultr", "Vultr (Standard DDoS Shield Available)"},
		{"choopa", "Vultr/Choopa (Standard)"},
		{"linode", "Linode/Akamai (Standard Firewall)"},
		{"alibaba", "Alibaba Cloud (Standard)"},
		{"tencent", "Tencent Cloud (Standard)"},
		{"oracle", "Oracle Cloud (Standard)"},
	})
}

func buildMap(clr color.Attribute, status string, entries []struct{ k, r string }) map[string]protEntry {
	m := make(map[string]protEntry, len(entries))
	for _, e := range entries {
		m[e.k] = protEntry{status: status, reason: e.r, clr: clr}
	}
	return m
}

// -------------------- Caches & pools --------------------
type ispCacheEntry struct {
	isp     string
	country string
}

var ispCache sync.Map

type resultCacheKey struct {
	ip   string
	port int
}

var resultCache sync.Map

func ipTo24Prefix(ipStr string) string {
	lastDot := strings.LastIndexByte(ipStr, '.')
	if lastDot == -1 {
		return ipStr
	}
	return ipStr[:lastDot]
}

// -------------------- Main --------------------
func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetGCPercent(300)

	minBandwidth := 0.0
	mode := "zmap"
	var filterKeyword string
	var outputFile string

	// Parse arguments: collect float, mode, then first remaining as filter, second as output file
	var args []string
	for _, arg := range os.Args[1:] {
		if val, err := strconv.ParseFloat(arg, 64); err == nil && val > 0 {
			minBandwidth = val
		} else if strings.ToLower(arg) == "masscan" || strings.ToLower(arg) == "zmap" {
			mode = strings.ToLower(arg)
		} else {
			args = append(args, arg)
		}
	}
	if len(args) > 0 {
		filterKeyword = args[0]
	}
	if len(args) > 1 {
		outputFile = args[1]
	}

	// Banner
	titleFn := color.New(color.FgHiCyan, color.Bold).SprintFunc()
	accentFn := color.New(color.FgCyan).SprintFunc()
	subFn := color.New(color.Faint).SprintFunc()
	fmt.Println()
	fmt.Println("  " + accentFn("--------------------------------------"))
	fmt.Println("  " + titleFn("  DSTAT SCANNER v3") + subFn("  by dstat"))
	fmt.Println("  " + accentFn("--------------------------------------"))
	fmt.Println("  " + subFn("  bandwidth - protection - xdp - system metrics"))
	if filterKeyword != "" {
		fmt.Printf("  %s %s\n", color.New(color.FgHiYellow).Sprint(">"), color.New(color.FgWhite, color.Bold).Sprint("filter: "+filterKeyword))
	}
	if outputFile != "" {
		fmt.Printf("  %s %s\n", color.New(color.FgHiYellow).Sprint(">"), color.New(color.FgWhite, color.Bold).Sprint("extra output: "+outputFile))
	}
	fmt.Println()

	var err error
	cityDB, err = geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "  >> GeoLite2-City.mmdb not found. Online fallback.\n")
		cityDB = nil
	} else {
		defer cityDB.Close()
	}
	asnDB, err = geoip2.Open("GeoLite2-ASN.mmdb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "  >> GeoLite2-ASN.mmdb not found. Online fallback.\n")
		asnDB = nil
	} else {
		defer asnDB.Close()
	}

	ports := []int{9100}

	bigFile, _ := os.OpenFile("big.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	protectedFile, _ := os.OpenFile("protected.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	unprotectedFile, _ := os.OpenFile("unprotected.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer bigFile.Close()
	defer protectedFile.Close()
	defer unprotectedFile.Close()

	bigWriter := newAsyncWriter(bigFile)
	protectedWriter := newAsyncWriter(protectedFile)
	unprotectedWriter := newAsyncWriter(unprotectedFile)
	defer bigWriter.Close()
	defer protectedWriter.Close()
	defer unprotectedWriter.Close()

	header := "IP:Port | Bandwidth | RAM | CPU | Disk(Cap/Free) | Protection | ISP | Country | XDP | Open Ports\n"
	sep := strings.Repeat("-", 120) + "\n"
	bigWriter.Write(header + sep)
	protectedWriter.Write(header + sep)
	unprotectedWriter.Write(header + sep)

	// Optional extra output file
	var extraWriter *asyncWriter
	if outputFile != "" {
		f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  >> Cannot open %s: %v\n", outputFile, err)
		} else {
			extraWriter = newAsyncWriter(f)
			defer extraWriter.Close()
			extraWriter.Write(header + sep)
		}
	}

	jobs := make(chan Job, 500_000)
	var total int64

	go func() {
		lineScanner := bufio.NewScanner(os.Stdin)
		lineScanner.Buffer(make([]byte, 2*1024*1024), 2*1024*1024)
		for lineScanner.Scan() {
			raw := strings.TrimSpace(lineScanner.Text())
			if raw == "" || strings.HasPrefix(raw, "#") || isGarbage(raw) {
				continue
			}

			if mode == "masscan" && strings.HasPrefix(raw, "open ") {
				parts := strings.Fields(raw)
				if len(parts) >= 4 {
					ipStr := parts[3]
					if net.ParseIP(ipStr) != nil {
						overridePort, _ := strconv.Atoi(parts[2])
						pList := ports
						if overridePort != 0 {
							pList = []int{overridePort}
						}
						for _, p := range pList {
							atomic.AddInt64(&total, 1)
							jobs <- Job{IP: ipStr, Port: p}
						}
						continue
					}
				}
			}

			if match := cidrRegex.FindString(raw); match != "" {
				ip, ipnet, err := net.ParseCIDR(match)
				if err == nil {
					count := cidrIPCount(ipnet)
					fmt.Printf("\r\033[K  %s %s %s %s\n",
						color.New(color.FgCyan).Sprint(">"),
						color.New(color.Faint).Sprint("scanning CIDR"),
						color.New(color.FgYellow, color.Bold).Sprint(match),
						color.New(color.Faint).Sprintf("(%s IPs)", color.New(color.FgHiGreen, color.Bold).Sprintf("%d", count)))
					for ip2 := ip.Mask(ipnet.Mask); ipnet.Contains(ip2); incIP(ip2) {
						s := ip2.String()
						for _, p := range ports {
							atomic.AddInt64(&total, 1)
							jobs <- Job{IP: s, Port: p}
						}
					}
					continue
				}
			}

			ipOnly, overridePort := parseIPAndOptionalPort(raw)
			if net.ParseIP(ipOnly) == nil {
				continue
			}
			pList := ports
			if overridePort != 0 {
				pList = []int{overridePort}
			}
			for _, p := range pList {
				atomic.AddInt64(&total, 1)
				jobs <- Job{IP: ipOnly, Port: p}
			}
		}
		if err := lineScanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "  >> Error reading input: %v\n", err)
		}
		close(jobs)
	}()

	startTime := time.Now()
	var attempted int64
	var foundCount int64
	var results []Result
	var mu sync.Mutex

	stopProgress := make(chan struct{})
	go func() {
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stopProgress:
				return
			case <-tick.C:
				a := atomic.LoadInt64(&attempted)
				f := atomic.LoadInt64(&foundCount)
				if a == 0 {
					continue
				}
				elapsed := time.Since(startTime).Seconds()
				if elapsed == 0 {
					continue
				}
				rate := float64(a) / elapsed
				fmt.Printf("\r\033[K  %s %s %s  %s %s  %s %s",
					color.New(color.FgCyan).Sprint(">>"),
					color.New(color.Faint).Sprint("scanned"), color.New(color.FgHiWhite, color.Bold).Sprint(fmt.Sprintf("%d", a)),
					color.New(color.Faint).Sprint("found"), color.New(color.FgHiGreen, color.Bold).Sprint(fmt.Sprintf("%d", f)),
					color.New(color.Faint).Sprint("rate"), color.New(color.FgHiYellow, color.Bold).Sprint(fmt.Sprintf("%.0f/s", rate)))
			}
		}
	}()

	type hit struct {
		ip     string
		port   int
		bw     float64
		hasXDP bool
	}
	hitCh := make(chan hit, 16384)

	var ppWg sync.WaitGroup
	for i := 0; i < 256; i++ {
		ppWg.Add(1)
		go func() {
			defer ppWg.Done()
			for h := range hitCh {
				key := resultCacheKey{ip: h.ip, port: h.port}
				if _, ok := resultCache.Load(key); ok {
					continue
				}
				ramGB, cpuCores, diskCapGB, diskFreeGB := scrapeSystemMetrics(h.ip, h.port)

				isp, country := getIPInfoCached(h.ip)
				ispLower := strings.ToLower(isp)

				hostnames := reverseDNSWithTimeout(h.ip, 150*time.Millisecond)
				pStatus := classifyProtection(ispLower, hostnames)

				// Apply filter if set
				if filterKeyword != "" {
					match := strings.Contains(ispLower, strings.ToLower(filterKeyword))
					if !match {
						for _, hn := range hostnames {
							if strings.Contains(strings.ToLower(hn), strings.ToLower(filterKeyword)) {
								match = true
								break
							}
						}
					}
					if !match {
						// skip this result
						continue
					}
				}

				res := Result{
					IP:               h.ip,
					Port:             h.port,
					BandwidthGbps:    h.bw,
					RAMGB:            ramGB,
					CPUcores:         int(cpuCores),
					DiskCapacityGB:   diskCapGB,
					DiskFreeGB:       diskFreeGB,
					ISP:              isp,
					Country:          country,
					HasXDP:           h.hasXDP,
					Category:         classifyCategory(h.bw),
					ProtectionStatus: pStatus.status,
					ProtectionReason: pStatus.reason,
					OpenPorts:        []int{h.port},
				}

				mu.Lock()
				results = append(results, res)
				atomic.AddInt64(&foundCount, 1)
				fmt.Print("\r\033[K")
				printResult(res)
				mu.Unlock()

				fullLine := fmt.Sprintf("%s:%d | %s | %.1fGB | %d | %.1f/%.1fGB | %s | %s | %s | %v | %d\n",
					h.ip, h.port, fmtBW(h.bw), ramGB, int(cpuCores), diskFreeGB, diskCapGB,
					pStatus.status, isp, country, h.hasXDP, h.port)

				// Write to three default files (filtered)
				if h.bw >= 100 {
					bigWriter.Write(fullLine)
				} else if h.hasXDP || pStatus.status == "PROTECTED" || pStatus.status == "PARTIAL" {
					protectedWriter.Write(fullLine)
				} else {
					unprotectedWriter.Write(fullLine)
				}

				// Write to extra output file if provided
				if extraWriter != nil {
					extraWriter.Write(fullLine)
				}

				resultCache.Store(key, struct{}{})
			}
		}()
	}

	workerCount := runtime.NumCPU() * 2000
	if workerCount < 8000 {
		workerCount = 8000
	}
	var wg sync.WaitGroup

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   400 * time.Millisecond,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        workerCount * 2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		DisableKeepAlives:   false,
		ResponseHeaderTimeout: 400 * time.Millisecond,
	}

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{
				Timeout:   800 * time.Millisecond,
				Transport: transport,
			}
			for j := range jobs {
				atomic.AddInt64(&attempted, 1)
				bwGbps, hasXDP := getNodeSpeed(client, j.IP, j.Port)
				if bwGbps == 0 || bwGbps < minBandwidth {
					continue
				}
				hitCh <- hit{ip: j.IP, port: j.Port, bw: bwGbps, hasXDP: hasXDP}
			}
		}()
	}

	wg.Wait()
	close(hitCh)
	ppWg.Wait()
	close(stopProgress)

	elapsed := time.Since(startTime)
	fmt.Println()
	sepFn := color.New(color.FgCyan).SprintFunc()
	checkFn := color.New(color.FgHiGreen, color.Bold).SprintFunc()
	labelFn := color.New(color.Faint).SprintFunc()
	valFn := color.New(color.FgHiWhite, color.Bold).SprintFunc()
	fmt.Println("  " + sepFn("--------------------------------------"))
	fmt.Printf("  %s  %s %s  %s %s  %s %s\n",
		checkFn(">"),
		labelFn("found"), valFn(fmt.Sprintf("%d", len(results))),
		labelFn("scanned"), valFn(fmt.Sprintf("%d", atomic.LoadInt64(&attempted))),
		labelFn("time"), valFn(elapsed.Round(time.Second).String()))
	fmt.Println()
}

// ---------- System metrics scraping (improved) ----------
func scrapeSystemMetrics(ip string, port int) (ramGB, cpuCores float64, diskCapGB, diskFreeGB float64) {
	client := &http.Client{Timeout: 600 * time.Millisecond}
	url := fmt.Sprintf("http://%s:%d/metrics", ip, port)
	resp, err := client.Get(url)
	if err != nil {
		return 0, 0, 0, 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, 0, 0, 0
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20)) // 1MB
	cpuSet := make(map[string]struct{})

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "node_memory_MemTotal_bytes") {
			if val := extractValue(line); val > 0 {
				ramGB = val / (1024 * 1024 * 1024)
			}
		}

		if strings.HasPrefix(line, "node_cpu_seconds_total{") {
			if cpu := extractCPULabel(line); cpu != "" {
				cpuSet[cpu] = struct{}{}
			}
		}

		if strings.HasPrefix(line, "node_filesystem_size_bytes{") && strings.Contains(line, `mountpoint="/"`) {
			if val := extractValue(line); val > 0 {
				diskCapGB = val / (1024 * 1024 * 1024)
			}
		}
		if strings.HasPrefix(line, "node_filesystem_free_bytes{") && strings.Contains(line, `mountpoint="/"`) {
			if val := extractValue(line); val > 0 {
				diskFreeGB = val / (1024 * 1024 * 1024)
			}
		}
	}
	cpuCores = float64(len(cpuSet))
	return
}

func extractCPULabel(line string) string {
	const prefix = `cpu="`
	idx := strings.Index(line, prefix)
	if idx == -1 {
		return ""
	}
	start := idx + len(prefix)
	end := strings.IndexByte(line[start:], '"')
	if end == -1 {
		return ""
	}
	return line[start : start+end]
}

func extractValue(line string) float64 {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0
	}
	val, err := strconv.ParseFloat(parts[len(parts)-1], 64)
	if err != nil {
		return 0
	}
	return val
}

// ---------- Bandwidth parsing (optimized) ----------
func getNodeSpeed(client *http.Client, ip string, port int) (float64, bool) {
	url := fmt.Sprintf("http://%s:%d/metrics", ip, port)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, false
	}
	return parseMetricsStream(resp.Body)
}

func parseMetricsStream(body io.Reader) (maxGbps float64, hasXDP bool) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	var speedPrefix = []byte("node_network_speed_bytes{")
	var xdpKeywords = [][]byte{[]byte("ebpf_"), []byte("xdp_")}

	for scanner.Scan() {
		line := scanner.Bytes()
		if !hasXDP {
			for _, kw := range xdpKeywords {
				if bytes.Contains(line, kw) {
					hasXDP = true
					break
				}
			}
		}
		if len(line) < 25 || line[0] != 'n' {
			continue
		}
		if !bytes.HasPrefix(line, speedPrefix) {
			continue
		}
		device, speedBytes := extractDeviceAndValueBytes(line)
		if device == "" || speedBytes <= 0 {
			continue
		}
		if speedBytes >= 536_870_911_875_000.0/2 {
			continue
		}
		if !isPhysicalInterface(device) {
			continue
		}
		gbps := (speedBytes * 8) / 1e9
		if gbps > 800 {
			continue
		}
		if gbps > maxGbps {
			maxGbps = gbps
		}
	}
	return
}

func extractDeviceAndValueBytes(line []byte) (string, float64) {
	const marker = `device="`
	idx := bytes.Index(line, []byte(marker))
	if idx == -1 {
		return "", 0
	}
	start := idx + len(marker)
	end := bytes.IndexByte(line[start:], '"')
	if end == -1 {
		return "", 0
	}
	device := string(line[start : start+end])
	spaceIdx := bytes.LastIndexByte(line, ' ')
	if spaceIdx == -1 || spaceIdx >= len(line)-1 {
		return device, 0
	}
	val, err := strconv.ParseFloat(string(line[spaceIdx+1:]), 64)
	if err != nil {
		return device, 0
	}
	return device, val
}

// ---------- Physical interface detection ----------
var virtualPrefixes = []string{
	"lo", "veth", "cali", "docker", "br-", "tun", "vxlan",
	"flannel", "tailscale", "macvlan", "bond", "vlan", "gre",
	"geneve", "virbr", "lxc", "lxd", "cni", "cilium", "kube", "vtun",
}
var physicalPrefixes = []string{"eth", "ens", "eno", "enp", "em"}

func isPhysicalInterface(device string) bool {
	low := strings.ToLower(device)
	for _, v := range virtualPrefixes {
		if strings.Contains(low, v) {
			return false
		}
	}
	for _, p := range physicalPrefixes {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	if len(low) >= 2 && low[0] == 'p' && low[1] >= '0' && low[1] <= '9' {
		return true
	}
	return false
}

// ---------- Protection classification ----------
func classifyProtection(ispLower string, hostnames []string) protEntry {
	var sb strings.Builder
	for _, h := range hostnames {
		sb.WriteString(strings.ToLower(h))
		sb.WriteByte(' ')
	}
	hostStr := sb.String()

	check := func(m map[string]protEntry) (protEntry, bool) {
		for k, v := range m {
			if strings.Contains(ispLower, k) || strings.Contains(hostStr, k) {
				return v, true
			}
		}
		return protEntry{}, false
	}

	if e, ok := check(protectedMap); ok {
		return e
	}
	if e, ok := check(unprotectedMap); ok {
		return e
	}
	if e, ok := check(cloudMap); ok {
		return e
	}
	return protEntry{status: "UNKNOWN", reason: "Unknown Status", clr: color.FgCyan}
}

// ---------- IP info (cached) ----------
func getIPInfoCached(ipStr string) (string, string) {
	prefix := ipTo24Prefix(ipStr)
	if cached, ok := ispCache.Load(prefix); ok {
		e := cached.(ispCacheEntry)
		return e.isp, e.country
	}
	isp, country := getIPInfo(ipStr)
	ispCache.Store(prefix, ispCacheEntry{isp: isp, country: country})
	return isp, country
}

var onlineClient = &http.Client{Timeout: 2 * time.Second}
var onlineSem = make(chan struct{}, 5)

func getIPInfo(ipStr string) (string, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "Unknown", "Unknown"
	}
	var isp, country string
	if asnDB != nil {
		if rec, err := asnDB.ASN(ip); err == nil {
			isp = rec.AutonomousSystemOrganization
		}
	}
	if cityDB != nil {
		if rec, err := cityDB.City(ip); err == nil {
			country = rec.Country.Names["en"]
		}
	}
	if isp == "" || country == "" {
		select {
		case onlineSem <- struct{}{}:
			oISP, oCountry, ok := getIPInfoOnline(ipStr)
			<-onlineSem
			if ok {
				if isp == "" {
					isp = oISP
				}
				if country == "" {
					country = oCountry
				}
			}
		default:
		}
	}
	if isp == "" {
		isp = "Unknown"
	}
	if country == "" {
		country = "Unknown"
	}
	return isp, country
}

func getIPInfoOnline(ipStr string) (string, string, bool) {
	if isp, c, err := queryIPAPI(ipStr); err == nil && isp != "" && c != "" {
		return isp, c, true
	}
	if isp, c, err := queryIPAPICo(ipStr); err == nil && isp != "" && c != "" {
		return isp, c, true
	}
	return "", "", false
}

func queryIPAPI(ipStr string) (string, string, error) {
	resp, err := onlineClient.Get("http://ip-api.com/json/" + ipStr)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var d struct {
		Status  string `json:"status"`
		ISP     string `json:"isp"`
		AS      string `json:"as"`
		Country string `json:"country"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return "", "", err
	}
	if d.Status != "success" {
		return "", "", fmt.Errorf("ip-api: %s", d.Status)
	}
	isp := d.ISP
	if isp == "" {
		isp = d.AS
	}
	return isp, d.Country, nil
}

func queryIPAPICo(ipStr string) (string, string, error) {
	req, _ := http.NewRequest("GET", "https://ipapi.co/"+ipStr+"/json/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := onlineClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var d struct {
		Org         string `json:"org"`
		ASN         string `json:"asn"`
		CountryName string `json:"country_name"`
		Error       bool   `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return "", "", err
	}
	if d.Error {
		return "", "", fmt.Errorf("ipapi.co error")
	}
	isp := d.Org
	if isp == "" {
		isp = d.ASN
	}
	return isp, d.CountryName, nil
}

// ---------- Reverse DNS ----------
func reverseDNSWithTimeout(ip string, timeout time.Duration) []string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	names, _ := net.DefaultResolver.LookupAddr(ctx, ip)
	return names
}

// ---------- Helpers ----------
var garbageKeywords = []string{
	"stat pid", "stat uptime", "stat cmd_get", "ssh-",
	"http/1.1", "unsolicited", "athinfod", "bad request",
}

func isGarbage(line string) bool {
	low := strings.ToLower(line)
	for _, b := range garbageKeywords {
		if strings.Contains(low, b) {
			return true
		}
	}
	return false
}

func classifyCategory(gbps float64) string {
	if gbps >= 100 {
		return "HIGH"
	}
	return "LOW"
}

func fmtBW(bw float64) string {
	if bw >= 1000 {
		tb := bw / 1000
		if tb == math.Trunc(tb) {
			return fmt.Sprintf("%dTb", int(tb))
		}
		return fmt.Sprintf("%.1fTb", tb)
	}
	if bw == math.Trunc(bw) {
		return fmt.Sprintf("%dGb", int(bw))
	}
	return fmt.Sprintf("%.1fGb", bw)
}

func parseIPAndOptionalPort(raw string) (string, int) {
	if strings.Contains(raw, ":") {
		parts := strings.Split(raw, ":")
		ip := parts[0]
		portStr := parts[len(parts)-1]
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
			return ip, p
		}
	}
	return raw, 0
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func cidrIPCount(ipnet *net.IPNet) int64 {
	ones, bits := ipnet.Mask.Size()
	if bits == 0 {
		return 0
	}
	exponent := bits - ones
	if exponent >= 62 {
		return math.MaxInt64
	}
	return 1 << exponent
}

// ---------- Pretty print ----------
func printResult(res Result) {
	sep := color.New(color.Faint).Sprint(" | ")
	catClr := color.New(color.FgHiGreen, color.Bold)
	if res.Category != "HIGH" {
		catClr = color.New(color.FgHiBlue, color.Bold)
	}
	catTag := catClr.Sprintf("[%s]", res.Category)

	pTag := protBadge(res.ProtectionStatus)
	bwTag := bwBadge(res.BandwidthGbps)
	ipStr := color.New(color.FgHiWhite, color.Bold).Sprintf("%s:%d", res.IP, res.Port)
	ispStr := color.New(color.FgWhite).Sprint(res.ISP)
	countryStr := color.New(color.FgYellow).Sprint(res.Country)

	xdpStr := ""
	if res.HasXDP {
		xdpStr = " \033[43m\033[30m\033[1m XDP \033[0m"
	}

	extra := ""
	if res.RAMGB > 0 || res.CPUcores > 0 {
		extra = fmt.Sprintf(" [%dC %.1fGB]", res.CPUcores, res.RAMGB)
	}

	fmt.Printf("  %s %s %s%s%s%s%s%s%s\n",
		catTag, pTag,
		ipStr, sep,
		bwTag, sep,
		ispStr+sep+countryStr,
		extra,
		xdpStr)
}

func bwBadge(bw float64) string {
	label := " " + fmtBW(bw) + " "
	const rst = "\033[0m"
	switch {
	case bw >= 100:
		return "\033[48;5;88m\033[97m\033[1m" + label + rst
	case bw >= 50:
		return "\033[101m\033[97m\033[1m" + label + rst
	case bw >= 30:
		return "\033[48;5;208m\033[30m\033[1m" + label + rst
	case bw >= 10:
		return "\033[43m\033[30m\033[1m" + label + rst
	default:
		return "\033[42m\033[30m\033[1m" + label + rst
	}
}

func protBadge(status string) string {
	label := " " + status + " "
	const rst = "\033[0m"
	switch status {
	case "PROTECTED":
		return "\033[41m\033[97m\033[1m" + label + rst
	case "UNPROTECTED":
		return "\033[48;5;22m\033[97m\033[1m" + label + rst
	case "PARTIAL":
		return "\033[48;5;136m\033[30m\033[1m" + label + rst
	default:
		return "\033[100m\033[97m" + label + rst
	}
}

// ---------- Async file writer ----------
type asyncWriter struct {
	ch   chan string
	done chan struct{}
}

func newAsyncWriter(f *os.File) *asyncWriter {
	aw := &asyncWriter{
		ch:   make(chan string, 8192),
		done: make(chan struct{}),
	}
	go func() {
		defer close(aw.done)
		bw := bufio.NewWriterSize(f, 256*1024)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case s, ok := <-aw.ch:
				if !ok {
					bw.Flush()
					return
				}
				bw.WriteString(s)
			case <-ticker.C:
				bw.Flush()
			}
		}
	}()
	return aw
}

func (aw *asyncWriter) Write(s string) { aw.ch <- s }
func (aw *asyncWriter) Close() {
	close(aw.ch)
	<-aw.done
}
