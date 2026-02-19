package subscription

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"
)

// 公共 DNS 服务器列表
var publicDNSServers = []string{
	"8.8.8.8:53",      // Google
	"1.1.1.1:53",      // Cloudflare
	"223.5.5.5:53",    // 阿里 DNS
	"119.29.29.29:53", // 腾讯 DNS
}

// Fetcher 订阅获取器
type Fetcher struct {
	client     *http.Client
	userAgent  string
	skipVerify bool
	useDNS     bool // 是否使用自定义 DNS
}

// createCustomDialer 创建使用公共 DNS 的自定义拨号器
func createCustomDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// 依次尝试公共 DNS 服务器
				d := net.Dialer{Timeout: 5 * time.Second}
				for _, dns := range publicDNSServers {
					conn, err := d.DialContext(ctx, "udp", dns)
					if err == nil {
						return conn, nil
					}
				}
				// 所有公共 DNS 都失败，回退到系统默认
				return d.DialContext(ctx, network, address)
			},
		},
	}
}

// createTransport 创建 HTTP Transport
func createTransport(insecure, useDNS bool) *http.Transport {
	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if insecure {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	if useDNS {
		dialer := createCustomDialer()
		transport.DialContext = dialer.DialContext
	}

	return transport
}

// NewFetcher 创建新的 Fetcher
func NewFetcher() *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		userAgent:  "V2rayNG/2.0.0",
		skipVerify: false,
		useDNS:     false,
	}
}

// NewFetcherInsecure 创建跳过证书验证的 Fetcher
func NewFetcherInsecure() *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: createTransport(true, false),
		},
		userAgent:  "V2rayNG/2.0.0",
		skipVerify: true,
		useDNS:     false,
	}
}

// NewFetcherWithDNS 创建使用公共 DNS 的 Fetcher (适用于 Android)
func NewFetcherWithDNS() *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: createTransport(false, true),
		},
		userAgent:  "V2rayNG/2.0.0",
		skipVerify: false,
		useDNS:     true,
	}
}

// NewFetcherFull 创建完整配置的 Fetcher
func NewFetcherFull(insecure, useDNS bool) *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: createTransport(insecure, useDNS),
		},
		userAgent:  "V2rayNG/2.0.0",
		skipVerify: insecure,
		useDNS:     useDNS,
	}
}

// SetUserAgent 设置 User-Agent
func (f *Fetcher) SetUserAgent(ua string) {
	f.userAgent = ua
}

// SetTimeout 设置超时时间
func (f *Fetcher) SetTimeout(timeout time.Duration) {
	f.client.Timeout = timeout
}

// SetInsecure 设置是否跳过证书验证
func (f *Fetcher) SetInsecure(insecure bool) {
	f.skipVerify = insecure
	f.client.Transport = createTransport(insecure, f.useDNS)
}

// SetUseDNS 设置是否使用公共 DNS
func (f *Fetcher) SetUseDNS(useDNS bool) {
	f.useDNS = useDNS
	f.client.Transport = createTransport(f.skipVerify, useDNS)
}

// Fetch 获取订阅内容
func (f *Fetcher) Fetch(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", f.userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// FetchWithProxy 通过代理获取订阅内容
func (f *Fetcher) FetchWithProxy(url, proxyURL string) (string, error) {
	// TODO: 实现代理支持
	return f.Fetch(url)
}
