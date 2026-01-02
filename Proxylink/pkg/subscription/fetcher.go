package subscription

import (
	"crypto/tls"
	"io"
	"net/http"
	"time"
)

// Fetcher 订阅获取器
type Fetcher struct {
	client     *http.Client
	userAgent  string
	skipVerify bool
}

// NewFetcher 创建新的 Fetcher
func NewFetcher() *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		userAgent:  "v2rayN/6.0",
		skipVerify: false,
	}
}

// NewFetcherInsecure 创建跳过证书验证的 Fetcher
func NewFetcherInsecure() *Fetcher {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &Fetcher{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		userAgent:  "v2rayN/6.0",
		skipVerify: true,
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
	if insecure {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		f.client.Transport = transport
	} else {
		f.client.Transport = nil
	}
	f.skipVerify = insecure
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
