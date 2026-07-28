package parser

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"proxylink/pkg/model"
	"proxylink/pkg/util"
)

// ParseSocks parses SOCKS5 share links with clear-text or Base64 user info.
func ParseSocks(uri string) (*model.ProfileItem, error) {
	uri = strings.TrimSpace(uri)
	schemeEnd := strings.Index(uri, "://")
	if schemeEnd < 0 {
		return nil, fmt.Errorf("invalid SOCKS URI")
	}
	scheme := strings.ToLower(uri[:schemeEnd])
	if scheme != "socks" && scheme != "socks5" {
		return nil, fmt.Errorf("unsupported SOCKS scheme: %s", scheme)
	}

	body := uri[schemeEnd+3:]
	remarks := ""
	if before, after, ok := strings.Cut(body, "#"); ok {
		body = before
		remarks = util.URLDecode(after)
	}

	server, port, username, password, err := parseSocksBody(body, true)
	if err != nil {
		return nil, err
	}

	config := model.NewProfileItem(model.SOCKS)
	config.Remarks = remarks
	if config.Remarks == "" {
		config.Remarks = "none"
	}
	config.Server = server
	config.ServerPort = port
	config.Username = username
	config.Password = password

	return config, nil
}

func parseSocksBody(body string, allowLegacyBase64 bool) (server, port, username, password string, err error) {
	if firstAt := strings.Index(body, "@"); firstAt >= 0 {
		lastAt := strings.LastIndex(body, "@")
		userInfo := body[:lastAt]
		serverInfo := body[lastAt+1:]
		server, port, err = parseSocksServer(serverInfo)
		if err != nil {
			return "", "", "", "", err
		}
		username, password, err = parseSocksUserInfo(userInfo)
		if err != nil {
			return "", "", "", "", err
		}
		return server, port, username, password, nil
	}

	server, port, err = parseSocksServer(body)
	if err == nil {
		return server, port, "", "", nil
	}
	if !allowLegacyBase64 {
		return "", "", "", "", err
	}

	decoded, decodeErr := util.Base64Decode(body)
	if decodeErr != nil || decoded == body {
		return "", "", "", "", err
	}
	return parseSocksBody(decoded, false)
}

func parseSocksServer(serverInfo string) (string, string, error) {
	u, err := url.Parse("socks://" + util.FixIllegalURL(serverInfo))
	if err != nil {
		return "", "", fmt.Errorf("invalid SOCKS server: %w", err)
	}
	server := u.Hostname()
	port := u.Port()
	if server == "" {
		return "", "", fmt.Errorf("missing SOCKS server")
	}
	if port == "" {
		return "", "", fmt.Errorf("missing SOCKS server port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", fmt.Errorf("invalid SOCKS server port: %s", port)
	}
	return server, port, nil
}

func parseSocksUserInfo(userInfo string) (string, string, error) {
	decodedUserInfo, err := url.PathUnescape(userInfo)
	if err != nil {
		return "", "", fmt.Errorf("invalid SOCKS user info: %w", err)
	}
	if username, password, ok := strings.Cut(decodedUserInfo, ":"); ok {
		return username, password, nil
	}

	base64UserInfo, decodeErr := util.Base64Decode(decodedUserInfo)
	if decodeErr == nil {
		if username, password, ok := strings.Cut(base64UserInfo, ":"); ok {
			return username, password, nil
		}
	}

	// Keep a username-only URI instead of rejecting valid empty-password auth.
	return decodedUserInfo, "", nil
}

// ToSocksURI generates a canonical clear-text SOCKS5 share link.
func ToSocksURI(config *model.ProfileItem) string {
	u := &url.URL{
		Scheme:   "socks",
		Host:     net.JoinHostPort(config.Server, config.ServerPort),
		Fragment: config.Remarks,
	}
	if config.Username != "" || config.Password != "" {
		u.User = url.UserPassword(config.Username, config.Password)
	}
	return u.String()
}
