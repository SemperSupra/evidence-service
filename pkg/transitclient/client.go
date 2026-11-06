// Package transitclient is a bounded OpenBao Transit API adapter for
// independently managed 256-bit data-encryption keys. It is not a vault,
// credential manager, or authorization service.
package transitclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxResponse = 16 << 10

var component = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// Client requires an existing derived, non-convergent Transit key. Give its
// token update-only privileges: no implicit key creation, deletion, export,
// token administration, or unrestricted access to other keys.
type Client struct {
	address string
	mount   string
	key     string
	token   string
	http    *http.Client
}

// New refuses plaintext remote endpoints, ambiguous paths and redirects.
// HTTP is admitted only for an explicit IP-literal loopback test server.
func New(baseURL, mount, key, token string, client *http.Client) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid Transit endpoint")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("Transit endpoint requires HTTPS (except IP loopback tests)")
		}
	}
	if !component.MatchString(mount) || !component.MatchString(key) || token == "" || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("invalid Transit configuration")
	}
	var h http.Client
	if client != nil {
		h = *client
	}
	if h.Timeout == 0 || h.Timeout > 10*time.Second {
		h.Timeout = 10 * time.Second
	}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{address: strings.TrimSuffix(u.String(), "/"), mount: mount, key: key, token: token, http: &h}, nil
}

type transitResponse struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
		Plaintext  string `json:"plaintext"`
	} `json:"data"`
}

func (c *Client) call(ctx context.Context, operation string, fields map[string]string) (transitResponse, error) {
	var output transitResponse
	body, err := json.Marshal(fields)
	if err != nil {
		return output, errors.New("Transit request encoding failed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.address+"/v1/"+c.mount+"/"+operation+"/"+c.key, bytes.NewReader(body))
	if err != nil {
		return output, errors.New("Transit request invalid")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return output, errors.New("Transit transport failed")
	}
	defer resp.Body.Close()
	limited, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(limited) > maxResponse {
		return output, errors.New("Transit response unavailable or oversized")
	}
	if resp.StatusCode != http.StatusOK {
		// Do not echo server errors: they could contain credentials or key data.
		return output, fmt.Errorf("Transit %s denied (status %d)", operation, resp.StatusCode)
	}
	if json.Unmarshal(limited, &output) != nil {
		return output, errors.New("Transit response malformed")
	}
	return output, nil
}

func validScope(scope []byte) bool { return len(scope) > 0 && len(scope) <= 512 }
func validCiphertext(text string) bool {
	return len(text) >= 12 && len(text) <= 8192 && strings.HasPrefix(text, "vault:v")
}

// WrapKey sends exactly one 32-byte synthetic/test-data DEK. The nonempty
// session+artifact scope is passed as OpenBao key-derivation context.
func (c *Client) WrapKey(ctx context.Context, dek, scope []byte) (string, error) {
	if len(dek) != 32 || !validScope(scope) {
		return "", errors.New("invalid DEK or derivation scope")
	}
	out, err := c.call(ctx, "encrypt", map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(dek),
		"context":   base64.StdEncoding.EncodeToString(scope),
	})
	if err != nil {
		return "", err
	}
	if !validCiphertext(out.Data.Ciphertext) {
		return "", errors.New("Transit returned invalid wrapped key")
	}
	return out.Data.Ciphertext, nil
}

// UnwrapKey is a privileged analysis-worker operation, never an agent API.
func (c *Client) UnwrapKey(ctx context.Context, ciphertext string, scope []byte) ([]byte, error) {
	if !validCiphertext(ciphertext) || !validScope(scope) {
		return nil, errors.New("invalid ciphertext or derivation scope")
	}
	out, err := c.call(ctx, "decrypt", map[string]string{
		"ciphertext": ciphertext,
		"context":    base64.StdEncoding.EncodeToString(scope),
	})
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil || len(key) != 32 {
		return nil, errors.New("Transit returned invalid DEK")
	}
	return key, nil
}

// RewrapKey upgrades Transit key versions without returning plaintext.
func (c *Client) RewrapKey(ctx context.Context, ciphertext string, scope []byte) (string, error) {
	if !validCiphertext(ciphertext) || !validScope(scope) {
		return "", errors.New("invalid ciphertext or derivation scope")
	}
	out, err := c.call(ctx, "rewrap", map[string]string{
		"ciphertext": ciphertext,
		"context":    base64.StdEncoding.EncodeToString(scope),
	})
	if err != nil {
		return "", err
	}
	if !validCiphertext(out.Data.Ciphertext) {
		return "", errors.New("Transit returned invalid rewrap")
	}
	return out.Data.Ciphertext, nil
}
