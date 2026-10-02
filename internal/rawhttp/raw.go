package rawhttp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Request struct {
	TargetURL string
	Payload   []byte // Raw HTTP request bytes
	Timeout   time.Duration
}

type Response struct {
	Status  int
	Headers map[string][]string
	Body    []byte
	Raw     []byte
}

// Send writes raw bytes to the target and reads the response.
func Send(req Request) (*Response, error) {
	u, err := url.Parse(req.TargetURL)
	if err != nil {
		return nil, err
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	timeout := req.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if u.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Hostname()})
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		conn = tlsConn
	}

	if _, err := conn.Write(req.Payload); err != nil {
		return nil, err
	}

	// Read response
	var raw bytes.Buffer
	buf := make([]byte, 65536)
	remaining := int64(4 * 1024 * 1024)
	for {
		if remaining == 0 {
			break
		}
		readBuf := buf
		if int64(len(readBuf)) > remaining {
			readBuf = readBuf[:remaining]
		}
		n, err := conn.Read(readBuf)
		if n > 0 {
			raw.Write(buf[:n])
			remaining -= int64(n)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			// timeout is fine — we've got what we've got
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			return nil, err
		}
	}

	return parseResponse(raw.Bytes())
}

func parseResponse(raw []byte) (*Response, error) {
	reader := bufio.NewReader(bytes.NewReader(raw))

	// Status line
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid status line: %q", statusLine)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}

	// Headers
	headers := make(map[string][]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			headers[k] = append(headers[k], v)
		}
	}

	body, _ := io.ReadAll(reader)

	return &Response{
		Status:  status,
		Headers: headers,
		Body:    body,
		Raw:     raw,
	}, nil
}
