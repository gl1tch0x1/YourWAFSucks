package techniques

import "strings"

func (Encoding) Name() string { return "encoding" }

type Encoding struct{}

func (Encoding) Generate(ctx Context) []Payload {
    // Segment-level mutations
    parts := strings.Split(strings.TrimPrefix(ctx.Target, "http://"), "/")
    if len(parts) < 2 {
        parts = strings.Split(strings.TrimPrefix(ctx.Target, "https://"), "/")
    }

    muts := []string{
        "%00", "%20", "%2f", "%2e", "%09", "%0a", "%0d",
        "%c0%af", "%ef%bc%8f", "%252e", "%252f", "%u002e", "%u002f",
    }
    var out []Payload
    for _, m := range muts {
        out = append(out, Payload{
            Method:      "GET",
            URL:         ctx.Target + "/" + m,
            Description: "Encoding: " + m,
            Detail:      m,
            Technique:   "encoding",
        })
    }
    return out
}