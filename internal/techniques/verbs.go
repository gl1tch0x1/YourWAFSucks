package techniques

func (Verbs) Name() string { return "verbs" }

type Verbs struct{}

func (Verbs) Generate(ctx Context) []Payload {
    methods := []string{
        "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD",
        "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
        "MOVE", "LOCK", "UNLOCK", "SEARCH", "REPORT", "ACL", "CHECKOUT",
        "MERGE", "MKACTIVITY", "MKCALENDAR", "PURGE", "LINK", "UNLINK", "VIEW",
    }
    var out []Payload
    for _, m := range methods {
        out = append(out, Payload{
            Method:      m,
            URL:         ctx.Target,
            Description: "Method: " + m,
            Detail:      "HTTP " + m,
            Technique:   "verbs",
        })
    }
    return out
}