package techniques

func (Protocol) Name() string { return "protocol" }

type Protocol struct{}

func (Protocol) Generate(ctx Context) []Payload {
    return []Payload{
        {Method: "GET", URL: ctx.Target, Description: "HTTP/1.0", Technique: "protocol"},
        {Method: "GET", URL: ctx.Target, Description: "HTTP/1.1", Technique: "protocol"},
        {Method: "GET", URL: ctx.Target, Description: "HTTP/2", Technique: "protocol"},
    }
}