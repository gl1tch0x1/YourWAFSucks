package techniques

func (Raw) Name() string { return "raw" }

type Raw struct{}

func (Raw) Generate(ctx Context) []Payload {
    // Raw techniques are executed by the raw engine; here we just
    // expose metadata that tells the main engine to use raw mode.
    return []Payload{
        {Method: "RAW", URL: ctx.Target, Description: "raw: CL.TE desync", Technique: "raw"},
        {Method: "RAW", URL: ctx.Target, Description: "raw: TE.CL desync", Technique: "raw"},
        {Method: "RAW", URL: ctx.Target, Description: "raw: duplicate headers", Technique: "raw"},
        {Method: "RAW", URL: ctx.Target, Description: "raw: absolute URI", Technique: "raw"},
        {Method: "RAW", URL: ctx.Target, Description: "raw: conflicting authority", Technique: "raw"},
    }
}