package techniques

import (
	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/score"
)

type Context struct {
	Target   string
	BypassIP string
}

type Payload struct {
	Method      string
	URL         string
	Description string
	Detail      string
	Headers     map[string]string
	Body        []byte
	Technique   string
}

type Result struct {
	Payload     Payload
	Response    *httpclient.Response
	Score       score.Result
	ReplayCount int
}

type Technique interface {
	Name() string
	Generate(ctx Context) []Payload
}

type Registry struct {
	techs map[string]Technique
	order []string
}

func NewRegistry() *Registry {
	return &Registry{techs: make(map[string]Technique)}
}

func (r *Registry) Register(t Technique) {
	r.techs[t.Name()] = t
	r.order = append(r.order, t.Name())
}

func (r *Registry) Get(name string) Technique {
	return r.techs[name]
}

func (r *Registry) Names() []string {
	return r.order
}

func RegisterAll(r *Registry) {
	r.Register(&Verbs{})
	r.Register(&Headers{})
	r.Register(&EndPaths{})
	r.Register(&MidPaths{})
	r.Register(&Encoding{})
	r.Register(&Raw{})
	r.Register(&Protocol{})
	r.Register(&Advanced{})
	r.Register(&SMT{})
	r.Register(&Unicode{})
}
