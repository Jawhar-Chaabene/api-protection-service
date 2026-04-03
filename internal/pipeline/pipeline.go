package pipeline

import "context"

// Step is one stage in the security verification pipeline.
type Step interface {
	Name() string
	Execute(ctx context.Context, sc *SecurityContext)
}

// Pipeline executes steps in strict order.
type Pipeline struct {
	steps []Step
}

// New creates a pipeline with ordered steps.
func New(steps ...Step) *Pipeline {
	return &Pipeline{steps: steps}
}

// Run executes each step until a denial occurs.
func (p *Pipeline) Run(ctx context.Context, sc *SecurityContext) {
	for _, step := range p.steps {
		if sc.Denied {
			return
		}
		step.Execute(ctx, sc)
	}
}
