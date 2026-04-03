package pipeline

import "context"

// DecisionStep finalizes ALLOW decisions.
type DecisionStep struct{}

func NewDecisionStep() *DecisionStep { return &DecisionStep{} }

func (s *DecisionStep) Name() string { return "decision_engine" }

func (s *DecisionStep) Execute(_ context.Context, sc *SecurityContext) {
	if sc.Denied {
		return
	}
	sc.FinalizeAllow()
}
