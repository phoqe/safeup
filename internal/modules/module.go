package modules

type CheckStatus int

const (
	StatusPass CheckStatus = iota
	StatusFail
	StatusWarn
)

type Check struct {
	Name     string
	Status   CheckStatus
	Expected string
	Actual   string
}

type VerifyResult struct {
	ModuleName string
	Checks     []Check
}

func (r *VerifyResult) AllPassed() bool {
	for _, c := range r.Checks {
		if c.Status != StatusPass {
			return false
		}
	}
	return true
}
