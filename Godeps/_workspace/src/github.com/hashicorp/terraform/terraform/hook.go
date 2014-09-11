package terraform

// HookAction is an enum of actions that can be taken as a result of a hook
// callback. This allows you to modify the behavior of Terraform at runtime.
type HookAction byte

const (
	// HookActionContinue continues with processing as usual.
	HookActionContinue HookAction = iota

	// HookActionHalt halts immediately: no more hooks are processed
	// and the action that Terraform was about to take is cancelled.
	HookActionHalt
)

// Hook is the interface that must be implemented to hook into various
// parts of Terraform, allowing you to inspect or change behavior at runtime.
//
// There are MANY hook points into Terraform. If you only want to implement
// some hook points, but not all (which is the likely case), then embed the
// NilHook into your struct, which implements all of the interface but does
// nothing. Then, override only the functions you want to implement.
type Hook interface {
	// PreApply and PostApply are called before and after a single
	// resource is applied. The error argument in PostApply is the
	// error, if any, that was returned from the provider Apply call itself.
	PreApply(string, *ResourceState, *ResourceDiff) (HookAction, error)
	PostApply(string, *ResourceState, error) (HookAction, error)

	// PreDiff and PostDiff are called before and after a single resource
	// resource is diffed.
	PreDiff(string, *ResourceState) (HookAction, error)
	PostDiff(string, *ResourceDiff) (HookAction, error)

	// Provisioning hooks
	PreProvisionResource(string, *ResourceState) (HookAction, error)
	PostProvisionResource(string, *ResourceState) (HookAction, error)
	PreProvision(string, string) (HookAction, error)
	PostProvision(string, string) (HookAction, error)

	// PreRefresh and PostRefresh are called before and after a single
	// resource state is refreshed, respectively.
	PreRefresh(string, *ResourceState) (HookAction, error)
	PostRefresh(string, *ResourceState) (HookAction, error)
}

// NilHook is a Hook implementation that does nothing. It exists only to
// simplify implementing hooks. You can embed this into your Hook implementation
// and only implement the functions you are interested in.
type NilHook struct{}

func (*NilHook) PreApply(string, *ResourceState, *ResourceDiff) (HookAction, error) {
	return HookActionContinue, nil
}

func (*NilHook) PostApply(string, *ResourceState, error) (HookAction, error) {
	return HookActionContinue, nil
}

func (*NilHook) PreDiff(string, *ResourceState) (HookAction, error) {
	return HookActionContinue, nil
}

func (*NilHook) PostDiff(string, *ResourceDiff) (HookAction, error) {
	return HookActionContinue, nil
}

func (*NilHook) PreProvisionResource(string, *ResourceState) (HookAction, error) {
	return HookActionContinue, nil
}

func (*NilHook) PostProvisionResource(string, *ResourceState) (HookAction, error) {
	return HookActionContinue, nil
}

func (*NilHook) PreProvision(string, string) (HookAction, error) {
	return HookActionContinue, nil
}

func (*NilHook) PostProvision(string, string) (HookAction, error) {
	return HookActionContinue, nil
}

func (*NilHook) PreRefresh(string, *ResourceState) (HookAction, error) {
	return HookActionContinue, nil
}

func (*NilHook) PostRefresh(string, *ResourceState) (HookAction, error) {
	return HookActionContinue, nil
}

// handleHook turns hook actions into panics. This lets you use the
// panic/recover mechanism in Go as a flow control mechanism for hook
// actions.
func handleHook(a HookAction, err error) {
	if err != nil {
		// TODO: handle errors
	}

	switch a {
	case HookActionContinue:
		return
	case HookActionHalt:
		panic(HookActionHalt)
	}
}
