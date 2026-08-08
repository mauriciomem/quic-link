package tunnel

import (
	"context"
	"testing"

	"github.com/mauriciomem/quic-link/internal/router"
)

// TestDataRouter_IsSatisfiedByTheRealRouteTable keeps the narrow data-plane
// interface honest in the one direction a compiler cannot check on its own:
// that it is still implemented by the real thing, not just by a test double.
// If the route table's dial signature ever changes, this fails at build time
// here rather than at the call site.
func TestDataRouter_IsSatisfiedByTheRealRouteTable(t *testing.T) {
	var _ dataRouter = (*router.Router)(nil)
}

// TestDataRouter_ExposesDialingOnly is the structural guarantee stated as a
// test. The data-plane handlers hold this interface and nothing wider, so the
// method set is the boundary: if a mutator were ever added to it, the type
// assertion below would start succeeding and this test would fail.
//
// It is written as a negative assertion on purpose. A test that only checked
// "Dial is present" would still pass on an interface that had grown a way to
// reprogram the route table, which is the thing actually worth preventing.
func TestDataRouter_ExposesDialingOnly(t *testing.T) {
	var d dataRouter = dialOnlyStub{}

	if _, ok := d.(interface {
		AddVhost(host string, port int) error
	}); ok {
		t.Error("the data-plane interface exposes a way to publish a name; " +
			"a stream handler must not be able to change what the agent serves")
	}
	if _, ok := d.(interface{ RouteDetails() []router.RouteDetail }); ok {
		t.Error("the data-plane interface exposes the administrative read surface; " +
			"forwarding a stream does not require listing the route table")
	}
}

type dialOnlyStub struct{ dataRouter }

var _ = context.Background
