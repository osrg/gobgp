package table

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
)

// TestWatchPolicyReferencesAreCountedPerPolicy checks that a policy used by
// several watchers stays protected until the last one releases it, and that
// a reload that defines the policy again under the same name gives the new
// policy references of its own: the release of a watcher of the old policy,
// which may come after the reload, neither protects nor unprotects the new
// one.
func TestWatchPolicyReferencesAreCountedPerPolicy(t *testing.T) {
	del := func(r *RoutingPolicy) error { return r.DeletePolicy(&Policy{Name: "p"}, true, false) }

	t.Run("two watchers of one policy", func(t *testing.T) {
		r := NewRoutingPolicy(logger)
		require.NoError(t, r.AddPolicy(&Policy{Name: "p"}, false))
		first, ok := r.AcquireWatchPolicy("p")
		require.True(t, ok)
		second, ok := r.AcquireWatchPolicy("p")
		require.True(t, ok)
		require.Same(t, first, second)

		require.Error(t, del(r))
		r.ReleaseWatchPolicy(first)
		require.Error(t, del(r), "releasing one watcher unprotected the policy for the other")
		r.ReleaseWatchPolicy(second)
		require.NoError(t, del(r))
		assert.Empty(t, r.watchRefs)
	})

	t.Run("an unknown policy", func(t *testing.T) {
		r := NewRoutingPolicy(logger)
		_, ok := r.AcquireWatchPolicy("missing")
		assert.False(t, ok)
		assert.Empty(t, r.watchRefs)
	})

	t.Run("a reload with old and new watchers on one name", func(t *testing.T) {
		r := NewRoutingPolicy(logger)
		require.NoError(t, r.AddPolicy(&Policy{Name: "p"}, false))
		old, ok := r.AcquireWatchPolicy("p")
		require.True(t, ok)

		require.NoError(t, r.Reset(&oc.RoutingPolicy{PolicyDefinitions: []oc.PolicyDefinition{{Name: "p"}}}, nil))
		assert.False(t, r.IsWatchPolicyCurrent(old), "the policy was replaced by the reload")
		_, current := r.MatchWatchPolicy(old, &Path{}, nil)
		assert.False(t, current)

		// The old watcher has not released yet. The new policy is not in use
		// by it: it can be deleted.
		require.NoError(t, del(r))
		require.NoError(t, r.Reset(&oc.RoutingPolicy{PolicyDefinitions: []oc.PolicyDefinition{{Name: "p"}}}, nil))

		// A new watcher takes the new policy; the old one's late release
		// leaves its reference alone.
		replaced, ok := r.AcquireWatchPolicy("p")
		require.True(t, ok)
		require.NotSame(t, old, replaced)
		r.ReleaseWatchPolicy(old)
		require.Error(t, del(r), "the release of the old policy unprotected the new one")
		r.ReleaseWatchPolicy(replaced)
		require.NoError(t, del(r))
		assert.Empty(t, r.watchRefs)
	})
}
