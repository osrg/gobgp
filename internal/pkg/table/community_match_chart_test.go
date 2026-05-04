package table

import (
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// createPathWithCommunities builds a path that carries the given community values.
func createPathWithCommunities(communities []uint32) *Path {
	p := netip.MustParsePrefix("10.0.0.0/24")
	nlri, _ := bgp.NewIPAddrPrefix(p)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	commAttr := bgp.NewPathAttributeCommunities(communities)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nexthop,
		commAttr,
	}
	return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

// communityChartCase describes one benchmark scenario for community matching.
type communityChartCase struct {
	// Bench is a short b.Run() sub-name (ASCII, no spaces) so console output stays narrow.
	Bench    string
	Name     string // human-readable; used in failure messages
	Patterns []string
	Regexps  []string
	WantHit  bool
}

func communityChartCases() []communityChartCase {
	return []communityChartCase{
		{
			Bench:    "exact_1",
			Name:     "Exact / 1 pattern / match",
			Patterns: []string{"65000:100"},
			Regexps:  []string{"^65000:100$"},
			WantHit:  true,
		},
		{
			Bench: "exact_10_last",
			Name:  "Exact / 10 patterns / last matches",
			Patterns: func() []string {
				s := make([]string, 10)
				for i := range 9 {
					s[i] = fmt.Sprintf("65099:%d", i)
				}
				s[9] = "65002:999"
				return s
			}(),
			Regexps: func() []string {
				s := make([]string, 10)
				for i := range 9 {
					s[i] = fmt.Sprintf("^65099:%d$", i)
				}
				s[9] = "^65002:999$"
				return s
			}(),
			WantHit: true,
		},
		{
			Bench: "exact_10_none",
			Name:  "Exact / 10 patterns / no match",
			Patterns: func() []string {
				s := make([]string, 10)
				for i := range 10 {
					s[i] = fmt.Sprintf("65099:%d", i)
				}
				return s
			}(),
			Regexps: func() []string {
				s := make([]string, 10)
				for i := range 10 {
					s[i] = fmt.Sprintf("^65099:%d$", i)
				}
				return s
			}(),
			WantHit: false,
		},
		{
			Bench:    "wildcard_yes",
			Name:     "Wildcard regexp / match",
			Patterns: []string{"^65000:.*$"},
			Regexps:  []string{"^65000:.*$"},
			WantHit:  true,
		},
		{
			Bench:    "wildcard_no",
			Name:     "Wildcard regexp / no match",
			Patterns: []string{"^65099:.*$"},
			Regexps:  []string{"^65099:.*$"},
			WantHit:  false,
		},
		{
			Bench:    "mixed_miss_then_hit",
			Name:     "Mixed: regex(miss) + exact(hit)",
			Patterns: []string{"^65099:.*$", "65001:300"},
			Regexps:  []string{"^65099:.*$", "^65001:300$"},
			WantHit:  true,
		},
		{
			Bench:    "local_star_100",
			Name:     "Local-independent / ^[0-9]*:local / match",
			Patterns: []string{"^[0-9]*:100$"},
			Regexps:  []string{"^[0-9]*:100$"},
			WantHit:  true,
		},
		{
			Bench:    "local_star_alt",
			Name:     "Local-independent / ^[0-9]*:(a|b) / match",
			Patterns: []string{"^[0-9]*:(999|888)$"},
			Regexps:  []string{"^[0-9]*:(999|888)$"},
			WantHit:  true,
		},
		{
			Bench:    "local_star_miss",
			Name:     "Local-independent / no match",
			Patterns: []string{"^[0-9]*:42$"},
			Regexps:  []string{"^[0-9]*:42$"},
			WantHit:  false,
		},
		{
			Bench:    "local_dplus",
			Name:     "Local-independent / \\d+ form / match",
			Patterns: []string{`^\d+:300$`},
			Regexps:  []string{`^\d+:300$`},
			WantHit:  true,
		},
	}
}

func communityBenchmarkPath() *Path {
	return createPathWithCommunities([]uint32{
		65000<<16 | 100,
		65000<<16 | 200,
		65001<<16 | 100,
		65001<<16 | 300,
		65002<<16 | 999,
	})
}

// communityMatchLegacyLoop is the naive fmt.Sprintf + regexp baseline (not semantically identical to MATCH_OPTION_ANY).
func communityMatchLegacyLoop(path *Path, regs []*regexp.Regexp) {
	cs := path.GetCommunities()
	for _, x := range regs {
		for _, y := range cs {
			if x.MatchString(fmt.Sprintf("%d:%d", y>>16, y&0xffff)) {
				break
			}
		}
	}
}

// BenchmarkCommunityCondition runs New and Legacy side by side per scenario (names like exact_1/New, exact_1/Legacy).
//
//	go test ./internal/pkg/table/ -run '^$' -bench 'BenchmarkCommunityCondition' -benchmem -count=5
func BenchmarkCommunityCondition(b *testing.B) {
	path := communityBenchmarkPath()
	for _, sc := range communityChartCases() {
		b.Run(sc.Bench+"/New", func(b *testing.B) {
			cs, err := NewCommunitySet(oc.CommunitySet{
				CommunitySetName: "bench",
				CommunityList:    sc.Patterns,
			})
			if err != nil {
				b.Fatal(err)
			}
			cond := &CommunityCondition{set: cs, option: MATCH_OPTION_ANY}
			if got := cond.Evaluate(path, nil); got != sc.WantHit {
				b.Fatalf("%s: expected match=%v got %v", sc.Name, sc.WantHit, got)
			}
			b.ResetTimer()
			for range b.N {
				cond.Evaluate(path, nil)
			}
		})
		b.Run(sc.Bench+"/Legacy", func(b *testing.B) {
			regs := make([]*regexp.Regexp, len(sc.Regexps))
			for i, p := range sc.Regexps {
				regs[i] = regexp.MustCompile(p)
			}
			b.ResetTimer()
			for range b.N {
				communityMatchLegacyLoop(path, regs)
			}
		})
	}
}

func TestCommunityConditionCompareSummary(t *testing.T) {
	if os.Getenv("GOBGP_COMMUNITY_BENCH_COMPARE") != "1" {
		t.Skip(`set GOBGP_COMMUNITY_BENCH_COMPARE=1 to print New vs Legacy ns/op and speedup (legacy/new)`)
	}
	path := communityBenchmarkPath()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, err := fmt.Fprintln(tw, "bench\tnew ns/op\tlegacy ns/op\tlegacy/new\tname")
	if err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprintln(tw, "-----\t---------\t-----------\t--------\t----")
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range communityChartCases() {
		rNew := testing.Benchmark(func(b *testing.B) {
			cs, err := NewCommunitySet(oc.CommunitySet{
				CommunitySetName: "bench",
				CommunityList:    sc.Patterns,
			})
			if err != nil {
				b.Fatal(err)
			}
			cond := &CommunityCondition{set: cs, option: MATCH_OPTION_ANY}
			if got := cond.Evaluate(path, nil); got != sc.WantHit {
				b.Fatalf("%s: expected match=%v got %v", sc.Name, sc.WantHit, got)
			}
			b.ResetTimer()
			for range b.N {
				cond.Evaluate(path, nil)
			}
		})
		regs := make([]*regexp.Regexp, len(sc.Regexps))
		for i, p := range sc.Regexps {
			regs[i] = regexp.MustCompile(p)
		}
		rLeg := testing.Benchmark(func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
				communityMatchLegacyLoop(path, regs)
			}
		})
		newNs := float64(rNew.NsPerOp())
		legNs := float64(rLeg.NsPerOp())
		ratio := legNs / newNs
		_, err := fmt.Fprintf(tw, "%s\t%.0f\t%.0f\t%.2fx\t%s\n", sc.Bench, newNs, legNs, ratio, sc.Name)
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Flush()
}
