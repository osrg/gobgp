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

const gobgpCommunityBenchCompareEnv = "GOBGP_COMMUNITY_BENCH_COMPARE"

func communityBenchComparePrintEnabled() bool {
	return os.Getenv(gobgpCommunityBenchCompareEnv) == "1"
}

func writeCommunityBenchCompareChartHeader(tw *tabwriter.Writer) error {
	if _, err := fmt.Fprintln(tw, "bench\tnew ns/op\tlegacy ns/op\tlegacy/new\tname"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(tw, "-----\t---------\t-----------\t--------\t----")
	return err
}

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

func createPathWithExtCommunities(ecs []bgp.ExtendedCommunityInterface) *Path {
	p := netip.MustParsePrefix("10.0.0.0/24")
	nlri, _ := bgp.NewIPAddrPrefix(p)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		nexthop,
		bgp.NewPathAttributeExtendedCommunities(ecs),
	}
	return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

type communityChartCase struct {
	Bench    string
	Name     string
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

type extCommunityLegacyEntry struct {
	subtype bgp.ExtendedCommunityAttrSubType
	re      *regexp.Regexp
}

func parseExtCommunityLegacyEntries(patterns []string) ([]extCommunityLegacyEntry, error) {
	entries := make([]extCommunityLegacyEntry, len(patterns))
	for i, p := range patterns {
		st, re, err := ParseExtCommunityRegexp(p)
		if err != nil {
			return nil, err
		}
		entries[i] = extCommunityLegacyEntry{subtype: st, re: re}
	}
	return entries, nil
}

func extCommunityMatchLegacyLoop(path *Path, entries []extCommunityLegacyEntry) {
	ecs := path.GetExtCommunities()
	for _, x := range ecs {
		if !isTransitiveType(x) {
			continue
		}
		xStr := x.String()
		for _, e := range entries {
			if subTypeEqual(x, e.subtype) && e.re.MatchString(xStr) {
				break
			}
		}
	}
}

type extCommunityChartCase struct {
	Bench    string
	Name     string
	Patterns []string
	Path     *Path
	WantHit  bool
}

func extCommunityChartCases() []extCommunityChartCase {
	makeRT := func(as uint16, la uint32) bgp.ExtendedCommunityInterface {
		return bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, as, la, true)
	}
	makeExtPath := func(ecs ...bgp.ExtendedCommunityInterface) *Path {
		p := netip.MustParsePrefix("10.0.0.0/8")
		nlri, _ := bgp.NewIPAddrPrefix(p)
		nh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
		return NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false,
			[]bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(0), nh,
				bgp.NewPathAttributeExtendedCommunities(ecs),
			}, time.Now(), false)
	}

	pols1 := []string{
		"rt:^65448:614$", "rt:^65448:654$", "rt:^65448:664$", "rt:^65448:665$", "rt:^65448:684$",
		"rt:^65533:614$", "rt:^65533:654$", "rt:^65533:664$", "rt:^65533:684$",
	}
	pols2 := []string{
		"rt:^65440:.*$", "rt:^65442:.*$",
		"rt:^65448:614$", "rt:^65448:654$", "rt:^65448:664$", "rt:^65448:665$", "rt:^65448:684$",
		"rt:^65533:614$", "rt:^65533:616$", "rt:^65533:654$", "rt:^65533:656$",
		"rt:^65533:664$", "rt:^65533:666$", "rt:^65533:684$", "rt:^65533:686$",
	}
	pathSingle := makeExtPath(makeRT(65533, 664))
	pathMulti := makeExtPath(makeRT(65448, 614), makeRT(65533, 654), makeRT(65533, 664))

	return []extCommunityChartCase{
		{"rt9_exact_last", "RT / 9 exact patterns / last matches", pols1, pathSingle, true},
		{"rt9_exact_none", "RT / 9 exact patterns / no match", pols1, makeExtPath(makeRT(65099, 1)), false},
		{"rt15_mix_exact", "RT / 15 patterns / wildcard prefix / exact RT match", pols2, pathSingle, true},
		{"rt15_mix_wild", "RT / 15 patterns / wildcard prefix / wildcard RT match", pols2, makeExtPath(makeRT(65440, 100)), true},
		{"rt15_multi_3rt", "RT / 15 patterns / 3 RTs / early match", pols2, pathMulti, true},
		{"rt_local_digit", "RT / ^\\d+:local / bitmap-style / match", []string{`rt:^\d+:664$`}, pathSingle, true},
		{"rt_local_alt", "RT / ^\\d+:(a|b) / bitmap-style / match", []string{`rt:^\d+:(614|664)$`}, pathSingle, true},
		{"rt_local_miss", "RT / ^\\d+:local / no match", []string{`rt:^\d+:1$`}, pathSingle, false},
	}
}

// BenchmarkCommunityCondition and BenchmarkExtCommunityCondition run New vs Legacy side by side
// per scenario (e.g. exact_1/New, exact_1/Legacy and rt9_exact_last/New, rt9_exact_last/Legacy).
//
//	go test ./internal/pkg/table/ -run '^$' -bench 'BenchmarkCommunity(Condition|ExtCommunityCondition)$' -benchmem -count=5
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

func BenchmarkExtCommunityCondition(b *testing.B) {
	for _, sc := range extCommunityChartCases() {
		b.Run(sc.Bench+"/New", func(b *testing.B) {
			es, err := NewExtCommunitySet(oc.ExtCommunitySet{ExtCommunitySetName: "bench", ExtCommunityList: sc.Patterns})
			if err != nil {
				b.Fatal(err)
			}
			cond := &ExtCommunityCondition{set: es, option: MATCH_OPTION_ANY}
			if got := cond.Evaluate(sc.Path, nil); got != sc.WantHit {
				b.Fatalf("%s: expected match=%v got %v", sc.Name, sc.WantHit, got)
			}
			b.ResetTimer()
			for range b.N {
				cond.Evaluate(sc.Path, nil)
			}
		})
		b.Run(sc.Bench+"/Legacy", func(b *testing.B) {
			entries, err := parseExtCommunityLegacyEntries(sc.Patterns)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for range b.N {
				extCommunityMatchLegacyLoop(sc.Path, entries)
			}
		})
	}
}

func TestCommunityConditionCompareSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping community bench compare summary in short mode")
	}
	if !communityBenchComparePrintEnabled() {
		t.Skipf(`set %s=1 to print standard vs Legacy ns/op and speedup (legacy/new)`, gobgpCommunityBenchCompareEnv)
	}
	path := communityBenchmarkPath()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "\n[standard community]"); err != nil {
		t.Fatal(err)
	}
	if err := writeCommunityBenchCompareChartHeader(tw); err != nil {
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

func TestExtCommunityConditionCompareSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ext-community bench compare summary in short mode")
	}
	if !communityBenchComparePrintEnabled() {
		t.Skipf(`set %s=1 to print standard vs Legacy ns/op and speedup (legacy/new)`, gobgpCommunityBenchCompareEnv)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "\n[extended community]"); err != nil {
		t.Fatal(err)
	}
	if err := writeCommunityBenchCompareChartHeader(tw); err != nil {
		t.Fatal(err)
	}

	for _, sc := range extCommunityChartCases() {
		es, err := NewExtCommunitySet(oc.ExtCommunitySet{ExtCommunitySetName: "bench", ExtCommunityList: sc.Patterns})
		if err != nil {
			t.Fatal(err)
		}
		cond := &ExtCommunityCondition{set: es, option: MATCH_OPTION_ANY}
		if got := cond.Evaluate(sc.Path, nil); got != sc.WantHit {
			t.Fatalf("%s: want match=%v got %v", sc.Name, sc.WantHit, got)
		}

		entries, err := parseExtCommunityLegacyEntries(sc.Patterns)
		if err != nil {
			t.Fatal(err)
		}

		rNew := testing.Benchmark(func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
				cond.Evaluate(sc.Path, nil)
			}
		})
		rLeg := testing.Benchmark(func(b *testing.B) {
			b.ResetTimer()
			for range b.N {
				extCommunityMatchLegacyLoop(sc.Path, entries)
			}
		})
		newNs := float64(rNew.NsPerOp())
		legNs := float64(rLeg.NsPerOp())
		ratio := legNs / newNs
		if _, err := fmt.Fprintf(tw, "%s\t%.0f\t%.0f\t%.2fx\t%s\n", sc.Bench, newNs, legNs, ratio, sc.Name); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Flush()
}
