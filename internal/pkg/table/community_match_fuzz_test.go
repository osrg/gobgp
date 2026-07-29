package table

import (
	"fmt"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// slowCommunityEvaluate drives the compiled communityMatchers directly,
// bypassing the fast-path index. Used as the reference in FuzzCommunityCondition
// to verify that the bitmap/map index always agrees with the matcher loop.
func slowCommunityEvaluate(s *CommunitySet, communities []uint32, option MatchOption) bool {
	result := false
	for _, m := range s.matchers {
		result = false
		for _, y := range communities {
			if m.matchesCommunity(y, s.list) {
				result = true
				break
			}
		}
		if option == MATCH_OPTION_ALL && !result {
			break
		}
		if (option == MATCH_OPTION_ANY || option == MATCH_OPTION_INVERT) && result {
			break
		}
	}
	if option == MATCH_OPTION_INVERT {
		result = !result
	}
	return result
}

func FuzzCommunityCondition(f *testing.F) {
	f.Add("65000:100", uint32(65000<<16|100), uint8(MATCH_OPTION_ANY))
	f.Add("^65000:.*$", uint32(65000<<16|200), uint8(MATCH_OPTION_ANY))
	f.Add("^[0-9]*:100$", uint32(65001<<16|100), uint8(MATCH_OPTION_ANY))
	f.Add(`^\d+:300$`, uint32(65001<<16|300), uint8(MATCH_OPTION_ANY))
	f.Add("65000:100", uint32(65001<<16|100), uint8(MATCH_OPTION_ANY))
	f.Add("65000:100", uint32(65000<<16|100), uint8(MATCH_OPTION_INVERT))
	f.Add("65000:100", uint32(65000<<16|100), uint8(MATCH_OPTION_ALL))

	f.Fuzz(func(t *testing.T, pattern string, comm uint32, opt uint8) {
		option := [...]MatchOption{MATCH_OPTION_ANY, MATCH_OPTION_ALL, MATCH_OPTION_INVERT}[opt%3]

		cs, err := NewCommunitySet(oc.CommunitySet{
			CommunitySetName: "fuzz",
			CommunityList:    []string{pattern},
		})
		if err != nil {
			return
		}

		cond := &CommunityCondition{set: cs, option: option}
		path := createPathWithCommunities([]uint32{comm})

		fastResult := cond.Evaluate(path, nil)
		slowResult := slowCommunityEvaluate(cs, []uint32{comm}, option)

		if fastResult != slowResult {
			t.Errorf("fast/slow mismatch: pattern=%q comm=%d option=%v fast=%v slow=%v",
				pattern, comm, option, fastResult, slowResult)
		}
	})
}

// slowExtCommunityEvaluate drives the compiled extCommunityMatchers directly,
// bypassing the fast-path index. Used as the reference in FuzzExtCommunityCondition
// to verify that the bitmap/map index always agrees with the matcher loop.
func slowExtCommunityEvaluate(es *ExtCommunitySet, ecs []bgp.ExtendedCommunityInterface, option MatchOption) bool {
	result := false
	for _, x := range ecs {
		result = false
		if !isTransitiveType(x) {
			continue
		}
		var xStr string
		for _, m := range es.matchers {
			if m.matchesExtCommunity(x, &xStr) {
				result = true
				break
			}
		}
		if option == MATCH_OPTION_ALL && !result {
			break
		}
		if option == MATCH_OPTION_ANY && result {
			break
		}
	}
	if option == MATCH_OPTION_INVERT {
		result = !result
	}
	return result
}

func FuzzExtCommunityCondition(f *testing.F) {
	f.Add("rt:65000:100", uint16(65000), uint32(100), uint8(0))
	f.Add("rt:^65000:.*$", uint16(65000), uint32(200), uint8(0))
	f.Add("rt:^65000:.*$", uint16(65001), uint32(200), uint8(0))
	f.Add(`rt:^\d+:100$`, uint16(65001), uint32(100), uint8(0))
	f.Add(`rt:^\d+:(100|200)$`, uint16(65001), uint32(200), uint8(0))
	f.Add("rt:^65000:(100|200)$", uint16(65000), uint32(100), uint8(0))
	f.Add("rt:65000:100", uint16(65001), uint32(100), uint8(0))
	f.Add("rt:65000:100", uint16(65000), uint32(100), uint8(2))    // INVERT
	f.Add("rt:65000:100", uint16(65000), uint32(100), uint8(1))    // ALL
	f.Add("rt:^65000:.*$", uint16(65000), uint32(65536), uint8(0)) // LA > 65535

	f.Fuzz(func(t *testing.T, pattern string, as uint16, la uint32, opt uint8) {
		option := [...]MatchOption{MATCH_OPTION_ANY, MATCH_OPTION_ALL, MATCH_OPTION_INVERT}[opt%3]

		es, err := NewExtCommunitySet(oc.ExtCommunitySet{
			ExtCommunitySetName: "fuzz",
			ExtCommunityList:    []string{pattern},
		})
		if err != nil {
			return
		}

		ec := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, as, la, true)
		p := createPathWithExtCommunities([]bgp.ExtendedCommunityInterface{ec})

		fastResult := (&ExtCommunityCondition{set: es, option: option}).Evaluate(p, nil)
		slowResult := slowExtCommunityEvaluate(es, []bgp.ExtendedCommunityInterface{ec}, option)

		if fastResult != slowResult {
			t.Errorf("fast/slow mismatch: pattern=%q as=%d la=%d option=%v fast=%v slow=%v",
				pattern, as, la, option, fastResult, slowResult)
		}
	})
}

// The fuzz targets above check the index against the matcher loop, so a
// matcher that was compiled wrong agrees with itself and slips through. These
// pin the property the compiler actually promises: a compiled matcher decides
// exactly what its regexp decides.
func TestCommunityMatcherAgreesWithRegexp(t *testing.T) {
	for _, tt := range []struct {
		pattern string
		comm    uint32
	}{
		{`^65100:666$|^65200:666$`, 65200<<16 | 666},
		{`^65200:666$|^65100:\d+$`, 65100<<16 | 12345},
		{`^65200:666$|^65100:\d+$`, 65200<<16 | 9999},
		{`^65100:(666|777)$`, 65100<<16 | 777},
		{`^65100:.*$`, 65100<<16 | 5},
		{`^\d+:100$`, 65001<<16 | 100},
	} {
		cs, err := NewCommunitySet(oc.CommunitySet{
			CommunitySetName: "t",
			CommunityList:    []string{tt.pattern},
		})
		if err != nil {
			t.Fatalf("NewCommunitySet(%q): %v", tt.pattern, err)
		}
		want := cs.list[0].MatchString(fmt.Sprintf("%d:%d", tt.comm>>16, tt.comm&0xffff))
		if got := cs.matchers[0].matchesCommunity(tt.comm, cs.list); got != want {
			t.Errorf("pattern=%q comm=%d:%d matcher=%v regexp=%v",
				tt.pattern, tt.comm>>16, tt.comm&0xffff, got, want)
		}
	}
}

func TestExtCommunityMatcherAgreesWithRegexp(t *testing.T) {
	for _, tt := range []struct {
		pattern string
		as      uint16
		la      uint32
	}{
		{`rt:^65200:666$|^65100:\d+$`, 65100, 12345},
		{`rt:^65200:666$|^65100:\d+$`, 65200, 9999},
		{`rt:^\d+:(100|200)$`, 65001, 200},
		{`rt:^65000:.*$`, 65000, 200},
	} {
		es, err := NewExtCommunitySet(oc.ExtCommunitySet{
			ExtCommunitySetName: "t",
			ExtCommunityList:    []string{tt.pattern},
		})
		if err != nil {
			t.Fatalf("NewExtCommunitySet(%q): %v", tt.pattern, err)
		}
		ec := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, tt.as, tt.la, true)
		want := es.list[0].MatchString(ec.String())
		var s string
		if got := es.matchers[0].matchesExtCommunity(ec, &s); got != want {
			t.Errorf("pattern=%q ec=%s matcher=%v regexp=%v", tt.pattern, ec.String(), got, want)
		}
	}
}
