package table

import (
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
