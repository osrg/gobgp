package table

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
)

// legacyEvaluate is the reference implementation of community matching using standard regexp.
func legacyEvaluate(cs []uint32, regs []*regexp.Regexp, option MatchOption) bool {
	if len(regs) == 0 {
		return false
	}
	result := false
	for _, x := range regs {
		result = false
		for _, y := range cs {
			if x.MatchString(fmt.Sprintf("%d:%d", y>>16, y&0xffff)) {
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
	// Add some seed corpus
	f.Add("65000:100", uint32(65000<<16|100), uint8(MATCH_OPTION_ANY))
	f.Add("^65000:.*$", uint32(65000<<16|200), uint8(MATCH_OPTION_ANY))
	f.Add("^[0-9]*:100$", uint32(65001<<16|100), uint8(MATCH_OPTION_ANY))
	f.Add(`^\d+:300$`, uint32(65001<<16|300), uint8(MATCH_OPTION_ANY))
	f.Add("65000:100", uint32(65001<<16|100), uint8(MATCH_OPTION_ANY))
	f.Add("65000:100", uint32(65000<<16|100), uint8(MATCH_OPTION_INVERT))
	f.Add("65000:100", uint32(65000<<16|100), uint8(MATCH_OPTION_ALL))

	f.Fuzz(func(t *testing.T, pattern string, comm uint32, opt uint8) {
		option := MatchOption(opt % 3) // 0: ANY, 1: ALL, 2: INVERT

		// Map 0, 1, 2 to the actual constants if they differ
		switch option {
		case 0:
			option = MATCH_OPTION_ANY
		case 1:
			option = MATCH_OPTION_ALL
		case 2:
			option = MATCH_OPTION_INVERT
		}

		// Try to compile the pattern as a regexp. If it fails, we skip this input.
		// We use ParseCommunityRegexp to handle the ^ and $ additions if needed,
		// but to be safe we just use ParseCommunityRegexp logic or just regexp.Compile.
		// Actually, NewCommunitySet does some parsing. Let's see if it errors.
		cs, err := NewCommunitySet(oc.CommunitySet{
			CommunitySetName: "fuzz",
			CommunityList:    []string{pattern},
		})
		if err != nil {
			// Invalid pattern, skip
			return
		}

		// For legacy, we need to mimic how ParseCommunityRegexp transforms the pattern.
		// ParseCommunityRegexp in gobgp usually adds ^ and $ if not present, but let's just use the compiled regexp from cs if possible, or compile it ourselves.
		// Wait, NewCommunitySet parses it. Let's just use the exact same regexp string that gobgp uses.
		// Actually, if we just compile the pattern directly, it might not match exactly what gobgp does (e.g., exact match vs partial).
		// Let's look at ParseCommunityRegexp.
		exp, err := ParseCommunityRegexp(pattern)
		if err != nil {
			return
		}
		reg := exp

		cond := &CommunityCondition{set: cs, option: option}
		path := createPathWithCommunities([]uint32{comm})

		newResult := cond.Evaluate(path, nil)
		legacyResult := legacyEvaluate([]uint32{comm}, []*regexp.Regexp{reg}, option)

		if newResult != legacyResult {
			t.Errorf("Mismatch for pattern %q, comm %d, option %v: new=%v, legacy=%v", pattern, comm, option, newResult, legacyResult)
		}
	})
}
