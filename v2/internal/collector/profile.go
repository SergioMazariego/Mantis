package collector

import "sort"

// DefaultMaxTotal is the per-profile default byte budget for a whole plan.
func DefaultMaxTotal(p Profile) int64 {
	switch p {
	case ProfileQuick:
		return 2 << 30
	case ProfileStandard:
		return 16 << 30
	case ProfileFull:
		return 64 << 30
	}
	return 8 << 30
}

// SelectProfile returns the sources a built-in profile includes. Sources marked
// Sensitive are only included when confirmSensitive is true, and never for
// Quick/Standard (their masks must not contain them). Custom returns nothing:
// the operator chooses sources one by one.
func SelectProfile(all []Source, p Profile, confirmSensitive bool) []Source {
	var out []Source
	for _, s := range all {
		if !s.Meta.Profiles.Has(p) {
			continue
		}
		if s.Meta.Sensitive && !confirmSensitive {
			continue
		}
		out = append(out, s)
	}
	return out
}

// ByCategory groups source IDs by package category (sorted), for listings.
func ByCategory(all []Source) map[string][]string {
	m := map[string][]string{}
	for _, s := range all {
		c := s.Meta.Category
		if c == "" {
			c = "other"
		}
		m[c] = append(m[c], s.ID)
	}
	for _, ids := range m {
		sort.Strings(ids)
	}
	return m
}

// NeedsConfirmation reports whether any selected source requires explicit
// operator confirmation (sensitive or system-altering acquisitions).
func NeedsConfirmation(selected []Source) []Source {
	var out []Source
	for _, s := range selected {
		if s.Meta.Sensitive {
			out = append(out, s)
		}
	}
	return out
}
