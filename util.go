package pg

import "sort"

// sortedKeysExcept returns the keys of m other than skip, in ascending order,
// giving StartupMessage (and any other key/value list) a deterministic byte
// order independent of Go map iteration.
func sortedKeysExcept(m map[string]string, skip string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k == skip {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
