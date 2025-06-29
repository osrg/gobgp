package utils

import (
	"slices"
)

func Classify[T comparable](all, part []T) ([]T, []T) {
	a := []T{}
	b := []T{}
	for _, f := range all {
		if slices.Contains(part, f) {
			a = append(a, f)
		} else {
			b = append(b, f)
		}
	}
	return a, b
}
