package utils

import (
	"math/rand/v2"
	"time"
)

type jitterOptions struct {
	minFactor float64
	maxFactor float64
}

type jitterOption func(*jitterOptions)

func WithMinFactor(mf float64) jitterOption {
	return func(opts *jitterOptions) {
		opts.minFactor = mf
	}
}

func WithMaxFactor(mf float64) jitterOption {
	return func(opts *jitterOptions) {
		opts.maxFactor = mf
	}
}

var defaultJitterOptions = jitterOptions{
	minFactor: 1.0,
	maxFactor: 1.0,
}

func Jitterize(d time.Duration, optionsFn ...jitterOption) time.Duration {
	opts := defaultJitterOptions
	for _, fn := range optionsFn {
		fn(&opts)
	}
	jitterFactor := opts.minFactor + (opts.maxFactor-opts.minFactor)*rand.Float64()
	return d * time.Duration(1.0+jitterFactor)
}
