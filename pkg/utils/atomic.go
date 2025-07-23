package utils

import "sync/atomic"

// Atomic is a generic type that provides atomic operations on a value of type T.
type Atomic[T any] struct {
	atomic.Value
}

func NewAtomic[T any](v T) *Atomic[T] {
	a := atomic.Value{}
	a.Store(v)
	return &Atomic[T]{Value: a}
}

func (a *Atomic[T]) Load() T {
	return a.Value.Load().(T)
}

func (a *Atomic[T]) Store(v T) {
	a.Value.Store(v)
}

func (a *Atomic[T]) Swap(new T) T {
	return a.Value.Swap(new).(T)
}

func (a *Atomic[T]) CompareAndSwap(old, new T) bool {
	return a.Value.CompareAndSwap(old, new)
}
