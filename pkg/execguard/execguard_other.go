//go:build !linux

package execguard

import (
	"context"
	"errors"
)

type Decision int

const (
	Allow Decision = iota
	Deny
)

type Rule struct {
	PathEquals    string
	PathHasPrefix string
	PathHasSuffix string
	PathContains  string
	Decision      Decision
	Reason        string
}

type EventCallback func(path string, pid int, decision Decision, reason string)

type Guard struct{}

type Stats struct{ Seen, Denied, Errors uint64 }

func New(_ EventCallback) *Guard               { return &Guard{} }
func (g *Guard) SetRules(_ []Rule)             {}
func (g *Guard) Start(_ context.Context, _ []string) error {
	return errors.New("execguard: only supported on Linux")
}
func (g *Guard) Stop() error  { return nil }
func (g *Guard) Stats() Stats { return Stats{} }
func DefaultRules() []Rule    { return nil }
