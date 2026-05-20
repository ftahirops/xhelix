// Package forensicapi registers LocalAPI handlers for the
// forensic IOC store.
package forensicapi

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/xhelix/xhelix/pkg/forensic"
	"github.com/xhelix/xhelix/pkg/localapi"
)

// API holds the IOC store.
type API struct {
	Store *forensic.Store
}

// Register binds the handlers:
//
//   forensic.iocs      → []*forensic.IOC   (param: QueryParam)
//   forensic.ioc       → *forensic.IOC     (param: KindValueParam)
//   forensic.ioc_tag   → ok                (param: TagParam)
//   forensic.ioc_count → CountResult
func (a *API) Register(s *localapi.Server) {
	s.RegisterHandler("forensic.iocs", a.handleQuery)
	s.RegisterHandler("forensic.ioc", a.handleGet)
	s.RegisterHandler("forensic.ioc_tag", a.handleTag)
	s.RegisterHandler("forensic.ioc_count", a.handleCount)
}

// QueryParam wraps forensic.Query so it can travel over JSON.
// We use string-typed Kind so callers don't need the typed package.
type QueryParam struct {
	Kinds      []string `json:"kinds,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Origin     string   `json:"origin,omitempty"`
	Since      string   `json:"since,omitempty"` // RFC3339 or empty
	Limit      int      `json:"limit,omitempty"`
}

func (q QueryParam) toQuery() (forensic.Query, error) {
	out := forensic.Query{
		Confidence: forensic.Confidence(q.Confidence),
		Origin:     q.Origin,
		Limit:      q.Limit,
	}
	for _, k := range q.Kinds {
		out.Kinds = append(out.Kinds, forensic.Kind(k))
	}
	if q.Since != "" {
		t, err := time.Parse(time.RFC3339, q.Since)
		if err != nil {
			return forensic.Query{}, err
		}
		out.Since = t
	}
	return out, nil
}

func (a *API) handleQuery(ctx context.Context, raw json.RawMessage) (any, error) {
	if a.Store == nil {
		return nil, errors.New("forensicapi: nil store")
	}
	var p QueryParam
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
	}
	q, err := p.toQuery()
	if err != nil {
		return nil, err
	}
	if q.Limit <= 0 {
		q.Limit = 200 // sensible default cap
	}
	return a.Store.Query(q), nil
}

// KindValueParam — single-IOC lookup.
type KindValueParam struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func (a *API) handleGet(ctx context.Context, raw json.RawMessage) (any, error) {
	if a.Store == nil {
		return nil, errors.New("forensicapi: nil store")
	}
	var p KindValueParam
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.Kind == "" || p.Value == "" {
		return nil, errors.New("kind+value required")
	}
	ioc := a.Store.Get(forensic.Kind(p.Kind), p.Value)
	if ioc == nil {
		return nil, errors.New("ioc not found")
	}
	return ioc, nil
}

// TagParam — apply a tag to an IOC.
type TagParam struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	Tag   string `json:"tag"`
}

func (a *API) handleTag(ctx context.Context, raw json.RawMessage) (any, error) {
	if a.Store == nil {
		return nil, errors.New("forensicapi: nil store")
	}
	var p TagParam
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.Kind == "" || p.Value == "" || p.Tag == "" {
		return nil, errors.New("kind+value+tag required")
	}
	a.Store.Tag(forensic.Kind(p.Kind), p.Value, p.Tag)
	return map[string]bool{"ok": true}, nil
}

// CountResult is the shape returned by forensic.ioc_count.
type CountResult struct {
	Total int `json:"total"`
}

func (a *API) handleCount(ctx context.Context, _ json.RawMessage) (any, error) {
	if a.Store == nil {
		return nil, errors.New("forensicapi: nil store")
	}
	return CountResult{Total: a.Store.Len()}, nil
}
