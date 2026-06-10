// Package appregistry stores declared app stacks and provides the cgroup →
// app mapping that lets the pipeline attribute events per-app.
//
// An App groups one or more Services. Each Service declares the cgroup
// prefix where it runs. The registry is SQLite-backed with an in-memory
// cgroup→app index for sub-microsecond hot-path lookups.
package appregistry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// EnforcementMode is the behavioral compiler enforcement level for an app.
type EnforcementMode string

const (
	ModeObserve EnforcementMode = "observe"  // record only; zero blocks
	ModeShadow  EnforcementMode = "shadow"   // log would-blocks; no enforcement
	ModeGuarded EnforcementMode = "guarded"  // red zones blocked; drift alerted
	ModeLocked  EnforcementMode = "locked"   // all undeclared behavior blocked
	ModeSealed  EnforcementMode = "sealed"   // all unsigned drift blocked
)

// ServiceType classifies the detected service so the compiler can apply
// the correct built-in contract skeleton.
type ServiceType string

const (
	ServiceNginx    ServiceType = "nginx"
	ServiceApache   ServiceType = "apache"
	ServicePhpFpm   ServiceType = "php-fpm"
	ServiceMySQL    ServiceType = "mysql"
	ServicePostgres ServiceType = "postgres"
	ServiceRedis    ServiceType = "redis"
	ServiceNode     ServiceType = "node"
	ServicePython   ServiceType = "python"
	ServiceCustom   ServiceType = "custom"
)

// DiscoveredService represents a running process group that could become
// an app service. It is returned by Discover() for display in the "new
// app" wizard. Defined here (platform-neutral) so the non-Linux Discover
// stub can reference it without a Linux build tag.
type DiscoveredService struct {
	CgroupPath  string      `json:"cgroup_path"`
	UnitName    string      `json:"unit_name"`
	BinaryPath  string      `json:"binary_path"`
	ServiceType ServiceType `json:"service_type"`
	PIDs        []int32     `json:"pids"`
	SampleComm  string      `json:"sample_comm"`
}

// Service is one process group within an app stack.
type Service struct {
	Name        string      `json:"name"`
	CgroupMatch string      `json:"cgroup_match"`
	BinaryPath  string      `json:"binary_path,omitempty"`
	ServiceType ServiceType `json:"service_type"`
	UnitName    string      `json:"unit_name,omitempty"`
}

// App is the top-level declaration unit.
type App struct {
	Name        string          `json:"name"`
	DisplayName string          `json:"display_name"`
	Description string          `json:"description,omitempty"`
	Mode        EnforcementMode `json:"mode"`
	Services    []Service       `json:"services"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// Registry is the main handle. Safe for concurrent use.
type Registry struct {
	db  *sql.DB
	mu  sync.RWMutex
	// cgroupIndex maps cgroup prefix → app name for hot-path lookups.
	cgroupIndex map[string]string
}

// Open opens (or creates) the app registry database at path.
func Open(path string) (*Registry, error) {
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("appregistry: open: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("appregistry: schema: %w", err)
	}
	r := &Registry{db: db, cgroupIndex: make(map[string]string)}
	if err := r.rebuildIndex(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return r, nil
}

// Close releases the database handle.
func (r *Registry) Close() error { return r.db.Close() }

// Create declares a new app. Returns an error if the name already exists.
func (r *Registry) Create(a App) error {
	if a.Name == "" {
		return errors.New("appregistry: name required")
	}
	if a.Mode == "" {
		a.Mode = ModeObserve
	}
	now := time.Now().Unix()
	tx, err := r.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	_, err = tx.Exec(
		`INSERT INTO apps (name, display_name, description, mode, created_at, updated_at)
		 VALUES (?,?,?,?,?,?)`,
		a.Name, a.DisplayName, a.Description, string(a.Mode), now, now,
	)
	if err != nil {
		return fmt.Errorf("appregistry: create: %w", err)
	}
	for _, svc := range a.Services {
		if svc.Name == "" {
			svc.Name = svc.UnitName
		}
		if svc.ServiceType == "" {
			svc.ServiceType = ServiceCustom
		}
		_, err = tx.Exec(
			`INSERT INTO app_services
			   (app_name, service_name, cgroup_match, binary_path, service_type, unit_name)
			 VALUES (?,?,?,?,?,?)`,
			a.Name, svc.Name, svc.CgroupMatch, svc.BinaryPath,
			string(svc.ServiceType), svc.UnitName,
		)
		if err != nil {
			return fmt.Errorf("appregistry: create service %q: %w", svc.Name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	r.mu.Lock()
	for _, svc := range a.Services {
		r.cgroupIndex[svc.CgroupMatch] = a.Name
	}
	r.mu.Unlock()
	return nil
}

// Get returns one app by name, or nil if not found.
func (r *Registry) Get(name string) (*App, error) {
	row := r.db.QueryRowContext(context.Background(),
		`SELECT name, display_name, description, mode, created_at, updated_at
		 FROM apps WHERE name=?`, name)
	a, err := scanApp(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.Services, err = r.loadServices(name)
	return a, err
}

// List returns all apps ordered by creation time (newest first).
func (r *Registry) List() ([]App, error) {
	rows, err := r.db.QueryContext(context.Background(),
		`SELECT name, display_name, description, mode, created_at, updated_at
		 FROM apps ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var apps []App
	for rows.Next() {
		var a App
		var cat, uat int64
		if err := rows.Scan(&a.Name, &a.DisplayName, &a.Description,
			(*string)(&a.Mode), &cat, &uat); err != nil {
			return nil, err
		}
		a.CreatedAt = time.Unix(cat, 0)
		a.UpdatedAt = time.Unix(uat, 0)
		apps = append(apps, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range apps {
		apps[i].Services, err = r.loadServices(apps[i].Name)
		if err != nil {
			return nil, err
		}
	}
	return apps, nil
}

// SetMode changes the enforcement mode for an app.
func (r *Registry) SetMode(name string, mode EnforcementMode) error {
	res, err := r.db.ExecContext(context.Background(),
		`UPDATE apps SET mode=?, updated_at=? WHERE name=?`,
		string(mode), time.Now().Unix(), name)
	if err != nil {
		return fmt.Errorf("appregistry: set mode: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("appregistry: app %q not found", name)
	}
	return nil
}

// Delete removes an app and all its services.
func (r *Registry) Delete(name string) error {
	tx, err := r.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`DELETE FROM app_services WHERE app_name=?`, name); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM apps WHERE name=?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("appregistry: app %q not found", name)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	r.mu.Lock()
	for k, v := range r.cgroupIndex {
		if v == name {
			delete(r.cgroupIndex, k)
		}
	}
	r.mu.Unlock()
	return nil
}

// AppForCgroup returns the app name owning the given cgroup path.
// Returns "" if no app claims this cgroup. Hot path — pure in-memory.
func (r *Registry) AppForCgroup(cgroupPath string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if name, ok := r.cgroupIndex[cgroupPath]; ok {
		return name
	}
	// Longest-prefix match among registered cgroups.
	best, bestLen := "", 0
	for prefix, name := range r.cgroupIndex {
		if len(prefix) > bestLen && cgroupMatchesPrefix(cgroupPath, prefix) {
			best, bestLen = name, len(prefix)
		}
	}
	return best
}

// cgroupMatchesPrefix returns true when path equals prefix or is a direct
// child of prefix (i.e. path starts with prefix + "/"). The slash anchor
// prevents /system.slice/php-fpm matching /system.slice/php-fpm-evil.
func cgroupMatchesPrefix(path, prefix string) bool {
	if path == prefix {
		return true
	}
	if strings.HasPrefix(prefix, "/") && strings.HasPrefix(path, prefix+"/") {
		return true
	}
	return false
}

func (r *Registry) loadServices(appName string) ([]Service, error) {
	rows, err := r.db.QueryContext(context.Background(),
		`SELECT service_name, cgroup_match, binary_path, service_type, unit_name
		 FROM app_services WHERE app_name=? ORDER BY service_name`, appName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Service
	for rows.Next() {
		var s Service
		if err := rows.Scan(&s.Name, &s.CgroupMatch, &s.BinaryPath,
			(*string)(&s.ServiceType), &s.UnitName); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *Registry) rebuildIndex() error {
	rows, err := r.db.QueryContext(context.Background(),
		`SELECT app_name, cgroup_match FROM app_services`)
	if err != nil {
		return fmt.Errorf("appregistry: rebuild index: %w", err)
	}
	defer rows.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	for rows.Next() {
		var appName, cgroupMatch string
		if err := rows.Scan(&appName, &cgroupMatch); err != nil {
			return err
		}
		r.cgroupIndex[cgroupMatch] = appName
	}
	return rows.Err()
}

func scanApp(row *sql.Row) (*App, error) {
	var a App
	var cat, uat int64
	if err := row.Scan(&a.Name, &a.DisplayName, &a.Description,
		(*string)(&a.Mode), &cat, &uat); err != nil {
		return nil, err
	}
	a.CreatedAt = time.Unix(cat, 0)
	a.UpdatedAt = time.Unix(uat, 0)
	return &a, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS apps (
  name         TEXT PRIMARY KEY,
  display_name TEXT NOT NULL DEFAULT '',
  description  TEXT NOT NULL DEFAULT '',
  mode         TEXT NOT NULL DEFAULT 'observe',
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS app_services (
  app_name     TEXT NOT NULL REFERENCES apps(name),
  service_name TEXT NOT NULL,
  cgroup_match TEXT NOT NULL,
  binary_path  TEXT NOT NULL DEFAULT '',
  service_type TEXT NOT NULL DEFAULT 'custom',
  unit_name    TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (app_name, service_name)
);
CREATE INDEX IF NOT EXISTS idx_app_services_app    ON app_services(app_name);
CREATE INDEX IF NOT EXISTS idx_app_services_cgroup ON app_services(cgroup_match);
`
