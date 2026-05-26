package brpparser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// iniSection is one [section] of an ini-style config (mysql my.cnf,
// php-fpm pool, systemd unit).
type iniSection struct {
	Name  string
	Pairs []iniPair
}

// iniPair is one key=value line within a section. Keys are preserved in
// the original case (mysql is case-insensitive but php-fpm is not).
type iniPair struct {
	Key   string
	Value string
}

// parseINI reads an ini-style file and returns its sections in order.
// Supports:
//   - [section_name] headers
//   - key = value and key=value lines
//   - # and ; comments (full-line and trailing)
//   - !include FILE and !includedir DIR directives (mysql-style)
//   - Unrecognised lines are skipped silently — caller doesn't need
//     to validate every directive, just extract what it cares about.
//
// Quoted values keep their content but the surrounding quotes are
// stripped. Escape handling is intentionally minimal — operators
// rarely escape anything in mysql/php-fpm configs.
func parseINI(path string, depth int) ([]iniSection, []string, error) {
	if depth >= maxIncludeDepth {
		return nil, nil, fmt.Errorf("ini include depth exceeded at %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var sections []iniSection
	var warnings []string
	current := iniSection{Name: ""} // default empty-section bucket
	baseDir := filepath.Dir(path)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := stripINIComment(scanner.Text())
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Section header.
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sections = append(sections, current)
			current = iniSection{Name: strings.TrimSpace(line[1 : len(line)-1])}
			continue
		}
		// !include / !includedir.
		if strings.HasPrefix(line, "!") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			target := fields[1]
			if !filepath.IsAbs(target) {
				target = filepath.Join(baseDir, target)
			}
			switch fields[0] {
			case "!include":
				inc, w, ierr := parseINI(target, depth+1)
				warnings = append(warnings, w...)
				if ierr != nil {
					warnings = append(warnings, fmt.Sprintf("!include %s: %v", target, ierr))
					continue
				}
				sections = append(sections, inc...)
			case "!includedir":
				entries, derr := os.ReadDir(target)
				if derr != nil {
					warnings = append(warnings, fmt.Sprintf("!includedir %s: %v", target, derr))
					continue
				}
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					name := e.Name()
					if !strings.HasSuffix(name, ".cnf") && !strings.HasSuffix(name, ".conf") {
						continue
					}
					inc, w, ierr := parseINI(filepath.Join(target, name), depth+1)
					warnings = append(warnings, w...)
					if ierr != nil {
						warnings = append(warnings, fmt.Sprintf("!includedir entry %s: %v", name, ierr))
						continue
					}
					sections = append(sections, inc...)
				}
			}
			continue
		}
		// key = value or key value.
		key, value := splitINIKV(line)
		if key == "" {
			continue
		}
		current.Pairs = append(current.Pairs, iniPair{Key: key, Value: value})
	}
	sections = append(sections, current)
	if err := scanner.Err(); err != nil {
		return sections, warnings, err
	}
	return sections, warnings, nil
}

func stripINIComment(line string) string {
	// Full-line comments handled first.
	t := strings.TrimSpace(line)
	if strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
		return ""
	}
	// Trailing comment after a `#`. Only strip if the # is preceded by
	// whitespace — preserves things like Apache hash characters inside
	// values, though MySQL doesn't usually have those.
	inQ := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' || c == '\'' {
			inQ = !inQ
		}
		if c == '#' && !inQ && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
}

func splitINIKV(line string) (string, string) {
	// First try "=" split.
	if idx := strings.IndexByte(line, '='); idx >= 0 {
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		v = trimINIQuotes(v)
		return k, v
	}
	// Otherwise whitespace split (mysql allows "key value" form).
	fields := strings.Fields(line)
	switch len(fields) {
	case 0:
		return "", ""
	case 1:
		return fields[0], ""
	}
	return fields[0], strings.Join(fields[1:], " ")
}

func trimINIQuotes(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') ||
			(v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
