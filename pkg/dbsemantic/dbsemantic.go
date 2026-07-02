// Package dbsemantic is the coarse database/cache semantic adapter (SP-3 core).
// Given the first application-layer bytes of a connection to a backing store,
// it extracts a COARSE (engine, verb, object) triple — e.g. mysql/SELECT/wp_posts,
// redis/GET/session:, postgres/UPDATE/users — WITHOUT a full SQL proxy or a
// full protocol implementation. This lifts a cross-app edge's fidelity from
// "php-fpm → mysql (coarse)" toward "php-fpm → mysql SELECT wp_posts".
//
// Honest kernel-limit boundary: this is COARSE by construction. It reads the
// leading bytes of one packet, recognises the verb, and best-effort extracts a
// single object name (table / key prefix). It does not parse full SQL, does not
// see prepared-statement parameters, and does not claim table-level truth for
// multi-statement or binary-protocol traffic.
package dbsemantic

import (
	"strings"
)

// Result is the coarse semantic classification of a DB/cache request.
type Result struct {
	Engine string // "mysql" | "postgres" | "redis"
	Verb   string // SELECT/INSERT/UPDATE/DELETE/... | GET/SET/DEL/... (upper-case)
	Object string // table (SQL) or key prefix (redis); "" if not extractable
}

// EngineForPort maps a well-known backing-store port to its engine, so the
// caller can pick the right parser. "" when the port is not a known store.
func EngineForPort(port string) string {
	switch port {
	case "3306":
		return "mysql"
	case "5432":
		return "postgres"
	case "6379":
		return "redis"
	}
	return ""
}

// Parse classifies the leading request bytes for the given engine. Returns
// (Result, true) when a verb was recognised; (_, false) otherwise (handshake,
// binary/prepared traffic, or an unrecognised opcode).
func Parse(engine string, b []byte) (Result, bool) {
	switch engine {
	case "mysql":
		return parseMySQL(b)
	case "postgres":
		return parsePostgres(b)
	case "redis":
		return parseRedis(b)
	}
	return Result{}, false
}

// parseMySQL reads a MySQL client packet: [len:3][seq:1][cmd:1][payload...].
// cmd 0x03 = COM_QUERY, followed by the SQL text.
func parseMySQL(b []byte) (Result, bool) {
	if len(b) < 6 || b[4] != 0x03 { // 0x03 = COM_QUERY
		return Result{}, false
	}
	sql := string(b[5:])
	verb, obj := sqlVerbAndObject(sql)
	if verb == "" {
		return Result{}, false
	}
	return Result{Engine: "mysql", Verb: verb, Object: obj}, true
}

// parsePostgres reads a Postgres simple-query message: 'Q' [len:4] [sql...\0].
func parsePostgres(b []byte) (Result, bool) {
	if len(b) < 6 || b[0] != 'Q' { // 'Q' = simple Query
		return Result{}, false
	}
	sql := string(b[5:])
	if i := strings.IndexByte(sql, 0); i >= 0 {
		sql = sql[:i]
	}
	verb, obj := sqlVerbAndObject(sql)
	if verb == "" {
		return Result{}, false
	}
	return Result{Engine: "postgres", Verb: verb, Object: obj}, true
}

// parseRedis reads a RESP array command: *N\r\n$len\r\nCMD\r\n$len\r\nkey\r\n...
// Inline commands ("GET foo\r\n") are also handled.
func parseRedis(b []byte) (Result, bool) {
	s := string(b)
	var tokens []string
	if len(s) > 0 && s[0] == '*' {
		// RESP array: collect the bulk-string values (lines not starting with * or $).
		for _, line := range strings.Split(s, "\r\n") {
			if line == "" || line[0] == '*' || line[0] == '$' {
				continue
			}
			tokens = append(tokens, line)
			if len(tokens) >= 2 {
				break
			}
		}
	} else {
		// Inline command.
		tokens = strings.Fields(s)
	}
	if len(tokens) == 0 {
		return Result{}, false
	}
	cmd := strings.ToUpper(tokens[0])
	if !isRedisCommand(cmd) {
		return Result{}, false
	}
	obj := ""
	if len(tokens) > 1 {
		obj = keyPrefix(tokens[1])
	}
	return Result{Engine: "redis", Verb: cmd, Object: obj}, true
}

var sqlVerbs = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true,
	"REPLACE": true, "CREATE": true, "DROP": true, "ALTER": true,
	"TRUNCATE": true, "GRANT": true, "SET": true, "SHOW": true, "CALL": true,
}

// sqlVerbAndObject extracts the leading verb and a best-effort object (table)
// name from a SQL string. Coarse: it finds the token after FROM/INTO/UPDATE/
// TABLE, stripping backticks/quotes and schema qualifiers.
func sqlVerbAndObject(sql string) (verb, object string) {
	fields := strings.Fields(sql)
	if len(fields) == 0 {
		return "", ""
	}
	verb = strings.ToUpper(strings.TrimLeft(fields[0], "(/*"))
	if !sqlVerbs[verb] {
		return "", ""
	}
	for i := 0; i < len(fields)-1; i++ {
		switch strings.ToUpper(fields[i]) {
		case "FROM", "INTO", "UPDATE", "TABLE":
			object = normalizeTable(fields[i+1])
			return verb, object
		}
	}
	return verb, ""
}

func normalizeTable(t string) string {
	if i := strings.LastIndexByte(t, '.'); i >= 0 { // strip schema qualifier first
		t = t[i+1:]
	}
	return strings.Trim(t, "`\"'();")
}

// keyPrefix returns a coarse redis key prefix (up to the first ':' separator),
// so per-key cardinality does not explode the topology (session:abc → session:).
func keyPrefix(key string) string {
	if i := strings.IndexByte(key, ':'); i >= 0 {
		return key[:i+1]
	}
	return key
}

func isRedisCommand(c string) bool {
	switch c {
	case "GET", "SET", "SETEX", "SETNX", "DEL", "EXISTS", "EXPIRE", "TTL",
		"INCR", "DECR", "HGET", "HSET", "HGETALL", "HDEL", "LPUSH", "RPUSH",
		"LPOP", "RPOP", "LRANGE", "SADD", "SREM", "SMEMBERS", "ZADD", "ZRANGE",
		"MGET", "MSET", "KEYS", "SCAN", "AUTH", "SELECT", "PING", "SUBSCRIBE",
		"PUBLISH", "EVAL", "FLUSHDB", "FLUSHALL":
		return true
	}
	return false
}
