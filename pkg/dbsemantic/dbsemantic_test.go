package dbsemantic

import "testing"

func mysqlQuery(sql string) []byte {
	// [len:3][seq:1][0x03 COM_QUERY][sql]
	b := []byte{0, 0, 0, 0, 0x03}
	return append(b, []byte(sql)...)
}

func TestParseMySQL(t *testing.T) {
	r, ok := Parse("mysql", mysqlQuery("SELECT * FROM wp_posts WHERE id=1"))
	if !ok || r.Verb != "SELECT" || r.Object != "wp_posts" {
		t.Errorf("mysql SELECT = %+v ok=%v", r, ok)
	}
	r, ok = Parse("mysql", mysqlQuery("UPDATE `wp`.`wp_users` SET x=1"))
	if !ok || r.Verb != "UPDATE" || r.Object != "wp_users" {
		t.Errorf("mysql UPDATE = %+v ok=%v", r, ok)
	}
	// A handshake / non-COM_QUERY packet is not classified.
	if _, ok := Parse("mysql", []byte{10, 0, 0, 0, 0x01, 'x'}); ok {
		t.Error("non-query mysql packet should not classify")
	}
}

func TestParsePostgres(t *testing.T) {
	b := append([]byte{'Q', 0, 0, 0, 0}, []byte("DELETE FROM users\x00")...)
	r, ok := Parse("postgres", b)
	if !ok || r.Verb != "DELETE" || r.Object != "users" {
		t.Errorf("pg DELETE = %+v ok=%v", r, ok)
	}
}

func TestParseRedis(t *testing.T) {
	r, ok := Parse("redis", []byte("*2\r\n$3\r\nGET\r\n$11\r\nsession:abc\r\n"))
	if !ok || r.Verb != "GET" || r.Object != "session:" {
		t.Errorf("redis GET = %+v ok=%v", r, ok)
	}
	r, ok = Parse("redis", []byte("SET foo bar\r\n"))
	if !ok || r.Verb != "SET" || r.Object != "foo" {
		t.Errorf("redis inline SET = %+v ok=%v", r, ok)
	}
}

func TestEngineForPort(t *testing.T) {
	for p, want := range map[string]string{"3306": "mysql", "5432": "postgres", "6379": "redis", "80": ""} {
		if got := EngineForPort(p); got != want {
			t.Errorf("EngineForPort(%s)=%q want %q", p, got, want)
		}
	}
}
