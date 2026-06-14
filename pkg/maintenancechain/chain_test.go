package maintenancechain

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv
}

func TestMint_Valid(t *testing.T) {
	pub, priv := genKey(t)
	trust := map[string]ed25519.PublicKey{"ops": pub}

	g, err := Mint(MintParams{
		AppName:     "billing-api",
		CgroupMatch: "/system.slice/php-fpm.service",
		Scope:       ScopeDeploy,
		Reason:      "deploying v1.4.2",
		CreatedBy:   "admin",
		TTL:         30 * time.Minute,
		SignerName:  "ops",
		SignerKey:   priv,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if g.ID == "" {
		t.Error("expected non-empty ID")
	}
	if len(g.Signature) == 0 {
		t.Error("expected non-empty signature")
	}
	if err := g.Validate(trust); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestMint_MissingFields(t *testing.T) {
	_, priv := genKey(t)
	cases := []struct {
		name string
		p    MintParams
	}{
		{"no app", MintParams{CgroupMatch: "/x", Reason: "r", TTL: time.Minute, SignerName: "ops", SignerKey: priv}},
		{"no cgroup", MintParams{AppName: "a", Reason: "r", TTL: time.Minute, SignerName: "ops", SignerKey: priv}},
		{"no reason", MintParams{AppName: "a", CgroupMatch: "/x", TTL: time.Minute, SignerName: "ops", SignerKey: priv}},
		{"no key", MintParams{AppName: "a", CgroupMatch: "/x", Reason: "r", TTL: time.Minute, SignerName: "ops"}},
		{"ttl too short", MintParams{AppName: "a", CgroupMatch: "/x", Reason: "r", TTL: time.Second, SignerName: "ops", SignerKey: priv}},
		{"ttl too long", MintParams{AppName: "a", CgroupMatch: "/x", Reason: "r", TTL: 25 * time.Hour, SignerName: "ops", SignerKey: priv}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Mint(tc.p)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestValidate_WrongSigner(t *testing.T) {
	pub, priv := genKey(t)
	otherPub, _ := genKey(t)
	trust := map[string]ed25519.PublicKey{"ops": pub}
	wrongTrust := map[string]ed25519.PublicKey{"ops": otherPub}

	g, _ := Mint(MintParams{
		AppName: "a", CgroupMatch: "/x", Reason: "r",
		TTL: time.Minute, SignerName: "ops", SignerKey: priv,
	})
	if err := g.Validate(trust); err != nil {
		t.Fatalf("should validate with correct key: %v", err)
	}
	if err := g.Validate(wrongTrust); err == nil {
		t.Error("should reject with wrong key")
	}
}

func TestValidate_UnknownSigner(t *testing.T) {
	_, priv := genKey(t)
	trust := map[string]ed25519.PublicKey{} // empty trust root

	g, _ := Mint(MintParams{
		AppName: "a", CgroupMatch: "/x", Reason: "r",
		TTL: time.Minute, SignerName: "ops", SignerKey: priv,
	})
	if err := g.Validate(trust); err == nil {
		t.Error("should reject unknown signer")
	}
}

func TestValidate_Expired(t *testing.T) {
	pub, priv := genKey(t)
	trust := map[string]ed25519.PublicKey{"ops": pub}

	g, _ := Mint(MintParams{
		AppName: "a", CgroupMatch: "/x", Reason: "r",
		TTL: time.Minute, SignerName: "ops", SignerKey: priv,
	})
	g.ExpiresAt = time.Now().Add(-time.Second) // manually expire
	if err := g.Validate(trust); err == nil {
		t.Error("should reject expired grant")
	}
}

func TestCoversExec(t *testing.T) {
	_, priv := genKey(t)
	g, _ := Mint(MintParams{
		AppName:     "a",
		CgroupMatch: "/system.slice/php-fpm.service",
		Scope:       ScopeCustom,
		AllowExec:   []string{"/bin/bash", "/usr/bin/python*"},
		Reason:      "r",
		TTL:         time.Minute,
		SignerName:  "ops",
		SignerKey:   priv,
	})

	cases := []struct {
		cgroup string
		binary string
		want   bool
	}{
		{"/system.slice/php-fpm.service", "/bin/bash", true},
		{"/system.slice/php-fpm.service/1", "/bin/bash", true},       // child cgroup (slash-anchored)
		{"/system.slice/php-fpm.service", "/usr/bin/python3", true},  // prefix match on binary
		{"/system.slice/php-fpm.service", "/usr/bin/node", false},
		{"/system.slice/nginx.service", "/bin/bash", false},          // wrong cgroup
		{"", "/bin/bash", false},                                     // no cgroup
		// Guard against unanchored prefix bypass: "php-fpm" must not
		// match a different service that merely starts with the same chars.
		{"/system.slice/php-fpm-malicious.service", "/bin/bash", false},
	}
	for _, tc := range cases {
		got := g.CoversExec(tc.cgroup, tc.binary)
		if got != tc.want {
			t.Errorf("CoversExec(%q, %q) = %v, want %v", tc.cgroup, tc.binary, got, tc.want)
		}
	}
}

func TestCoversWrite(t *testing.T) {
	_, priv := genKey(t)
	g, _ := Mint(MintParams{
		AppName:     "a",
		CgroupMatch: "/system.slice/php-fpm.service",
		Scope:       ScopeCustom,
		AllowWrite:  []string{"/srv/app/", "/tmp/"},
		Reason:      "r",
		TTL:         time.Minute,
		SignerName:  "ops",
		SignerKey:   priv,
	})

	if !g.CoversWrite("/system.slice/php-fpm.service", "/srv/app/releases/v2") {
		t.Error("expected write allowed under /srv/app/")
	}
	if g.CoversWrite("/system.slice/php-fpm.service", "/etc/cron.d/evil") {
		t.Error("expected write denied for /etc/cron.d/")
	}
	if g.CoversWrite("/system.slice/nginx.service", "/srv/app/x") {
		t.Error("expected deny for wrong cgroup")
	}
}

func TestScopeDefaults_Deploy(t *testing.T) {
	_, priv := genKey(t)
	g, _ := Mint(MintParams{
		AppName: "a", CgroupMatch: "/x", Scope: ScopeDeploy,
		Reason: "r", TTL: time.Minute, SignerName: "ops", SignerKey: priv,
	})
	if len(g.AllowExec) == 0 {
		t.Error("deploy scope should have default exec list")
	}
	if len(g.AllowWrite) == 0 {
		t.Error("deploy scope should have default write list")
	}
}

func TestRemaining(t *testing.T) {
	_, priv := genKey(t)
	g, _ := Mint(MintParams{
		AppName: "a", CgroupMatch: "/x", Reason: "r",
		TTL: 30 * time.Minute, SignerName: "ops", SignerKey: priv,
	})
	r := g.Remaining()
	if r < 29*time.Minute || r > 31*time.Minute {
		t.Errorf("expected ~30m remaining, got %v", r)
	}
}

func TestNewID_Unique(t *testing.T) {
	ids := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := newID()
		if ids[id] {
			t.Fatalf("duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}
