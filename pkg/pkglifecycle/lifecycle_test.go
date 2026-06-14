package pkglifecycle

import "testing"

func fakeEnvReader(envs map[uint32]map[string]string) func(uint32) (map[string]string, error) {
	return func(pid uint32) (map[string]string, error) {
		return envs[pid], nil
	}
}

// TestTagSpawn_NpmPostinstall: a process with npm lifecycle env vars gets tagged.
func TestTagSpawn_NpmPostinstall(t *testing.T) {
	tagger := newWithReader(fakeEnvReader(map[uint32]map[string]string{
		100: {
			"npm_lifecycle_event": "postinstall",
			"npm_package_name":    "noon-contracts",
			"npm_config_registry": "https://registry.npmjs.org",
		},
	}))
	tagger.TagSpawn(100, 1)

	ctx := tagger.Tag(100)
	if ctx == nil {
		t.Fatal("expected npm context for PID 100, got nil")
	}
	if ctx.PackageName != "noon-contracts" {
		t.Errorf("PackageName = %q, want noon-contracts", ctx.PackageName)
	}
	if ctx.LifecycleEvent != "postinstall" {
		t.Errorf("LifecycleEvent = %q, want postinstall", ctx.LifecycleEvent)
	}
	if ctx.Registry != "https://registry.npmjs.org" {
		t.Errorf("Registry = %q, want https://registry.npmjs.org", ctx.Registry)
	}
}

// TestTagSpawn_ChildInherits: a child that lacks npm vars inherits from its parent.
// This is the main attack shape: postinstall spawns node/sh/curl/aws which
// don't have npm vars in their own environ.
func TestTagSpawn_ChildInherits(t *testing.T) {
	tagger := newWithReader(fakeEnvReader(map[uint32]map[string]string{
		100: {
			"npm_lifecycle_event": "postinstall",
			"npm_package_name":    "noon-contracts",
		},
		// PID 200 (child) has no npm vars
	}))
	tagger.TagSpawn(100, 1)   // postinstall root
	tagger.TagSpawn(200, 100) // child spawned by postinstall (e.g. sh -c curl ...)

	ctx := tagger.Tag(200)
	if ctx == nil {
		t.Fatal("child should inherit parent npm context")
	}
	if ctx.PackageName != "noon-contracts" {
		t.Errorf("PackageName = %q, want noon-contracts", ctx.PackageName)
	}
}

// TestTagSpawn_GrandchildInherits: lineage propagates through multiple generations.
// postinstall → node → aws cli (grandchild) should all be tagged.
func TestTagSpawn_GrandchildInherits(t *testing.T) {
	tagger := newWithReader(fakeEnvReader(map[uint32]map[string]string{
		100: {"npm_lifecycle_event": "postinstall", "npm_package_name": "evil-pkg"},
	}))
	tagger.TagSpawn(100, 1)   // postinstall
	tagger.TagSpawn(200, 100) // node
	tagger.TagSpawn(300, 200) // aws (spawned by node)

	if tagger.Tag(300) == nil {
		t.Fatal("grandchild should inherit npm context")
	}
}

// TestTagSpawn_NormalProcess_NoTag: a process without npm vars is not tagged.
func TestTagSpawn_NormalProcess_NoTag(t *testing.T) {
	tagger := newWithReader(fakeEnvReader(map[uint32]map[string]string{
		100: {"HOME": "/root", "PATH": "/usr/bin:/bin"},
	}))
	tagger.TagSpawn(100, 1)
	if ctx := tagger.Tag(100); ctx != nil {
		t.Errorf("expected no npm context for normal process, got %+v", ctx)
	}
}

// TestOnExit_CleansUp: OnExit removes the pid from the tracker.
func TestOnExit_CleansUp(t *testing.T) {
	tagger := newWithReader(fakeEnvReader(map[uint32]map[string]string{
		100: {"npm_lifecycle_event": "postinstall", "npm_package_name": "evil"},
	}))
	tagger.TagSpawn(100, 1)
	if tagger.Tag(100) == nil {
		t.Fatal("expected context before exit")
	}
	tagger.OnExit(100)
	if tagger.Tag(100) != nil {
		t.Fatal("expected no context after exit")
	}
}

// TestNilTagger_Safe: nil receiver does not panic.
func TestNilTagger_Safe(t *testing.T) {
	var tagger *Tagger
	tagger.TagSpawn(100, 1)
	tagger.OnExit(100)
	if tagger.Tag(100) != nil {
		t.Fatal("nil tagger should return nil")
	}
}
