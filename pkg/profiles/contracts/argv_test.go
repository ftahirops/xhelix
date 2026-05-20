package contracts

import "testing"

func TestClassifyArgvShape(t *testing.T) {
	cases := []struct {
		path string
		argv []string
		want string
	}{
		{"/usr/bin/base64", []string{"-d"}, "base64_decode"},
		{"/usr/bin/base64", []string{"--decode", "file.txt"}, "base64_decode"},
		{"/usr/bin/base64", []string{"file.txt"}, ""},
		{"/usr/bin/openssl", []string{"base64", "-d", "in.b64"}, "base64_decode"},
		{"/usr/bin/openssl", []string{"sha256", "file"}, ""},
		{"/usr/bin/xxd", []string{"-r", "-p"}, "base64_decode"},
		{"/usr/bin/xxd", []string{"file"}, ""},

		{"/bin/rm", []string{"-rf", "/tmp/cache"}, "recursive_delete"},
		{"/bin/rm", []string{"-r", "-f", "/tmp/cache"}, "recursive_delete"},
		{"/bin/rm", []string{"-fr", "/tmp/x"}, "recursive_delete"},
		{"/bin/rm", []string{"file"}, ""},
		{"/bin/rm", []string{"-f", "file"}, ""}, // -f alone is not recursive

		{"/bin/chmod", []string{"+x", "/tmp/dropper.sh"}, "chmod_exec"},
		{"/bin/chmod", []string{"755", "/dev/shm/x"}, "chmod_exec"},
		{"/bin/chmod", []string{"0777", "/var/tmp/x"}, "chmod_exec"},
		{"/bin/chmod", []string{"+x", "/usr/local/bin/legitimate"}, ""}, // not a tempfile
		{"/bin/chmod", []string{"644", "/tmp/x"}, ""},                   // no exec bit

		{"/usr/sbin/nginx", []string{"-t"}, ""}, // legitimate
		{"", nil, ""},
	}
	for _, tc := range cases {
		got := ClassifyArgvShape(tc.path, tc.argv)
		if got != tc.want {
			t.Errorf("ClassifyArgvShape(%q, %v) = %q, want %q", tc.path, tc.argv, got, tc.want)
		}
	}
}
