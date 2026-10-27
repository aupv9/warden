package main

import (
	"bytes"
	"strings"
	"testing"
)

// Bad arguments are rejected before any database connection is attempted.
func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"org"},
		{"org", "delete"},
		{"org", "create", "--name", "Acme"},
		{"org", "set-role", "--org", "not-a-uuid", "--email", "a@b.c", "--role", "member"},
		{"org", "set-role", "--org", "8b3c2f8e-7b0e-4d3c-9a51-0c6f1f0b2a11", "--email", "a@b.c", "--role", "root"},
		{"org", "set-role", "--org", "8b3c2f8e-7b0e-4d3c-9a51-0c6f1f0b2a11", "--role", "member"},
		{"audit", "verify", "--org", "x"},
		{"org", "add-member", "--org", "x", "--email", "a@b.c", "--role", "member"},
		{"org", "add-member", "--org", "8b3c2f8e-7b0e-4d3c-9a51-0c6f1f0b2a11", "--email", "a@b.c", "--role", "owner"},
		{"user", "relink", "--email", "a@b.c"},                                 // neither --sub nor --next-sign-in
		{"user", "relink", "--email", "a@b.c", "--sub", "s", "--next-sign-in"}, // both
		{"user", "relink", "--sub", "s"},
		{"user", "relink", "--email", "a@b.c", "--next-sign-in", "--within", "soon"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage:") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errOut.String())
		}
	}
	for _, r := range []string{"org_admin", "security_lead", "member"} {
		if !validRole(r) {
			t.Error(r)
		}
	}
}
