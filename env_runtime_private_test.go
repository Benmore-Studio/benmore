//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeCredentialsStayOutOfAppEnvironment(t *testing.T) {
	const key, secret = "BENMORE_SERVER_SECRET", "local-fixture-runtime-secret-12345678"
	t.Setenv(key, secret)
	if got := GetEnv("", key); got != secret {
		t.Fatal("operator access was removed")
	}
	for _, source := range []string{"process", "generated", "yaml", "credential"} {
		t.Run(source, func(t *testing.T) {
			dir := t.TempDir()
			var data []byte
			switch source {
			case "generated":
				if err := os.MkdirAll(filepath.Join(dir, ".benmore"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, ".benmore", "env"), []byte(key+"="+secret+"\nAPP_TOKEN=app-owned\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "yaml":
				data = []byte(key + ": " + secret + "\nAPP_TOKEN: app-owned\n")
			case "credential":
				t.Setenv(key, "")
				credDir := t.TempDir()
				t.Setenv("CREDENTIALS_DIRECTORY", credDir)
				if err := os.WriteFile(filepath.Join(credDir, strings.ToLower(key)), []byte(secret), 0600); err != nil {
					t.Fatal(err)
				}
			}
			values, err := readAppEnvFromSource(dir, data)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := values[key]; ok {
				t.Fatal("runtime credential entered app snapshot")
			}
		})
	}
	dir := t.TempDir()
	values := map[string]string{key: secret, "APP_TOKEN": "app-owned"}
	storeAppEnv(dir, values)
	SetAppEnv(dir, key, secret)
	if GetAppEnv(dir, key) != "" || AppEnvSnapshot(dir)[key] != "" || appEnvSnapshot(dir, values)[key] != "" {
		t.Fatal("private credential visible through app accessor")
	}
	if GetAppEnv(dir, "APP_TOKEN") != "app-owned" {
		t.Fatal("app-owned credential was removed")
	}
	if strings.Contains(interpolateEnvValues("{{env.BENMORE_SERVER_SECRET}}", values), secret) {
		t.Fatal("private credential interpolated")
	}
	if envLookupFromSource([]byte(key+": "+secret), key) != "" {
		t.Fatal("Go template exposed private credential")
	}
}
