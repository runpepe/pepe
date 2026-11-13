// Command release builds and signs distributable binaries. No CI required.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: go run ./scripts/release v0.1.0 /private/path/to/signing-key")
	}
	version := os.Args[1]
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(version) {
		panic("invalid version")
	}
	raw, e := os.ReadFile(os.Args[2])
	must(e)
	key, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	must(e)
	if len(key) != ed25519.PrivateKeySize {
		panic("invalid signing key")
	}
	if base64.StdEncoding.EncodeToString(ed25519.PrivateKey(key).Public().(ed25519.PublicKey)) != "Pb/DI60gEUsD/KSlfSnSlSwix84CU5a99EiHt2dL32k=" {
		panic("key does not match release trust root")
	}
	must(os.MkdirAll("dist", 0755))
	files := map[string]string{}
	for _, platform := range []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"} {
		p := strings.Split(platform, "/")
		name := "pepe_" + p[0] + "_" + p[1]
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w -X main.version="+version, "-o", filepath.Join("dist", name), "./cmd/pepe")
		cmd.Env = append(os.Environ(), "GOOS="+p[0], "GOARCH="+p[1], "CGO_ENABLED=0")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		must(cmd.Run())
		b, e := os.ReadFile(filepath.Join("dist", name))
		must(e)
		h := sha256.Sum256(b)
		files[name] = hex.EncodeToString(h[:])
		fmt.Println("built", name)
	}
	m := struct {
		Version string            `json:"version"`
		Files   map[string]string `json:"files"`
	}{version, files}
	b, e := json.MarshalIndent(m, "", "  ")
	must(e)
	b = append(b, '\n')
	must(os.WriteFile("dist/manifest.json", b, 0644))
	must(os.WriteFile("dist/manifest.sig", ed25519.Sign(key, b), 0644))
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
