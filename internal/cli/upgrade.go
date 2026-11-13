package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/marccampbell/pepe/internal/relay"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

const releasePublicKey = "Pb/DI60gEUsD/KSlfSnSlSwix84CU5a99EiHt2dL32k="
const releases = "https://github.com/marccampbell/pepe/releases/download/"

type manifest struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"files"`
}

func fetch(url string, limit int64) ([]byte, error) {
	c := &http.Client{Timeout: 2 * time.Minute}
	r, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("download returned HTTP %d", r.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("download exceeds size limit")
	}
	return b, err
}
func verifyManifest(raw, sig []byte, version string) (manifest, error) {
	var m manifest
	key, _ := base64.StdEncoding.DecodeString(releasePublicKey)
	if !ed25519.Verify(ed25519.PublicKey(key), raw, sig) {
		return m, errors.New("invalid release signature")
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, err
	}
	if m.Version != version {
		return m, errors.New("release version mismatch")
	}
	return m, nil
}
func upgrade(args []string, current string) error {
	f := flags("upgrade")
	version := f.String("version", "", "release version (default: latest stable)")
	check := f.Bool("check", false, "check without installing")
	if err := parse(f, args); err != nil {
		return err
	}
	if *version == "" {
		b, err := fetch("https://api.github.com/repos/marccampbell/pepe/releases/latest", 1<<20)
		if err != nil {
			return err
		}
		var v struct {
			Tag string `json:"tag_name"`
		}
		if err = json.Unmarshal(b, &v); err != nil {
			return err
		}
		*version = v.Tag
	}
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(*version) {
		return errors.New("expected stable version vMAJOR.MINOR.PATCH")
	}
	base := releases + *version + "/"
	raw, err := fetch(base+"manifest.json", 1<<20)
	if err != nil {
		return err
	}
	sig, err := fetch(base+"manifest.sig", 1024)
	if err != nil {
		return err
	}
	m, err := verifyManifest(raw, sig, *version)
	if err != nil {
		return err
	}
	name := "pepe_" + runtime.GOOS + "_" + runtime.GOARCH
	expected, ok := m.Files[name]
	if !ok {
		return errors.New("release does not support this platform")
	}
	fmt.Printf("Installed: %s; release: %s\n", current, m.Version)
	if *check || current == m.Version {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	if filepath.Base(filepath.Dir(exe)) == "bin" && filepath.Dir(exe) != "/usr/local/bin" {
		return errors.New("this installation may be package-managed; upgrade with your package manager")
	}
	b, err := fetch(base+name, 200<<20)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != expected {
		return errors.New("binary checksum mismatch")
	}
	old, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	_, serviceErr := os.Stat("/etc/systemd/system/pepe.service")
	service := runtime.GOOS == "linux" && serviceErr == nil && exe == "/usr/local/bin/pepe"
	var c Config
	backup := ""
	if service {
		if err = requireRoot(); err != nil {
			return err
		}
		c, err = readConfig("/etc/pepe/pepe.json")
		if err != nil {
			return err
		}
		if err = command("systemctl", "stop", "pepe.service"); err != nil {
			return err
		}
		restartOnError := func(e error) error { _ = command("systemctl", "start", "pepe.service"); return e }
		store, e := relay.Open(c.Database)
		if e != nil {
			return restartOnError(e)
		}
		backup = c.Database + ".backup-" + time.Now().UTC().Format("20060102T150405.000000000")
		e = store.Backup(backup)
		store.Close()
		if e != nil {
			return restartOnError(e)
		}
		if err = os.Chmod(backup, 0600); err != nil {
			return restartOnError(err)
		}
	}
	if err = atomicWrite(exe, b, 0755); err != nil {
		if service {
			_ = command("systemctl", "start", "pepe.service")
		}
		return err
	}
	if service {
		err = command("systemctl", "start", "pepe.service")
		if err == nil {
			err = health("http://" + c.Listen)
		}
		if err != nil {
			stopErr := command("systemctl", "stop", "pepe.service")
			if stopErr != nil {
				return fmt.Errorf("upgrade failed (%v); could not stop for rollback: %w; database backup: %s", err, stopErr, backup)
			}
			if e := atomicWrite(exe, old, 0755); e != nil {
				return fmt.Errorf("binary rollback failed: %w; backup: %s", e, backup)
			}
			saved, e := os.ReadFile(backup)
			if e != nil {
				return e
			}
			for _, suffix := range []string{"-wal", "-shm"} {
				if e = os.Remove(c.Database + suffix); e != nil && !os.IsNotExist(e) {
					return e
				}
			}
			if e = atomicWrite(c.Database, saved, 0600); e != nil {
				return e
			}
			if e = command("chown", "pepe:pepe", c.Database); e != nil {
				return e
			}
			if e = command("systemctl", "start", "pepe.service"); e != nil {
				return fmt.Errorf("rollback restart failed: %w", e)
			}
			return fmt.Errorf("upgrade failed and previous binary/database restored: %w", err)
		}
	}
	fmt.Printf("Upgraded to %s\n", m.Version)
	if backup != "" {
		fmt.Printf("Database backup: %s\n", backup)
	}
	return nil
}
