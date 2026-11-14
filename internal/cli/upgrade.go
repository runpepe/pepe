package cli

import (
	"errors"
	"fmt"
	"github.com/runpepe/pepe/internal/relay"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Development upgrades use an explicitly supplied build, not published releases.
func upgrade(args []string, current string) error {
	f := flags("upgrade")
	binary := f.String("binary", "", "path to a locally built Pepe executable")
	check := f.Bool("check", false, "inspect the supplied development build without installing")
	if err := parse(f, args); err != nil {
		return err
	}
	if *binary == "" {
		if *check {
			fmt.Printf("Installed: %s; development builds only, no release channel\n", current)
			return nil
		}
		return errors.New("Pepe is pre-release; supply --binary /path/to/a/source-build")
	}
	candidate, err := filepath.Abs(*binary)
	if err != nil {
		return err
	}
	info, err := os.Stat(candidate)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return errors.New("binary must be a regular executable")
	}
	out, err := exec.Command(candidate, "version").Output()
	if err != nil {
		return fmt.Errorf("candidate version check: %w", err)
	}
	candidateVersion := strings.TrimSpace(string(out))
	fmt.Printf("Installed: %s; candidate: %s\n", current, candidateVersion)
	if *check {
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
	b, err := os.ReadFile(candidate)
	if err != nil {
		return err
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
	fmt.Printf("Upgraded to %s\n", candidateVersion)
	if backup != "" {
		fmt.Printf("Database backup: %s\n", backup)
	}
	return nil
}
