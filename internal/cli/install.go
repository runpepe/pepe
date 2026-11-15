package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const unit = `[Unit]
Description=Pepe callback router
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pepe
Group=pepe
ExecStart=/usr/local/bin/pepe serve --config /etc/pepe/pepe.json
Restart=on-failure
RestartSec=3
StateDirectory=pepe
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/pepe

[Install]
WantedBy=multi-user.target
`

func command(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
func requireRoot() error {
	if runtime.GOOS != "linux" {
		return errors.New("service installation requires Linux with systemd")
	}
	if os.Geteuid() != 0 {
		return errors.New("run this command with sudo")
	}
	return nil
}
func atomicWrite(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pepe-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func install(args []string) error {
	f := flags("install")
	domain := f.String("domain", "", "public DNS hostname")
	public := f.String("public-url", "", "public HTTPS URL for an existing proxy")
	proxy := f.String("proxy", "", "caddy or empty (existing proxy)")
	dry := f.Bool("dry-run", false, "print installation plan without changing the host")
	if err := parse(f, args); err != nil {
		return err
	}
	if *proxy != "" && *proxy != "caddy" {
		return errors.New("proxy must be caddy or omitted")
	}
	if *domain != "" {
		if !regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`).MatchString(*domain) || !strings.Contains(*domain, ".") {
			return errors.New("domain must be a DNS hostname")
		}
		if *public != "" {
			return errors.New("choose --domain or --public-url")
		}
		*public = "https://" + *domain
	}
	u, err := url.Parse(*public)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("a public HTTPS origin is required")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`).MatchString(u.Hostname()) {
		return errors.New("public URL must have a DNS hostname")
	}
	caddy := fmt.Sprintf("%s {\n    reverse_proxy 127.0.0.1:8080\n}\n", u.Host)
	if *dry {
		fmt.Printf("Install /usr/local/bin/pepe\nCreate unprivileged pepe user\nPreserve or create /etc/pepe/pepe.json (0600, pepe-owned)\nState: /var/lib/pepe\nEnable pepe.service:\n%s", unit)
		if *proxy == "caddy" {
			fmt.Printf("Caddy configuration:\n%s", caddy)
		}
		return nil
	}
	if err = requireRoot(); err != nil {
		return err
	}
	if _, err = exec.LookPath("systemctl"); err != nil {
		return errors.New("systemctl is required")
	}
	if *proxy == "caddy" {
		if _, err = exec.LookPath("caddy"); err != nil {
			return errors.New("install Caddy using its official OS package first, then rerun")
		}
		if b, e := os.ReadFile("/etc/caddy/Caddyfile"); e == nil && !strings.Contains(string(b), "import /etc/caddy/pepe.caddy") {
			return errors.New("add 'import /etc/caddy/pepe.caddy' to your existing Caddyfile, then rerun; Pepe will not overwrite it")
		}
	}
	if err = command("id", "-u", "pepe"); err != nil {
		if err = command("useradd", "--system", "--user-group", "--home-dir", "/var/lib/pepe", "--shell", "/usr/sbin/nologin", "pepe"); err != nil {
			return err
		}
	}
	for _, p := range []string{"/etc/pepe", "/var/lib/pepe", "/usr/local/bin", "/etc/systemd/system"} {
		if err = os.MkdirAll(p, 0755); err != nil {
			return err
		}
	}
	path := "/etc/pepe/pepe.json"
	if existing, e := readConfig(path); e == nil && strings.TrimRight(existing.PublicURL, "/") != strings.TrimRight(*public, "/") {
		return errors.New("existing configuration has a different public URL; update it explicitly before reinstalling")
	}
	if _, err = os.Stat(path); os.IsNotExist(err) {
		c := Config{Listen: "127.0.0.1:8080", PublicURL: strings.TrimRight(*public, "/"), Database: "/var/lib/pepe/pepe.sqlite", AdminToken: randomToken(), WebhookSecret: randomToken()}
		b, _ := json.MarshalIndent(c, "", "  ")
		if err = atomicWrite(path, append(b, '\n'), 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err = command("chown", "-R", "pepe:pepe", "/var/lib/pepe"); err != nil {
		return err
	}
	if err = command("chmod", "0700", "/var/lib/pepe"); err != nil {
		return err
	}
	if err = command("chown", "pepe:pepe", path); err != nil {
		return err
	}
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(executable)
	if err != nil {
		return err
	}
	if err = atomicWrite("/usr/local/bin/pepe", b, 0755); err != nil {
		return err
	}
	if err = atomicWrite("/etc/systemd/system/pepe.service", []byte(unit), 0644); err != nil {
		return err
	}
	if *proxy == "caddy" {
		if err = os.MkdirAll("/etc/caddy", 0755); err != nil {
			return err
		}
		main := "/etc/caddy/Caddyfile"
		if _, err = os.Stat(main); os.IsNotExist(err) {
			if err = atomicWrite(main, []byte("import /etc/caddy/pepe.caddy\n"), 0644); err != nil {
				return err
			}
		}
		if err = atomicWrite("/etc/caddy/pepe.caddy", []byte(caddy), 0644); err != nil {
			return err
		}
		if err = command("caddy", "validate", "--config", main); err != nil {
			return err
		}
	}
	if err = command("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err = command("systemctl", "enable", "pepe.service"); err != nil {
		return err
	}
	if err = command("systemctl", "restart", "pepe.service"); err != nil {
		return err
	}
	if *proxy == "caddy" {
		if err = command("systemctl", "enable", "--now", "caddy.service"); err != nil {
			return err
		}
		if err = command("systemctl", "reload", "caddy.service"); err != nil {
			return err
		}
	}
	c, err := readConfig(path)
	if err != nil {
		return err
	}
	if err = health("http://" + c.Listen); err != nil {
		return fmt.Errorf("service installed but local health check failed: %w", err)
	}
	fmt.Println("Pepe installed. Credentials: /etc/pepe/pepe.json (not printed).")
	if *proxy == "caddy" {
		if err = health(c.PublicURL); err != nil {
			return fmt.Errorf("Pepe is healthy locally; public HTTPS is not ready (check DNS and ports 80/443): %w", err)
		}
	} else {
		fmt.Printf("Configure your reverse proxy for %s → %s\n", c.PublicURL, c.Listen)
	}
	return nil
}
func uninstall(args []string) error {
	f := flags("uninstall")
	purge := f.Bool("purge", false, "delete Pepe configuration, credentials and queued events")
	if err := parse(f, args); err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if err := command("systemctl", "disable", "--now", "pepe.service"); err != nil {
		return err
	}
	for _, p := range []string{"/etc/systemd/system/pepe.service", "/usr/local/bin/pepe"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := command("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if *purge {
		for _, p := range []string{"/etc/pepe", "/var/lib/pepe"} {
			if err := os.RemoveAll(p); err != nil {
				return err
			}
		}
	}
	fmt.Println("Pepe service removed. Caddy configuration is preserved; remove its Pepe route when ready.")
	return nil
}
