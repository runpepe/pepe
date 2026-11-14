package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/runpepe/pepe/internal/relay"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Listen        string `json:"listen"`
	PublicURL     string `json:"public_url"`
	Database      string `json:"database"`
	AdminToken    string `json:"admin_token"`
	WebhookSecret string `json:"webhook_secret"`
}

func Run(args []string, version string) (err error) {
	defer func() {
		if errors.Is(err, flag.ErrHelp) {
			err = nil
		}
	}()
	if len(args) == 0 {
		help()
		return nil
	}
	switch args[0] {
	case "help", "--help", "-h":
		help()
		return nil
	case "version", "--version":
		fmt.Println(version)
		return nil
	case "serve":
		return serve(args[1:])
	case "run":
		return runAgent(args[1:])
	case "status":
		return status(args[1:])
	case "replay":
		return replay(args[1:])
	case "claim":
		return claim(args[1:])
	case "install":
		return install(args[1:])
	case "uninstall":
		return uninstall(args[1:])
	case "upgrade":
		return upgrade(args[1:], version)
	default:
		return fmt.Errorf("unknown command %q; run pepe help", args[0])
	}
}
func help() {
	fmt.Print(`Pepe — stable callbacks for disposable development environments.

  pepe run        Connect this workspace and deliver webhooks locally
  pepe serve      Run a public relay (SQLite-backed)
  pepe status     Show relay health and queue counts
  pepe replay     Requeue a stored delivery for this workspace
  pepe claim      Bind a repository ID and PR to this workspace
  pepe install    Install a Linux systemd relay; optionally configure Caddy
  pepe uninstall  Remove the service; preserve state unless --purge
  pepe upgrade    Install an explicitly supplied development build
  pepe version    Print version

Use pepe <command> --help for options. https://runpepe.dev
`)
}
func flags(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ContinueOnError) }
func parse(f *flag.FlagSet, args []string) error {
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(f.Args(), " "))
	}
	return nil
}
func readConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}
func serve(args []string) error {
	f := flags("serve")
	config := f.String("config", "", "JSON config file (optional)")
	listen := f.String("listen", "127.0.0.1:8080", "listen address")
	database := f.String("db", "pepe.sqlite", "SQLite file")
	public := f.String("public-url", "http://localhost:8080", "externally reachable URL")
	if err := parse(f, args); err != nil {
		return err
	}
	c := Config{Listen: *listen, Database: *database, PublicURL: *public, AdminToken: os.Getenv("PEPE_ADMIN_TOKEN"), WebhookSecret: os.Getenv("PEPE_GITHUB_WEBHOOK_SECRET")}
	if *config != "" {
		var err error
		c, err = readConfig(*config)
		if err != nil {
			return err
		}
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.Database == "" {
		return errors.New("database path required")
	}
	s, err := relay.Open(c.Database)
	if err != nil {
		return err
	}
	defer s.Close()
	handler, err := relay.New(s, c.AdminToken, c.WebhookSecret, c.PublicURL)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: c.Listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32768}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		log.Printf("Pepe listening on %s; public URL %s", c.Listen, c.PublicURL)
		done <- server.ListenAndServe()
	}()
	select {
	case err = <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
	return nil
}
func request(ctx context.Context, client *http.Client, server, path, token string, input, output any) error {
	b, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(server, "/")+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("relay returned HTTP %d", res.StatusCode)
	}
	if output != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 60_000_000)).Decode(output)
	}
	return nil
}
func apiClient() *http.Client {
	return &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

type identity struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

func workspace(path string) (identity, error) {
	var i identity
	b, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(b, &i)
		if err == nil && (i.ID == "" || len(i.Token) < 32) {
			err = errors.New("invalid workspace identity")
		}
		return i, err
	}
	if !os.IsNotExist(err) {
		return i, err
	}
	i = identity{"p_" + relay.Token()[:12], relay.Token()}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return i, err
	}
	b, _ = json.MarshalIndent(i, "", "  ")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return i, err
	}
	_, err = file.Write(b)
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	return i, err
}
func runAgent(args []string) error {
	f := flags("run")
	server := f.String("server", os.Getenv("PEPE_SERVER"), "public relay URL")
	target := f.String("target", "http://127.0.0.1:3000/api/github/webhook", "local webhook receiver")
	callback := f.String("callback", "", "exact application OAuth callback URL")
	state := f.String("state", ".pepe/identity.json", "persistent workspace identity file")
	localSecret := f.String("webhook-secret-env", "PEPE_LOCAL_WEBHOOK_SECRET", "optional env var for local webhook signing key")
	if err := parse(f, args); err != nil {
		return err
	}
	if err := relay.ValidateURL(*server); err != nil {
		return err
	}
	u, err := url.Parse(*target)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("target must be an HTTP(S) URL")
	}
	i, err := workspace(*state)
	if err != nil {
		return err
	}
	client := apiClient()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	admin := os.Getenv("PEPE_ADMIN_TOKEN")
	if admin == "" {
		return errors.New("set PEPE_ADMIN_TOKEN to register this workspace")
	}
	if err = request(ctx, client, *server, "/sessions", admin, map[string]string{"id": i.ID, "token": i.Token, "callback": *callback}, nil); err != nil {
		return err
	}
	fmt.Printf("Pepe connected · %s\nLocal app: %s\nBranch prefix: pepe/%s/\nIdentity: %s (keep this private)\n", i.ID, *target, i.ID, *state)
	for {
		if ctx.Err() != nil {
			return nil
		}
		var batch struct {
			Events []relay.Event `json:"events"`
		}
		err = request(ctx, client, *server, "/sessions/"+i.ID+"/poll", i.Token, struct{}{}, &batch)
		if err != nil {
			log.Printf("poll failed: %v", err)
		} else {
			for _, e := range batch.Events {
				if err = fetchEvent(ctx, client, *server, i, &e); err != nil {
					log.Printf("fetch %s failed: %v", e.Delivery, err)
					break
				}
				if err = deliver(ctx, client, *target, os.Getenv(*localSecret), e); err != nil {
					log.Printf("delivery %s failed: %v (will retry)", e.Delivery, err)
					break
				}
				if err = request(ctx, client, *server, "/sessions/"+i.ID+"/ack", i.Token, map[string]any{"delivery": e.Delivery, "attempt": e.Attempt}, nil); err != nil {
					log.Printf("ack failed: %v", err)
					break
				}
				log.Printf("delivered %s %s", e.Event, e.Delivery)
			}
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
func status(args []string) error {
	f := flags("status")
	server := f.String("server", os.Getenv("PEPE_SERVER"), "public relay URL")
	if err := parse(f, args); err != nil {
		return err
	}
	if err := relay.ValidateURL(*server); err != nil {
		return err
	}
	var out any
	if err := request(context.Background(), apiClient(), *server, "/status", os.Getenv("PEPE_ADMIN_TOKEN"), struct{}{}, &out); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	return nil
}
func claim(args []string) error {
	f := flags("claim")
	server := f.String("server", os.Getenv("PEPE_SERVER"), "public relay URL")
	state := f.String("state", ".pepe/identity.json", "workspace identity")
	repo := f.Int64("repo", 0, "numeric GitHub repository ID")
	pr := f.Int64("pr", 0, "PR number")
	if err := parse(f, args); err != nil {
		return err
	}
	if err := relay.ValidateURL(*server); err != nil {
		return err
	}
	b, err := os.ReadFile(*state)
	if err != nil {
		return err
	}
	var i identity
	if err = json.Unmarshal(b, &i); err != nil {
		return err
	}
	return request(context.Background(), apiClient(), *server, "/sessions/"+i.ID+"/claim", i.Token, map[string]int64{"repo": *repo, "pr": *pr}, nil)
}

func replay(args []string) error {
	f := flags("replay")
	server := f.String("server", os.Getenv("PEPE_SERVER"), "public relay URL")
	state := f.String("state", ".pepe/identity.json", "workspace identity")
	delivery := f.String("delivery", "", "stored upstream delivery ID")
	if err := parse(f, args); err != nil {
		return err
	}
	if *delivery == "" {
		return errors.New("delivery required")
	}
	if err := relay.ValidateURL(*server); err != nil {
		return err
	}
	b, err := os.ReadFile(*state)
	if err != nil {
		return err
	}
	var i identity
	if err = json.Unmarshal(b, &i); err != nil {
		return err
	}
	var out any
	if err = request(context.Background(), apiClient(), *server, "/sessions/"+i.ID+"/replay", i.Token, map[string]string{"delivery": *delivery}, &out); err != nil {
		return err
	}
	b, _ = json.Marshal(out)
	fmt.Println(string(b))
	return nil
}
