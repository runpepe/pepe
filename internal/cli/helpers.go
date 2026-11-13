package cli

import (
	"fmt"
	"github.com/marccampbell/pepe/internal/relay"
	"net/http"
	"time"
)

func randomToken() string { return relay.Token() }
func health(base string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	var last error
	for n := 0; n < 5; n++ {
		r, e := client.Get(base + "/healthz")
		if e == nil {
			r.Body.Close()
			if r.StatusCode == 200 {
				return nil
			}
			e = fmt.Errorf("HTTP %d", r.StatusCode)
		}
		last = e
		time.Sleep(time.Second)
	}
	return last
}
