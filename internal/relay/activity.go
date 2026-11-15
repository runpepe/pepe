package relay

import (
	"encoding/json"
	"log"
	"net/http"
)

type Activity struct {
	ID          string          `json:"id"`
	Session     string          `json:"session"`
	Kind        string          `json:"kind"`
	Result      string          `json:"result"`
	Destination string          `json:"destination"`
	Details     json.RawMessage `json:"details,omitempty"`
	Created     int64           `json:"created"`
}

// Activity stores routing metadata only. OAuth parameters, headers, and bodies
// never enter this log. Failure to record activity must not interrupt delivery.
func (s *Server) recordActivity(session, kind, result, destination string, details ...map[string]any) {
	id := Token()
	_, err := s.Store.Exec("INSERT INTO activity(namespace,id,session,kind,result,destination,created) VALUES(?,?,?,?,?,?,?)", s.Store.namespace, id, session, kind, result, destination, s.Now().UnixMilli())
	if err != nil {
		log.Print("could not record relay activity")
	}
	if err == nil && len(details) > 0 {
		payload, _ := json.Marshal(details[0])
		if _, err = s.Store.Exec("INSERT INTO activity_details(namespace,id,payload) VALUES(?,?,?)", s.Store.namespace, id, string(payload)); err != nil {
			log.Print("could not record relay request details")
		}
	}
}

func (s *Server) activity(w http.ResponseWriter, r *http.Request, session string) {
	if !auth(r, s.AdminToken) {
		fail(w, 401, "unauthorized")
		return
	}
	rows, err := s.Store.Query("SELECT id,session,kind,result,destination,created FROM activity WHERE namespace=? AND session=? ORDER BY created DESC,id DESC LIMIT 1000", s.Store.namespace, session)
	if err != nil {
		fail(w, 503, "activity unavailable")
		return
	}
	defer rows.Close()
	entries := []Activity{}
	for rows.Next() {
		var entry Activity
		if err = rows.Scan(&entry.ID, &entry.Session, &entry.Kind, &entry.Result, &entry.Destination, &entry.Created); err != nil {
			fail(w, 503, "activity unavailable")
			return
		}
		entries = append(entries, entry)
	}
	if rows.Err() != nil {
		fail(w, 503, "activity unavailable")
		return
	}
	rows.Close()
	for i := range entries {
		var payload string
		if err := s.Store.QueryRow("SELECT payload FROM activity_details WHERE namespace=? AND id=?", s.Store.namespace, entries[i].ID).Scan(&payload); err == nil {
			entries[i].Details = json.RawMessage(payload)
		}
	}
	reply(w, 200, map[string]any{"activity": entries})
}
