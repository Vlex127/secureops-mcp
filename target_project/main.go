package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("cmd")
	out, _ := exec.Command("sh", "-c", userInput).Output()
	fmt.Fprintf(w, string(out))
}

func queryHandler(db *sql.DB, userInput string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userInput)
	db.Exec(query)
}

var apiSecret = "sk-live-abc123def456ghi789jklmno"

func main() {
	http.HandleFunc("/exec", handler)
	http.ListenAndServe(":8080", nil)
}
