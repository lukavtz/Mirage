package main

import (
	"database/sql"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func main() {
	pw := "admin"
	if len(os.Args) > 1 {
		pw = os.Args[1]
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(hash))

	db, err := sql.Open("sqlite", "data/mirage.db")
	if err != nil {
		fmt.Fprintf(os.Stderr, "db open: %v\n", err)
		return
	}
	defer db.Close()

	res, err := db.Exec("UPDATE users SET password_hash = ? WHERE id = 'u_admin'", string(hash))
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
		return
	}
	n, _ := res.RowsAffected()
	fmt.Fprintf(os.Stderr, "admin password set (%d rows)\n", n)
}
