package db

import "database/sql"

// DefaultAdminPasswordPlaceholder is the hash value migration 001 seeds the
// built-in admin with. It is not a valid bcrypt hash, so login already fails
// closed; this constant lets startup warn the operator to set a real one.
const DefaultAdminPasswordPlaceholder = "CHANGE_ME_RUN_HASHPW_TOOL"

// IsDefaultAdminPassword reports whether the built-in admin account still has
// the placeholder hash from migration 001.
func IsDefaultAdminPassword(db *sql.DB) (bool, error) {
	var h string
	err := db.QueryRow("SELECT password_hash FROM users WHERE id = 'u_admin'").Scan(&h)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return h == DefaultAdminPasswordPlaceholder, nil
}
