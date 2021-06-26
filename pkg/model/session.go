package model

type Command struct {
	SessionID  string `json:"session"`
	OrgID      string `json:"org_id"`
	Input      string `json:"input"`
	Output     string `json:"output"`
	User       string `json:"user"`
	Server     string `json:"asset"`
	SystemUser string `json:"system_user"`
	Timestamp  int64  `json:"timestamp"`
	RiskLevel  int64  `json:"risk_level"`

	RemoteAddress string `json:"remote_address"`
	ManageType string `json:"manage_type"`
	EventMsg string `json:"event_msg"`
	AssetOperatingSystemType string `json:"asset_operating_system_type"`
	AssetRegisteredName string `json:"asset_registered_name"`
}

type FTPLog struct {
	User       string `json:"user"`
	Hostname   string `json:"asset"`
	OrgID      string `json:"org_id"`
	SystemUser string `json:"system_user"`
	RemoteAddr string `json:"remote_addr"`
	Operate    string `json:"operate"`
	Path       string `json:"filename"`
	DataStart  string `json:"data_start"`
	IsSuccess  bool   `json:"is_success"`
}
