package main

// -----------------------------
// Types for incoming request and SFTPGo response
// -----------------------------

// sftpgoVirtualFolder links a virtual folder to a single folder in sftpgo
type sftpgoVirtualFolder struct {
	Name        string `json:"name"`
	VirtualPath string `json:"virtual_path"`
}

// sftpgoFolder is a single virtual folder in sftpgo
type sftpgoFolder struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description,omitempty"`
	MappedPath  string                  `json:"mapped_path"`
	Filesystem  *sftpgoFolderFilesystem `json:"filesystem"`
}

// sftpgoFolderFilesystem is the filesystem provider for a virtual folder
// (currently only local filesystem is supported; its value is always 0)
type sftpgoFolderFilesystem struct {
	Provider int `json:"provider"`
}

// sftpgoResponse is the final response to sftpgo after authentication
type sftpgoResponse struct {
	Id             int32                 `json:"id,omitempty"`
	Status         int                   `json:"status"`                    // 0 = disabled, 1 = enabled
	Username       string                `json:"username"`                  // empty = disallow login
	Uid            int32                 `json:"uid,omitempty"`             // 0 = no change
	Gid            int32                 `json:"gid,omitempty"`             // 0 = no change
	ExpirationDate int64                 `json:"expiration_date,omitempty"` // 0 = no expiration; unix timestamp in ms
	HomeDir        string                `json:"home_dir,omitempty"`
	VirtualFolders []sftpgoVirtualFolder `json:"virtual_folders,omitempty"` // user-facing folders seen after login
	Permissions    map[string][]string   `json:"permissions,omitempty"`     // permissions for each virtual folder
	Meta           map[string]string     `json:"meta,omitempty"`
	Error          string                `json:"error,omitempty"`
}
