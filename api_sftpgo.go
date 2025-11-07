package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"

	log "github.com/sirupsen/logrus"
)

// --------------------------
// Types for incoming request and sftpgo response
// --------------------------

// sftpgoVirtualFolder links a virtual folder to a single folder in sftpgo, including its permissions for specific user.
type sftpgoVirtualFolder struct {
	Name        string   `json:"name"`
	VirtualPath string   `json:"virtual_path"`
	Permission  []string `json:"-"`
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

// Main functions

// sftpgoSyncFolders is the main function to sync virtual folders with sftpgo REST API
// It will authenticate towards sftpgo REST API, create/update/delete folders as necessary,
// and logout. It returns a list of folders that could not be processed/synced.
func sftpgoSyncFolders(log *log.Entry, desiredFolders []sftpgoFolder) ([]string, error) {
	// Remember all folders that could not be processed/synced
	failedFolders := make([]string, 0)

	// Create a dedicated cookie jar and client (no shared cookies) for sftpgo API
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.WithError(err).Error("failed to create cookie jar")
	}
	client := &http.Client{
		Jar:     jar,
		Timeout: HttpTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !SftpgoCheckCert,
				MinVersion:         tls.VersionTLS12,
			},
		},
	}

	// Authenticate and obtain token
	token, code, err := sftpgoGetLoginToken(log, client)
	if err != nil {
		log.WithField("http_code", code).WithError(err).Error("failed to get sftpgo token")
		return []string{}, err
	}

	// We go through each desiredFolder and check if it exists in sftpgo.
	// if it does not, we create it.
	// If it does, we check for differences and update it if necessary.
	for _, desiredFolder := range desiredFolders {
		name := desiredFolder.Name
		log.WithField("folder", name).Debug("checking folder")
		err := sftpgoProcessFolder(log, client, token, desiredFolder)
		if err != nil {
			log.WithField("folder", name).WithError(err).Error("failed to create/update folder")
			failedFolders = append(failedFolders, name)
		}
	}

	// Logout
	if code, err := sftpgoLogout(log, client, token); err != nil {
		log.WithField("http_code", code).WithError(err).Error("failed to logout of sftpgo, proceeding...")
	}

	return failedFolders, nil
}

// sftpgoProcessFolder is processing and taking care of single folders. It will create/update as necessary.
// It returns an error if something went wrong.
func sftpgoProcessFolder(log *log.Entry, client *http.Client, token string, desiredFolder sftpgoFolder) error {
	name := desiredFolder.Name
	log.WithField("folder", name).Debug("processing folder")

	folder, code, err := sftpgoGetFolder(log, client, token, name)
	// We consider 200 and 404 to be fine (200 = folder exists, 404 = folder does not exist)
	if code == 200 || code == 404 {
		// soft-fail. don't error out.
		err = nil
	}
	// Check for error
	if err != nil {
		log.WithField("folder", name).WithField("http_code", code).Info("failed to get folder details")
		return err
	}

	// Create the folder if it does not exist
	if code == 404 {
		// Folder does not exist, create it
		if err := sftpgoCreateFolder(log, client, token, desiredFolder); err != nil {
			log.WithField("folder", name).WithField("http_code", code).Info("failed to create folder")
			return err
		}
	}

	// Folder exists, check for differences
	if code == 200 {
		// Compare "folder" and "desiredFolder" structs recursively
		if !folderStructsEqual(folder, desiredFolder) {
			log.WithField("folder", name).Info("folder differs from desired state, updating...")
			// Differences found, delete and recreate folder
			if err := sftpgoUpdateFolder(log, client, token, desiredFolder); err != nil {
				log.WithField("folder", name).WithError(err).Error("failed to update folder")
				return err
			}
		}
	}

	return nil
}

// sftpgoGetLoginToken authenticates towards sftpgo REST API and retrieves a login token.
// It returns the token, HTTP status code, and error if any.
func sftpgoGetLoginToken(log *log.Entry, client *http.Client) (string, int, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v2/token", SftpgoApiUrl), nil)
	if err != nil {
		return "", 400, err
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(SftpgoApiUser, SftpgoApiPass)

	resp, err := client.Do(req)
	if err != nil {
		return "", 400, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.WithError(err).Error("sftpgo token request: failed to close response body")
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", resp.StatusCode, fmt.Errorf("token request failed: %s", string(body))
	}

	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", resp.StatusCode, err
	}
	log.WithField("expires_at", data.ExpiresAt).Trace("sftpgo token obtained")

	return data.AccessToken, resp.StatusCode, nil
}

// sftpgoLogout logs out of sftpgo REST API. It returns the HTTP status code and error if any.
// This will invalidate the token, so it can not longer be used.
func sftpgoLogout(log *log.Entry, client *http.Client, token string) (int, error) {
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v2/logout", SftpgoApiUrl), nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return 400, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.WithError(err).Error("sftpgo logout: failed to close response body")
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, fmt.Errorf("logout failed: %s", string(body))
	}

	log.Info("sftpgo logout completed")
	return resp.StatusCode, nil
}

// sftpgoCreateFolder creates a virtual folder in sftpgo REST API. It returns an error if any.
func sftpgoCreateFolder(log *log.Entry, client *http.Client, token string, folder sftpgoFolder) error {
	payload, _ := json.Marshal(folder)

	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/v2/folders", SftpgoApiUrl), bytes.NewBuffer(payload))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.WithError(err).Error("sftpgo create folder: failed to close response body")
		}
	}(resp.Body)

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create folder failed: %s", string(body))
	}

	log.WithField("name", folder.Name).Info("Folder created successfully")
	return nil
}

// sftpgoGetFolder retrieves a specific virtual folder by name from sftpgo REST API.
// It returns the folder, HTTP status code, and error if any. The folder is returned as a struct.
// HTTP Error 404 means folder does not exist.
func sftpgoGetFolder(log *log.Entry, client *http.Client, token, name string) (sftpgoFolder, int, error) {
	url := fmt.Sprintf("%s/api/v2/folders/%s", SftpgoApiUrl, name)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return sftpgoFolder{}, 400, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.WithError(err).Error("sftpgo get folder: failed to close response body")
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return sftpgoFolder{}, resp.StatusCode, fmt.Errorf("get folder failed: %s", string(body))
	}

	body, _ := io.ReadAll(resp.Body)
	log.WithField("folder", string(body)).Info("fetched folder details")

	var folder sftpgoFolder
	if err := json.Unmarshal(body, &folder); err != nil {
		log.WithError(err).Error("failed to unmarshal folder details")
		return sftpgoFolder{}, 400, err
	}
	return folder, 200, nil
}

// sftpgoUpdateFolder updates a virtual folder in sftpgo REST API with struct provided. It returns an error if any.
func sftpgoUpdateFolder(log *log.Entry, client *http.Client, token string, folder sftpgoFolder) error {
	payload, _ := json.Marshal(folder)

	url := fmt.Sprintf("%s/api/v2/folders/%s", SftpgoApiUrl, folder.Name)
	req, _ := http.NewRequest("PUT", url, bytes.NewBuffer(payload))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.WithError(err).Error("sftpgo update folder: failed to close response body")
		}
	}(resp.Body)

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update folder failed: %s", string(body))
	}

	log.WithField("name", folder.Name).Info("sftpgo folder updated successfully")
	return nil
}

// --- Helper functions

// folderStructsEqual compares two sftpgoFolder structs recursively.
func folderStructsEqual(a sftpgoFolder, b sftpgoFolder) bool {
	log.WithField("a", fmt.Sprintf("%v", a)).WithField("b", fmt.Sprintf("%v", b)).Trace("comparing folders")

	if a.Name != b.Name || a.Description != b.Description || a.MappedPath != b.MappedPath {
		return false
	}

	// Handle nil pointer comparisons for Filesystem
	if a.Filesystem == nil && b.Filesystem == nil {
		return true
	}
	if a.Filesystem == nil || b.Filesystem == nil {
		return false
	}

	return a.Filesystem.Provider == b.Filesystem.Provider
}
