package main

import (
	"bytes"
	"context"
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

// sftpgoVirtualFolder links a virtual folder to a single folder in sftpgo, including permissions for a specific user.
type sftpgoVirtualFolder struct {
	Name        string   `json:"name"`
	VirtualPath string   `json:"virtual_path"`
	Permission  []string `json:"-"`
}

// sftpgoBackendFolder is a single virtual folder in sftpgo.
type sftpgoBackendFolder struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description,omitempty"`
	MappedPath  string                  `json:"mapped_path"`
	Filesystem  *sftpgoFolderFilesystem `json:"filesystem"`
}

// sftpgoFolderFilesystem is the filesystem provider for a virtual folder.
// (currently only local filesystem is supported; its value is always 0)
type sftpgoFolderFilesystem struct {
	Provider int `json:"provider"`
}

// sftpgoResponse is the final response to sftpgo after authentication.
type sftpgoResponse struct {
	ID             int32                 `json:"id,omitempty"`
	Status         int                   `json:"status"`                    // 0 = disabled, 1 = enabled
	Username       string                `json:"username"`                  // empty = disallow login
	UID            int32                 `json:"uid,omitempty"`             // 0 = no change
	GID            int32                 `json:"gid,omitempty"`             // 0 = no change
	ExpirationDate int64                 `json:"expiration_date,omitempty"` // 0 = no expiration; unix timestamp in ms
	HomeDir        string                `json:"home_dir,omitempty"`
	VirtualFolders []sftpgoVirtualFolder `json:"virtual_folders,omitempty"` // user-facing folders seen after login
	Permissions    map[string][]string   `json:"permissions,omitempty"`     // permissions for each virtual folder
	Meta           map[string]string     `json:"meta,omitempty"`
	Error          string                `json:"error,omitempty"`
}

// Main functions

// sftpgoSyncFolders is the main function to sync virtual folders with sftpgo REST API.
// It will authenticate towards sftpgo REST API, create/update/delete folders as necessary,
// and logout. It returns a list of folders that could not be processed/synced.
func sftpgoSyncFolders(authLog *log.Entry, desiredFolders []sftpgoBackendFolder) ([]string, error) {
	// Remember all folders that could not be processed/synced
	failedFolders := make([]string, 0)

	// Create a dedicated cookie jar and client (no shared cookies) for sftpgo API
	jar, err := cookiejar.New(nil)
	if err != nil {
		authLog.WithError(err).Error("failed to create cookie jar")
		return []string{}, err
	}

	//nolint:gosec,exhaustruct // intentional: user decides to ignore, defaults acceptable
	client := &http.Client{
		Jar:     jar,
		Timeout: HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !SftpgoCheckCert,
				MinVersion:         tls.VersionTLS12,
			},
		},
	}

	// Create context with timeout derived from request context
	ctx, cancel := context.WithTimeout(context.Background(), HTTPTimeout)
	defer cancel()

	// Authenticate and obtain token
	token, code, err := sftpgoGetLoginToken(ctx, authLog, client)
	if err != nil {
		authLog.WithField("http_code", code).WithError(err).Error("failed to get sftpgo token")
		return []string{}, err
	}
	authLog.Info("sftpgo token obtained, authentication successful")

	// We go through each desiredFolder and check if it exists in sftpgo.
	// if it does not, we create it.
	// If it does, we check for differences and update it if necessary.
	for _, desiredFolder := range desiredFolders {
		name := desiredFolder.Name
		authLog.WithField("folder", name).Trace("checking folder")
		apiErr := sftpgoProcessFolder(ctx, authLog, client, token, desiredFolder)
		if apiErr != nil {
			authLog.WithField("folder", name).WithError(apiErr).
				Error("failed to create/update folder, skipping")
			failedFolders = append(failedFolders, name)
		}
	}

	// Logout
	if apiCode, apiErr := sftpgoLogout(ctx, authLog, client, token); apiErr != nil {
		authLog.WithField("http_code", apiCode).WithError(apiErr).
			Error("failed to logout of sftpgo, proceeding")
	}

	authLog.Info("sftpgo virtual folders synced")
	return failedFolders, nil
}

// sftpgoProcessFolder is processing and taking care of single folders. It will create/update as necessary.
// It returns an error if something went wrong.
func sftpgoProcessFolder(ctx context.Context, authLog *log.Entry, client *http.Client,
	token string, desiredFolder sftpgoBackendFolder) error {
	name := desiredFolder.Name
	authLog.WithField("folder", name).Debug("processing folder")

	folder, code, err := sftpgoGetFolder(ctx, authLog, client, token, name)
	// We consider 200 and 404 to be fine (200 = folder exists, 404 = folder does not exist)
	if code == http.StatusOK || code == http.StatusNotFound {
		// soft-fail. don't error out.
		err = nil
	}
	// Check for error
	if err != nil {
		authLog.WithField("folder", name).WithField("http_code", code).Info("failed to get folder details")
		return err
	}

	// Create the folder if it does not exist
	if code == http.StatusNotFound {
		// Folder does not exist, create it
		if apiErr := sftpgoCreateFolder(ctx, authLog, client, token, desiredFolder); apiErr != nil {
			authLog.WithField("folder", name).WithField("http_code", code).Info("failed to create folder")
			return apiErr
		}
	}

	// Folder exists, check for differences
	if code == http.StatusOK {
		// Compare "folder" and "desiredFolder" structs recursively
		if !folderStructsEqual(authLog, folder, desiredFolder) {
			authLog.WithField("folder", name).Info("folder differs from desired state, updating...")
			// Differences found, delete and recreate folder
			if apiErr := sftpgoUpdateFolder(ctx, authLog, client, token, desiredFolder); apiErr != nil {
				authLog.WithField("folder", name).WithError(apiErr).Error("failed to update folder")
				return apiErr
			}
		}
	}

	return nil
}

// sftpgoGetLoginToken authenticates towards sftpgo REST API and retrieves a login token.
// It returns the token, HTTP status code, and error if any.
func sftpgoGetLoginToken(ctx context.Context, authLog *log.Entry, client *http.Client) (string, int, error) {
	apiURL := fmt.Sprintf("%s/api/v2/token", SftpgoAPIURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", http.StatusUnprocessableEntity, err
	}

	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(SftpgoAPIUser, SftpgoAPIPass)

	resp, err := client.Do(req)
	if err != nil {
		return "", http.StatusUnprocessableEntity, err
	}
	defer closeIOBody(&resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			authLog.WithError(readErr).Error("sftpgo token request: failed to read error response body")
		}
		return "", resp.StatusCode, fmt.Errorf("token request failed: %s", string(body))
	}

	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
	}
	if jsonErr := json.NewDecoder(resp.Body).Decode(&data); jsonErr != nil {
		return "", resp.StatusCode, jsonErr
	}
	authLog.WithField("expires_at", data.ExpiresAt).Trace("sftpgo token obtained")

	return data.AccessToken, resp.StatusCode, nil
}

// sftpgoLogout logs out of sftpgo REST API. It returns the HTTP status code and error if any.
// This will invalidate the token, so it cannot longer be used.
func sftpgoLogout(ctx context.Context, authLog *log.Entry, client *http.Client, token string) (int, error) {
	apiURL := fmt.Sprintf("%s/api/v2/logout", SftpgoAPIURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return http.StatusUnprocessableEntity, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return http.StatusUnprocessableEntity, err
	}
	defer closeIOBody(&resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, fmt.Errorf("logout failed: %s", string(body))
	}

	authLog.Debug("sftpgo logout completed")
	return resp.StatusCode, nil
}

// sftpgoCreateFolder creates a virtual folder in sftpgo REST API. It returns an error if any.
func sftpgoCreateFolder(ctx context.Context, authLog *log.Entry, client *http.Client,
	token string, folder sftpgoBackendFolder) error {
	payload, err := json.Marshal(folder)
	if err != nil {
		authLog.WithError(err).Error("sftpgo create folder: failed to marshal folder payload")
		return err
	}

	apiURL := fmt.Sprintf("%s/api/v2/folders", SftpgoAPIURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer closeIOBody(&resp.Body)

	if resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create folder failed: %s", string(body))
	}

	authLog.WithField("name", folder.Name).Info("sftpgo folder created successfully")
	return nil
}

// sftpgoGetFolder retrieves a specific virtual folder by name from sftpgo REST API.
// It returns the folder, HTTP status code, and error if any. The folder is returned as a struct.
// HTTP Error 404 means the folder does not exist.
func sftpgoGetFolder(ctx context.Context, authLog *log.Entry, client *http.Client,
	token, name string) (sftpgoBackendFolder, int, error) {
	url := fmt.Sprintf("%s/api/v2/folders/%s", SftpgoAPIURL, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return sftpgoBackendFolder{}, http.StatusUnprocessableEntity, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return sftpgoBackendFolder{}, http.StatusUnprocessableEntity, err
	}
	defer closeIOBody(&resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return sftpgoBackendFolder{}, resp.StatusCode, fmt.Errorf("get folder failed: %s", string(body))
	}

	body, _ := io.ReadAll(resp.Body)
	authLog.WithField("folder", string(body)).Info("fetched folder details")

	var folder sftpgoBackendFolder
	if jsonErr := json.Unmarshal(body, &folder); jsonErr != nil {
		authLog.WithError(jsonErr).Error("failed to unmarshal folder details")
		return sftpgoBackendFolder{}, http.StatusUnprocessableEntity, jsonErr
	}
	return folder, http.StatusOK, nil
}

// sftpgoUpdateFolder updates a virtual folder via sftpgo REST API with the data provided.
// It returns an error, if any.
func sftpgoUpdateFolder(ctx context.Context, authLog *log.Entry, client *http.Client,
	token string, folder sftpgoBackendFolder) error {
	payload, err := json.Marshal(folder)
	if err != nil {
		authLog.WithError(err).Error("failed to marshal folder for update")
		return err
	}

	url := fmt.Sprintf("%s/api/v2/folders/%s", SftpgoAPIURL, folder.Name)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer closeIOBody(&resp.Body)

	if resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update folder failed: %s", string(body))
	}

	authLog.WithField("name", folder.Name).Info("sftpgo folder updated successfully")
	return nil
}

// --- Helper functions

// folderStructsEqual compares two sftpgoBackendFolder structs recursively.
func folderStructsEqual(authLog *log.Entry, a sftpgoBackendFolder, b sftpgoBackendFolder) bool {
	authLog.WithField("a", fmt.Sprintf("%v", a)).WithField("b", fmt.Sprintf("%v", b)).Trace("comparing folders")

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
