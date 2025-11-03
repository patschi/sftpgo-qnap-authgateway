package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
)

// -----------------------------
// QNAP helpers
// Each uses ctx; the client is per-request and has its own cookiejar.
// -----------------------------

var errAuthFailed = errors.New("authentication failed")

// qnapLogin authenticates a user with a QNAP device and returns the session ID if login is successful or an error otherwise.
func qnapLogin(ctx context.Context, client *http.Client, baseURL string, auth authRequest) (string, error) {
	user := auth.Username

	loginURL := fmt.Sprintf("%s/cgi-bin/authLogin.cgi", baseURL)

	// build request params
	params := url.Values{}
	params.Set("user", user)
	params.Set("serviceKey", "1")
	params.Set("service", "1")

	// build request body in byte buffer
	// form-encode manually into a wipeable [] byte buffer
	var buf bytes.Buffer
	buf.WriteString(params.Encode())
	buf.WriteString("&pwd=")
	err := auth.Password.WriteBase64To(&buf)
	if err != nil {
		return "", err
	}

	log.WithFields(log.Fields{"user": user}).Debug("calling qnap auth endpoint")
	defer WipeBuffer(&buf) // wipe buffer from memory
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(buf.Bytes()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		// network/timeout errors
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.WithError(err).Error("login: failed to close response body")
		}
	}(resp.Body)
	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// treat non-200 as auth failure for credential issues or QNAP errors differently
		// we attempt to parse body to determine, but default to auth failed
		return "", fmt.Errorf("login HTTP %d - body: %s", resp.StatusCode, string(bodyBytes))
	}

	reqBody := strings.TrimSpace(string(bodyBytes))
	log.WithFields(log.Fields{"user": user, "response": reqBody}).Trace("qnap login api response received")

	// Parse XML response
	var xr qnapLoginResp
	if err := xml.Unmarshal(bodyBytes, &xr); err != nil {
		log.WithField("xml", reqBody).WithError(err).Warn("failed to parse xml login response")
		return "", fmt.Errorf("unable to parse login response")
	}
	log.WithField("response", fmt.Sprintf("%+v", xr)).Trace("parsed qnap api response struct")

	// check if login was successful
	if xr.AuthSid != "" && xr.AuthPassed == "1" {
		log.WithField("user", user).Debug("qnap login successful")
		return xr.AuthSid, nil

	} else if xr.AuthSid != "" || xr.AuthPassed != "1" {
		log.WithField("user", user).Warn("qnap login failed")
		return "", errAuthFailed
	}

	return "", fmt.Errorf("unknown error or unexpected response from qnap api")
}

// qnapLogout logs out a user from a QNAP NAS via the authLogout API endpoint.
// It takes a context and HTTP client as parameters.
// Returns an error in case of failure.
func qnapLogout(ctx context.Context, client *http.Client, baseURL string, sid string) error {
	log.WithField("sid", sid).Trace("Destroying session on QNAP API")

	logoutURL := fmt.Sprintf("%s/cgi-bin/authLogout.cgi", baseURL)

	params := url.Values{}
	params.Set("sid", sid)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, logoutURL, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.WithError(err).Error("logout: failed to close response body")
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("logout failed HTTP %d: %s", resp.StatusCode, string(body))
	}

	log.WithField("sid", sid).Trace("User session destroyed on QNAP API")
	return nil
}

// qnapGetShares retrieves a list of shared folders from a QNAP NAS via the get_tree API endpoint.
// It takes a context, HTTP client, NAS base URL, session ID, and user identifier as parameters.
// Returns a slice of qnapShareNode containing share details or an error in case of failure.
func qnapGetShares(ctx context.Context, client *http.Client, baseURL string, sid string, user string) ([]qnapShareNode, error) {

	sharesUrl := fmt.Sprintf("%s/cgi-bin/filemanager/utilRequest.cgi", baseURL)
	params := url.Values{}
	params.Set("func", "get_tree")
	params.Set("node", "share_root")
	params.Set("is_iso", "0")
	params.Set("check_acl", "1")
	params.Set("vol", "0")
	params.Set("sid", sid)

	log.WithField("user", user).Debugf("calling qnap get_tree endpoint")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sharesUrl, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.WithField("user", user).WithError(err).Error("getShares: failed to close response body")
		}
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	log.WithFields(log.Fields{
		"user": user,
		"body": strings.TrimSpace(string(body)),
	}).Tracef("qnap shares api response received")

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get_tree HTTP %d - body: %s", resp.StatusCode, string(body))
	}

	// parse as array
	var arr []qnapShareNode
	if err := json.Unmarshal(body, &arr); err != nil {
		return nil, fmt.Errorf("unable to parse get_tree response: %s", err)
	}
	log.WithFields(log.Fields{
		"user":     user,
		"response": fmt.Sprintf("%+v", arr),
	}).Trace("parsed qnap get_tree response")

	return arr, nil
}
