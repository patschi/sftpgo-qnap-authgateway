package main

import (
	"errors"
	"math"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Example of QNAP passwd file:
// nasadmin:x:1000:100:Linux User,,,:/share/homes/nasadmin:/bin/sh
// user:x:1001:100:Linux User,,,:/share/homes/user:/bin/sh

// passwdUser represents a single user entry in the passwd file
type passwdUser struct {
	Username string
	UID      int32
	GID      int32
	HomeDir  string
}

// checkPasswdFileExistence checks if the passwd file has been mounted within the container at /nas_passwd
func checkPasswdFileExistence() bool {
	if _, err := os.Stat(QnapPasswdFile); os.IsNotExist(err) {
		return false
	}
	return true
}

// getPasswdFileAllUsers parses the passwd file and returns all users found
func getPasswdFileAllUsers() ([]passwdUser, error) {
	log.Debug("parsing qnap passwd file")

	data, err := os.ReadFile(QnapPasswdFile)
	if err != nil {
		log.WithError(err).Error("failed to read qnap passwd file: line")
		return []passwdUser{}, err
	}

	var users []passwdUser
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		line = strings.TrimSuffix(line, "\r")
		// log.WithField("line", line).Trace("parsed qnap passwd file line")
		line := strings.Split(line, ":")

		// Parse current line
		username := line[0]
		homeDir := line[5]

		uid, uidInt := strconv.Atoi(line[2])
		if uidInt != nil {
			log.WithError(uidInt).Error("failed to parse qnap passwd: uid invalid, skipping")
			continue
		}
		if uid < 0 || uid > math.MaxInt32 {
			log.Error("failed to parse qnap passwd: uid out of int32 range, skipping")
			continue
		}

		gid, gidInt := strconv.Atoi(line[3])
		if gidInt != nil {
			log.WithError(gidInt).Error("failed to parse qnap passwd: gid invalid, skipping")
			continue
		}
		if gid < 0 || gid > math.MaxInt32 {
			log.Error("failed to parse qnap passwd: gid out of int32 range, skipping")
			continue
		}

		log.WithFields(log.Fields{
			"username": username,
			"uid":      uid,
			"gid":      gid,
			"homeDir":  homeDir,
		}).Trace("parsed qnap passwd file line")

		// check if all fields are present
		if username == "" || homeDir == "" {
			log.Error("failed to parse qnap passwd file: line invalid, skipping")
			continue
		}

		// Add user to the list
		users = append(users, passwdUser{
			Username: username,
			UID:      int32(uid), //nolint:gosec // integer overflow not possible due to checks above
			GID:      int32(gid), //nolint:gosec // integer overflow not possible due to checks above
			HomeDir:  homeDir,
		})
	}

	log.WithFields(log.Fields{
		"users": len(users),
	}).Trace("parsed qnap passwd file")

	return users, nil
}

// getPasswdFileUser returns the user entry for the given username from the passwd file
func getPasswdFileUser(username string) (passwdUser, error) {
	users, err := getPasswdFileAllUsers()
	if err != nil {
		log.WithError(err).Error("failed to get user data from passwd file")
		return passwdUser{}, err
	}

	// Find the user in the passwd file
	for _, user := range users {
		if user.Username == username {
			log.WithField("username", username).Trace("found user in passwd file")
			return user, nil
		}
	}

	err = errors.New("user not found in passwd file")
	return passwdUser{}, err
}
