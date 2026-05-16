package main

import (
	"errors"
	"math"
	"os"
	"strconv"
	"strings"
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
	if _, err := os.Stat(config.Qnap.PasswdFile); os.IsNotExist(err) {
		return false
	}
	return true
}

// getPasswdFileAllUsers parses the passwd file and returns all users found
func getPasswdFileAllUsers() ([]passwdUser, error) {
	logger.Debug("parsing qnap passwd file")

	data, err := os.ReadFile(config.Qnap.PasswdFile)
	if err != nil {
		logger.Errorw("failed to read qnap passwd file", "error", err)
		return []passwdUser{}, err
	}

	var users []passwdUser
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		line = strings.TrimSuffix(line, "\r")
		// logger.Logw(TraceLevel, "parsed qnap passwd file line", "line", line)
		line := strings.Split(line, ":")

		// Parse current line
		username := line[0]
		homeDir := line[5]

		uid, uidErr := strconv.Atoi(line[2])
		if uidErr != nil {
			logger.Errorw("failed to parse qnap passwd: uid invalid, skipping", "error", uidErr)
			continue
		}
		if uid < 0 || uid > math.MaxInt32 {
			logger.Error("failed to parse qnap passwd: uid out of int32 range, skipping")
			continue
		}

		gid, gidErr := strconv.Atoi(line[3])
		if gidErr != nil {
			logger.Errorw("failed to parse qnap passwd: gid invalid, skipping", "error", gidErr)
			continue
		}
		if gid < 0 || gid > math.MaxInt32 {
			logger.Error("failed to parse qnap passwd: gid out of int32 range, skipping")
			continue
		}

		logger.Logw(TraceLevel, "parsed qnap passwd file line",
			"username", username,
			"uid", uid,
			"gid", gid,
			"homeDir", homeDir,
		)

		// check if all fields are present
		if username == "" || homeDir == "" {
			logger.Error("failed to parse qnap passwd file: line invalid, skipping")
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

	logger.Logw(TraceLevel, "parsed qnap passwd file", "users", len(users))

	return users, nil
}

// getPasswdFileUser returns the user entry for the given username from the passwd file
func getPasswdFileUser(username string) (passwdUser, error) {
	users, err := getPasswdFileAllUsers()
	if err != nil {
		logger.Errorw("failed to get user data from passwd file", "error", err)
		return passwdUser{}, err
	}

	// Find the user in the passwd file
	for _, user := range users {
		if user.Username == username {
			logger.Logw(TraceLevel, "found user in passwd file", "username", username)
			return user, nil
		}
	}

	err = errors.New("user not found in passwd file")
	return passwdUser{}, err
}
