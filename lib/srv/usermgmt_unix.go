//go:build !windows
// +build !windows

/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package srv

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

/*
#include <sys/types.h>
#include <pwd.h>
*/
import "C"

type UnixHostUsersBackend struct {
	sudoersPath string
}

var _ HostUsersBackend = &UnixHostUsersBackend{}

// Lookup implements host user information lookup
func (*UnixHostUsersBackend) Lookup(username string) (*user.User, error) {
	return user.Lookup(username)
}

// UserGIDs returns the list of group IDs for a user
func (*UnixHostUsersBackend) UserGIDs(u *user.User) ([]string, error) {
	return u.GroupIds()
}

// LookupGroup host group information lookup
func (*UnixHostUsersBackend) LookupGroup(name string) (*user.Group, error) {
	return user.LookupGroup(name)
}

// GetAllUsers returns a full list of users present on a system
func (*UnixHostUsersBackend) GetAllUsers() ([]string, error) {
	var result *C.struct_passwd
	names := []string{}
	// getpwent(3), posix compatible way to iterate /etc/passwd.
	// Provided as os/user does not provide any iteration helpers
	C.setpwent()
	defer C.endpwent()
	for {
		result = C.getpwent()
		if result == nil {
			break
		}
		name := result.pw_name
		names = append(names, C.GoString(name))
	}
	if len(names) == 0 {
		return nil, trace.NotFound("failed to find any /etc/passwd entries")
	}
	return names, nil
}

// CreateGroup creates a group on a host
func (*UnixHostUsersBackend) CreateGroup(name string) error {
	_, err := utils.GroupAdd(name)
	return trace.Wrap(err)
}

// CreateUser creates a user on a host
func (*UnixHostUsersBackend) CreateUser(name string, groups []string) error {
	_, err := utils.UserAdd(name, groups)
	return trace.Wrap(err)
}

// CreateUser creates a user on a host
func (*UnixHostUsersBackend) DeleteUser(name string) error {
	code, err := utils.UserDel(name)
	if code == utils.UserLoggedInExit {
		return trace.Wrap(ErrUserLoggedIn)
	}
	return trace.Wrap(err)
}

func (*UnixHostUsersBackend) TestSudoersFile(contents []byte) error {
	code, err := utils.TestSudoersFile(contents)
	if err != nil {
		if code != 0 {
			return trace.Errorf("visudo: invalid sudoers file")
		}
		return trace.Wrap(err)
	}
	return nil
}

func (u *UnixHostUsersBackend) WriteSudoersFile(username string, contents []byte) error {
	sudoersFilePath := filepath.Join(u.sudoersPath, fmt.Sprintf("%s-%s", "teleport", username))
	err := os.WriteFile(sudoersFilePath, contents, 0440)
	return trace.Wrap(err)
}

func (u *UnixHostUsersBackend) RemoveSudoersFile(username string) error {
	sudoersFilePath := filepath.Join(u.sudoersPath, fmt.Sprintf("%s-%s", "teleport", username))
	if _, err := os.Stat(sudoersFilePath); os.IsNotExist(err) {
		log.Debugf("User %q, did not have sudoers file as it did not exist at path %q",
			username,
			sudoersFilePath)
		return nil
	}
	return trace.Wrap(os.Remove(sudoersFilePath))
}
