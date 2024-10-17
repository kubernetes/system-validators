//go:build linux
// +build linux

/*
Copyright 2016 The Kubernetes Authors.

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

package system

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateCgroupSubsystem(t *testing.T) {
	// hardcoded cgroups v2 subsystems
	pseudoSubsystems := []string{"devices", "freezer"}

	v := &CgroupsValidator{
		Reporter: DefaultReporter,
	}
	for desc, test := range map[string]struct {
		subsystems []string
		cgroupSpec []string
		required   bool
		missing    []string
	}{
		"missing required cgroup subsystem should report missing": {
			cgroupSpec: []string{"system1", "system2"},
			subsystems: []string{"system1"},
			required:   true,
			missing:    []string{"system2"},
		},
		"missing optional cgroup subsystem should report missing": {
			cgroupSpec: []string{"system1", "system2"},
			subsystems: []string{"system1"},
			required:   false,
			missing:    []string{"system2"},
		},
		"extra cgroup subsystems should not report missing": {
			cgroupSpec: []string{"system1", "system2"},
			subsystems: []string{"system1", "system2", "system3"},
			required:   true,
			missing:    nil,
		},
		"subsystems the same with spec should not report missing": {
			cgroupSpec: []string{"system1"},
			subsystems: []string{"system1", "system2"},
			required:   false,
			missing:    nil,
		},
		"missing required cgroup subsystem when pseudo hardcoded subsystems are set": {
			cgroupSpec: []string{"system1", "devices", "freezer"},
			subsystems: pseudoSubsystems,
			required:   true,
			missing:    []string{"system1"},
		},
		"missing optional cgroup subsystem when pseudo hardcoded subsystems are set": {
			cgroupSpec: []string{"system1", "devices", "freezer"},
			subsystems: pseudoSubsystems,
			required:   false,
			missing:    []string{"system1"},
		},
		"extra cgroup subsystems when pseudo hardcoded subsystems are set": {
			cgroupSpec: []string{"system1", "devices", "freezer"},
			subsystems: append(pseudoSubsystems, "system1", "system2"),
			required:   true,
			missing:    nil,
		},
		"matching list of cgroup subsystems including pseudo hardcoded subsystems": {
			cgroupSpec: []string{"system1", "devices", "freezer"},
			subsystems: append(pseudoSubsystems, "system1"),
			required:   false,
			missing:    nil,
		},
	} {
		t.Run(desc, func(t *testing.T) {
			missing := v.validateCgroupSubsystems(test.cgroupSpec, test.subsystems, test.required)
			assert.Equal(t, test.missing, missing, "%q: Expect error not to occur with cgroup", desc)
		})
	}
}

func TestGetUnifiedMountpoint(t *testing.T) {
	tests := map[string]struct {
		mountsFileContent string
		expectedErr       bool
		expectedPath      string
	}{
		"cgroups v2": {
			mountsFileContent: "cgroup2 /sys/fs/cgroup cgroup2 rw,seclabel,nosuid,nodev,noexec,relatime 0 0",
			expectedErr:       false,
			expectedPath:      "/sys/fs/cgroup",
		},
		"cgroups v1": {
			mountsFileContent: "cgroup /sys/fs/cgroup cgroup rw,seclabel,nosuid,nodev,noexec,relatime 0 0",
			expectedErr:       false,
			expectedPath:      "/sys/fs/cgroup",
		},
		"empty file": {
			mountsFileContent: "",
			expectedErr:       true,
			expectedPath:      "",
		},
		"no cgroup mounts": {
			mountsFileContent: `proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,seclabel,nosuid,nodev,noexec,relatime 0 0`,
			expectedErr:  true,
			expectedPath: "",
		},
		"multiple cgroups v1 and v2": {
			mountsFileContent: `cgroup /sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory
cgroup2 /sys/fs/cgroup/unified cgroup2 rw,seclabel,nosuid,nodev,noexec,relatime`,
			expectedErr:  false,
			expectedPath: "/sys/fs/cgroup/unified",
		},
		"cgroups v1 only with multiple subsystems": {
			mountsFileContent: `cgroup /sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory`,
			expectedErr:  false,
			expectedPath: "/sys/fs/cgroup/cpuset", // First valid cgroups v1 path
		},
		"no valid cgroup": {
			mountsFileContent: "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\nsysfs /sys sysfs rw,seclabel,nosuid,nodev,noexec,relatime 0 0",
			expectedErr:       true,
			expectedPath:      "",
		},
	}

	for desc, test := range tests {
		t.Run(desc, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "mounts")
			assert.NoError(t, err, "Unexpected error creating temp file")
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.Write([]byte(test.mountsFileContent))
			assert.NoError(t, err, "Unexpected error writing to temp file")
			tmpFile.Close()

			path, err := getUnifiedMountpoint(tmpFile.Name())

			if test.expectedErr {
				assert.Error(t, err, "Expected error but got none")
			} else {
				assert.NoError(t, err, "Did not expect error but got one: %s", err)
			}

			assert.Equal(t, test.expectedPath, path, "Expected cgroup path mismatch")
		})
	}
}
