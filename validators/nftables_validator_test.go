//go:build linux
// +build linux

/*
Copyright 2026 The Kubernetes Authors.

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
	"errors"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testReporter struct {
	reportedKey        string
	reportedValue      string
	reportedResultType ValidationResultType
}

func (r *testReporter) Report(key, value string, resultType ValidationResultType) error {
	r.reportedKey = key
	r.reportedValue = value
	r.reportedResultType = resultType
	return nil
}

func TestNftablesValidator(t *testing.T) {
	tests := []struct {
		name           string
		nftablesSpec   bool
		sysfsModuleDir string
		fakeCheck      func() (bool, error)
		expectedWarns  int
		expectedErrs   int
		expectedKey    string
		expectedVal    string
		expectedResult ValidationResultType
	}{
		{
			name:           "Nftables not requested in spec",
			nftablesSpec:   false,
			sysfsModuleDir: "/nonexistent_directory_for_nftables_test",
			fakeCheck: func() (bool, error) {
				return true, nil
			},
			expectedWarns: 0,
			expectedErrs:  0,
		},
		{
			name:           "Nftables enabled and supported",
			nftablesSpec:   true,
			sysfsModuleDir: "/nonexistent_directory_for_nftables_test",
			fakeCheck: func() (bool, error) {
				return true, nil
			},
			expectedWarns:  0,
			expectedErrs:   0,
			expectedKey:    "NFTABLES",
			expectedVal:    "enabled",
			expectedResult: good,
		},
		{
			name:           "Nftables disabled",
			nftablesSpec:   true,
			sysfsModuleDir: "/nonexistent_directory_for_nftables_test",
			fakeCheck: func() (bool, error) {
				return false, nil
			},
			expectedWarns:  0,
			expectedErrs:   1,
			expectedKey:    "NFTABLES",
			expectedVal:    "disabled",
			expectedResult: bad,
		},
		{
			name:           "Permission denied / EPERM (requires root)",
			nftablesSpec:   true,
			sysfsModuleDir: "/nonexistent_directory_for_nftables_test",
			fakeCheck: func() (bool, error) {
				return false, syscall.EPERM
			},
			expectedWarns:  1,
			expectedErrs:   0,
			expectedKey:    "NFTABLES",
			expectedVal:    "unknown (requires root)",
			expectedResult: warn,
		},
		{
			name:           "Permission denied / EACCES (requires root)",
			nftablesSpec:   true,
			sysfsModuleDir: "/nonexistent_directory_for_nftables_test",
			fakeCheck: func() (bool, error) {
				return false, syscall.EACCES
			},
			expectedWarns:  1,
			expectedErrs:   0,
			expectedKey:    "NFTABLES",
			expectedVal:    "unknown (requires root)",
			expectedResult: warn,
		},
		{
			name:           "Generic netlink error",
			nftablesSpec:   true,
			sysfsModuleDir: "/nonexistent_directory_for_nftables_test",
			fakeCheck: func() (bool, error) {
				return false, errors.New("socket failure")
			},
			expectedWarns:  0,
			expectedErrs:   1,
			expectedKey:    "NFTABLES",
			expectedVal:    "error",
			expectedResult: bad,
		},
		{
			name:           "Nftables module loaded via sysfs fast-path",
			nftablesSpec:   true,
			sysfsModuleDir: t.TempDir(),
			fakeCheck: func() (bool, error) {
				return false, errors.New("netlink query shouldn't be called")
			},
			expectedWarns:  0,
			expectedErrs:   0,
			expectedKey:    "NFTABLES",
			expectedVal:    "enabled",
			expectedResult: good,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.sysfsModuleDir != "" {
				origSysfsModuleDir := sysfsModuleDir
				sysfsModuleDir = tc.sysfsModuleDir
				defer func() { sysfsModuleDir = origSysfsModuleDir }()
			}

			reporter := &testReporter{}
			v := &nftablesValidator{
				reporter:      reporter,
				nftablesCheck: tc.fakeCheck,
			}

			spec := SysSpec{
				Nftables: tc.nftablesSpec,
			}

			warns, errs := v.Validate(spec)

			assert.Len(t, warns, tc.expectedWarns)
			assert.Len(t, errs, tc.expectedErrs)

			if tc.nftablesSpec {
				assert.Equal(t, tc.expectedKey, reporter.reportedKey)
				assert.Equal(t, tc.expectedVal, reporter.reportedValue)
				assert.Equal(t, tc.expectedResult, reporter.reportedResultType)
			}
		})
	}
}
