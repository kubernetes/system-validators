//go:build !linux
// +build !linux

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

var _ Validator = &nftablesValidator{}

// nftablesValidator stub for non-Linux OS.
type nftablesValidator struct {
	reporter Reporter
}

// Name is part of the system.Validator interface.
func (n *nftablesValidator) Name() string {
	return "nftables"
}

// Validate is part of the system.Validator interface.
func (n *nftablesValidator) Validate(spec SysSpec) ([]error, []error) {
	return nil, nil
}
