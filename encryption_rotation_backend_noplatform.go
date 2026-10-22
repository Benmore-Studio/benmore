//go:build !cli && !platform

package main

import "errors"

func validateRotationJournalSnapshot(s appRotationBackendSnapshot) error {
	if s.Kind == appRotationPlatformVault {
		return errors.New("platform rotation is unsupported in this build")
	}
	return nil
}
