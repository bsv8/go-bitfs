package masterseed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// CreateSeedFileOptions controls atomic path publishing.
type CreateSeedFileOptions struct {
	Overwrite bool
	Sync      bool
}

// CreateSeedFile writes a seed beside the target, then publishes it. The
// default is no-overwrite; an incomplete seed is never left at seedPath.
func CreateSeedFile(ctx context.Context, sourcePath, seedPath string, options CreateSeedFileOptions) (info SeedInfo, err error) {
	if sourcePath == "" || seedPath == "" {
		return SeedInfo{}, invalidArgument("source and seed paths are required")
	}
	sourceStat, statErr := os.Stat(sourcePath)
	if statErr != nil {
		return SeedInfo{}, errorWithPath(ReadFailed, "stat source", sourcePath, statErr)
	}
	targetStat, targetErr := os.Stat(seedPath)
	if targetErr == nil {
		if os.SameFile(sourceStat, targetStat) {
			return SeedInfo{}, invalidArgument("source and seed paths refer to the same file")
		}
		if !options.Overwrite {
			return SeedInfo{}, &Error{Code: TargetExists, Message: "seed target already exists", Path: seedPath}
		}
	} else if !errors.Is(targetErr, os.ErrNotExist) {
		return SeedInfo{}, errorWithPath(WriteFailed, "stat target", seedPath, targetErr)
	}

	source, openErr := os.Open(sourcePath)
	if openErr != nil {
		return SeedInfo{}, errorWithPath(ReadFailed, "open source", sourcePath, openErr)
	}
	defer func() {
		if closeErr := source.Close(); err == nil && closeErr != nil {
			err = errorWithPath(ReadFailed, "close source", sourcePath, closeErr)
		}
	}()

	directory := filepath.Dir(seedPath)
	base := filepath.Base(seedPath)
	temporary, tempErr := os.CreateTemp(directory, "."+base+".masterseed-*")
	if tempErr != nil {
		return SeedInfo{}, errorWithPath(WriteFailed, "create temporary seed", seedPath, tempErr)
	}
	temporaryPath := temporary.Name()
	published := false
	temporaryClosed := false
	defer func() {
		if !temporaryClosed {
			_ = temporary.Close()
		}
	}()
	defer func() {
		if !published {
			_ = os.Remove(temporaryPath)
		}
	}()

	info, err = CreateSeed(ctx, source, temporary)
	if err != nil {
		return info, err
	}
	if options.Sync {
		if syncErr := temporary.Sync(); syncErr != nil {
			return info, errorWithPath(WriteFailed, "sync temporary seed", seedPath, syncErr)
		}
	}
	if closeErr := temporary.Close(); closeErr != nil {
		return info, errorWithPath(WriteFailed, "close temporary seed", seedPath, closeErr)
	}
	temporaryClosed = true

	if options.Overwrite {
		if renameErr := os.Rename(temporaryPath, seedPath); renameErr != nil {
			return info, errorWithPath(WriteFailed, "publish seed", seedPath, renameErr)
		}
	} else {
		// A hard-link publish is atomic and fails instead of replacing a target
		// that appeared after the initial existence check.
		if linkErr := os.Link(temporaryPath, seedPath); linkErr != nil {
			if errors.Is(linkErr, os.ErrExist) {
				return info, &Error{Code: TargetExists, Message: "seed target already exists", Path: seedPath, Cause: linkErr}
			}
			return info, errorWithPath(WriteFailed, "publish seed", seedPath, linkErr)
		}
		if removeErr := os.Remove(temporaryPath); removeErr != nil {
			return info, errorWithPath(WriteFailed, "remove temporary seed", seedPath, removeErr)
		}
	}
	published = true
	return info, nil
}

// VerifySourceFile verifies the seed hash before reopening the seed for the
// complete source pass, so untrusted seed contents are not used unchecked.
func VerifySourceFile(ctx context.Context, sourcePath, seedPath string, expected Digest) (VerifyInfo, error) {
	if sourcePath == "" || seedPath == "" {
		return VerifyInfo{}, invalidArgument("source and seed paths are required")
	}
	sourceStat, sourceStatErr := os.Stat(sourcePath)
	seedStat, seedStatErr := os.Stat(seedPath)
	if sourceStatErr != nil {
		return VerifyInfo{}, errorWithPath(ReadFailed, "stat source", sourcePath, sourceStatErr)
	}
	if seedStatErr != nil {
		return VerifyInfo{}, errorWithPath(ReadFailed, "stat seed", seedPath, seedStatErr)
	}
	if os.SameFile(sourceStat, seedStat) {
		return VerifyInfo{}, invalidArgument("source and seed paths refer to the same file")
	}

	seed, openErr := os.Open(seedPath)
	if openErr != nil {
		return VerifyInfo{}, errorWithPath(ReadFailed, "open seed", seedPath, openErr)
	}
	_, verifyErr := VerifySeed(ctx, seed, expected)
	closeSeedErr := seed.Close()
	if verifyErr != nil {
		return VerifyInfo{}, verifyErr
	}
	if closeSeedErr != nil {
		return VerifyInfo{}, errorWithPath(ReadFailed, "close seed", seedPath, closeSeedErr)
	}

	source, sourceOpenErr := os.Open(sourcePath)
	if sourceOpenErr != nil {
		return VerifyInfo{}, errorWithPath(ReadFailed, "open source", sourcePath, sourceOpenErr)
	}
	defer source.Close()
	var seedOpenErr error
	seed, seedOpenErr = os.Open(seedPath)
	if seedOpenErr != nil {
		return VerifyInfo{}, errorWithPath(ReadFailed, "reopen seed", seedPath, seedOpenErr)
	}
	defer seed.Close()
	return VerifySource(ctx, source, seed)
}

func errorWithPath(code ErrorCode, operation, path string, cause error) error {
	return &Error{Code: code, Operation: operation, Path: path, Cause: cause, Message: fmt.Sprintf("%s: %v", operation, cause)}
}

var _ io.Reader = (*os.File)(nil)
