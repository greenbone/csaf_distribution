// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT

package errs

import (
	"errors"
	"strings"
)

// ErrNetwork indicates a network level error
type ErrNetwork struct {
	Message string
}

func (e ErrNetwork) Error() string {
	return e.Message
}

// ErrInvalidCsaf notifies about an invalid csaf document (can only be fixed by the CSAF Source/Provider)
type ErrInvalidCsaf struct {
	Message string
}

func (e ErrInvalidCsaf) Error() string {
	return e.Message
}

// ErrCsafProviderIssue is an error which is not related directly the contents of a csaf document and can be only fixed by the CSAF Source/Provider
type ErrCsafProviderIssue struct {
	Message string
}

func (e ErrCsafProviderIssue) Error() string {
	return e.Message
}

type ErrInvalidCredentials struct {
	Message string
}

func (e ErrInvalidCredentials) Error() string {
	return e.Message
}

var ErrRetryable = errors.New("(retryable error)")

// CompositeErrRolieFeed holds an array of errors which encountered during processing rolie feeds
type CompositeErrRolieFeed struct {
	Errs []error
}

func (e *CompositeErrRolieFeed) Error() string {
	if len(e.Errs) == 0 {
		return "empty CompositeErrRolieFeed"
	}

	messages := make([]string, 0, len(e.Errs))
	for _, e := range e.Errs {
		messages = append(messages, e.Error())
	}
	return strings.Join(messages, "\n")
}

func (e *CompositeErrRolieFeed) Unwrap() []error {
	return e.Errs
}

// CompositeErrCsafDownload holds an array of errors which encountered during the actual csaf download
type CompositeErrCsafDownload struct {
	Errs []error
}

func (e *CompositeErrCsafDownload) Error() string {
	if len(e.Errs) == 0 {
		return "empty CompositeErrCsafDownload"
	}

	messages := make([]string, 0, len(e.Errs))
	for _, e := range e.Errs {
		messages = append(messages, e.Error())
	}
	return strings.Join(messages, "\n")
}

func (e *CompositeErrCsafDownload) Unwrap() []error {
	return e.Errs
}

// FlattenError flattens out all composite errors (note: discards the errors wrapped around [CompositeErrRolieFeed] or [CompositeErrCsafDownload])
// The assumed structure is CompositeErrRolieFeed{Errs: []error{...,CompositeErrCsafDownload,...,CompositeErrCsafDownload,...}}.
func FlattenError(err error) (flattenedErrors []error) {
	var rolieErrs *CompositeErrRolieFeed
	if errors.As(err, &rolieErrs) {
		for _, rolieErr := range rolieErrs.Unwrap() {
			var csafDlErrs *CompositeErrCsafDownload
			if errors.As(rolieErr, &csafDlErrs) {
				for _, csafDlErr := range csafDlErrs.Unwrap() {
					flattenedErrors = append(flattenedErrors, csafDlErr)
				}
			} else {
				flattenedErrors = append(flattenedErrors, rolieErr)
			}
		}
	} else {
		flattenedErrors = []error{err}
	}

	return flattenedErrors
}
