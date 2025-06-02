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

// CompositeErrFeed holds an array of errors which encountered during processing rolie feeds
type CompositeErrFeed struct {
	Errs []error
}

func (e *CompositeErrFeed) Error() string {
	if len(e.Errs) == 0 {
		return "empty CompositeErrFeed"
	}

	messages := make([]string, 0, len(e.Errs))
	for _, e := range e.Errs {
		messages = append(messages, e.Error())
	}
	return strings.Join(messages, "\n")
}

func (e *CompositeErrFeed) Unwrap() []error {
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

// FlattenError flattens out all composite errors (note: discards the errors wrapped around [CompositeErrFeed] or [CompositeErrCsafDownload])
// The assumed structure is CompositeErrFeed{Errs: []error{...,CompositeErrCsafDownload,...,CompositeErrCsafDownload,...}}.
func FlattenError(err error) (flattenedErrors []error) {
	var rolieErrs *CompositeErrFeed
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
