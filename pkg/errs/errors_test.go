// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT

package errs

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlattenError(t *testing.T) {

	t.Run("flatten (only) composite errors defined in this package", func(t *testing.T) {
		csafDownloadErrsFlat := []error{
			fmt.Errorf("error containing several errors 1: %w 2: %w", errors.New("nested err 1"), errors.New("nested err 2")), errors.New("nested err 2"),
			errors.Join(errors.New("nested err in join 1"), errors.New("nested err in join 2")),
			errors.New("single error 1"),
			errors.New("single error 2"),
		}

		compositeErrCsafDownload := &CompositeErrCsafDownload{Errs: csafDownloadErrsFlat}

		singleRolieFeedErrs := []error{
			errors.New("single error rolie feed 1"),
			errors.New("single error rolie feed 2"),
		}

		rolieFeedCompositeErr := CompositeErrRolieFeed{
			Errs: append(
				singleRolieFeedErrs,
				fmt.Errorf("issues during downloader of rolie: %w", compositeErrCsafDownload),
				compositeErrCsafDownload,
			),
		}
		wantFlattenedErrors := slices.Concat(singleRolieFeedErrs, csafDownloadErrsFlat, csafDownloadErrsFlat)

		gotFlattenedErrors := FlattenError(fmt.Errorf("wrap rolie feed composite err: %w", &rolieFeedCompositeErr))

		assert.ElementsMatch(t, wantFlattenedErrors, gotFlattenedErrors)
	})

	t.Run("single error is returned as is", func(t *testing.T) {
		err := errors.Join(errors.New("nested err in join 1"), errors.New("nested err in join 2"))
		wantFlattenedErrors := []error{err}
		gotFlattenedErrors := FlattenError(err)
		assert.ElementsMatch(t, wantFlattenedErrors, gotFlattenedErrors)
	})
}
