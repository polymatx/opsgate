//go:build !unix

package audit

import "os"

func lockFile(*os.File) (func(), error) {
	return func() {}, nil
}
