//go:build !linux

package pkglifecycle

func platformReadEnviron(pid uint32) (map[string]string, error) {
	return nil, nil
}
