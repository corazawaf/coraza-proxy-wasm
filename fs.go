package main

import (
	"io/fs"
	"os"
	"path"
	"strings"
)

type embedFS interface {
	fs.FS
	ReadDir(name string) ([]fs.DirEntry, error)
	ReadFile(name string) ([]byte, error)
}

type rulesFS struct {
	fs           embedFS
	filesMapping map[string]string
	dirsMapping  map[string]string
}

const pathSeparator = string(os.PathSeparator)

func (r rulesFS) Open(name string) (fs.File, error) {
	if strings.Contains(name, pathSeparator) {
		// is not in root, hence we can do dir mapping
		for a, dst := range r.dirsMapping {
			prefix := a + pathSeparator
			if strings.HasPrefix(name, prefix) {
				return r.fs.Open(path.Join(dst, name[len(prefix):]))
			}
		}
	}

	for a, dst := range r.filesMapping {
		if a == name {
			return r.fs.Open(dst)
		}
	}

	return r.fs.Open(name)
}

func (r rulesFS) ReadDir(name string) ([]fs.DirEntry, error) {
	for a, dst := range r.dirsMapping {
		if a == name {
			return r.fs.ReadDir(dst)
		}

		prefix := a + pathSeparator
		if strings.HasPrefix(name, prefix) {
			return r.fs.ReadDir(path.Join(dst, name[len(prefix):]))
		}
	}
	return r.fs.ReadDir(name)
}

func (r rulesFS) ReadFile(name string) ([]byte, error) {
	for a, dst := range r.filesMapping {
		if a == name {
			return r.fs.ReadFile(dst)
		}
	}

	return r.fs.ReadFile(name)
}
