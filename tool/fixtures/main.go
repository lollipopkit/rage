// Writes age files with the reference Go implementation (filippo.io/age), so
// the tests read files rage itself did not write. Run from this folder:
//
//	go run . ../../test/fixtures
package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const plaintext = "written by filippo.io/age\n"

func write(dir, name string, armored bool, rs ...age.Recipient) {
	var buf bytes.Buffer
	var out io.Writer = &buf
	var a io.WriteCloser
	if armored {
		a = armor.NewWriter(&buf)
		out = a
	}
	w, err := age.Encrypt(out, rs...)
	if err != nil {
		panic(err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	if a != nil {
		if err := a.Close(); err != nil {
			panic(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
		panic(err)
	}
}

func main() {
	dir := os.Args[1]
	s, err := age.NewScryptRecipient("correct horse battery staple")
	if err != nil {
		panic(err)
	}
	s.SetWorkFactor(15)
	write(dir, "go_passphrase.age", false, s)
	write(dir, "go_passphrase_armor.age", true, s)

	id, err := age.GenerateX25519Identity()
	if err != nil {
		panic(err)
	}
	write(dir, "go_x25519.age", false, id.Recipient())
	if err := os.WriteFile(filepath.Join(dir, "go_x25519.key"), []byte(id.String()+"\n"), 0o644); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plaintext.txt"), []byte(plaintext), 0o644); err != nil {
		panic(err)
	}
}
