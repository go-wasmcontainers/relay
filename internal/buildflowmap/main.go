// SPDX-License-Identifier: BSD-3-Clause

// Command buildflowmap builds the flow-map page's WebAssembly (module
// web/flowmap, GOOS=js) and writes what server/flowmap embeds:
// flowmap.wasm.gz (gzip, no name, no time: reproducible) and wasm_exec.js
// (from the toolchain that built it). With -check it rebuilds into memory and
// fails if the committed files differ — the CI gate.
//
//	go run ./internal/buildflowmap [-check]   (from the repository root)
package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	check := flag.Bool("check", false, "compare with the committed files instead of writing them")
	flag.Parse()
	if err := run(*check); err != nil {
		fmt.Fprintln(os.Stderr, "buildflowmap:", err)
		os.Exit(1)
	}
}

func run(check bool) error {
	tmp, err := os.MkdirTemp("", "flowmap")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	out := filepath.Join(tmp, "flowmap.wasm")
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", out, "./wasm")
	cmd.Dir = filepath.Join("web", "flowmap")
	cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm", "CGO_ENABLED=0", "GOWORK=off")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go build: %w", err)
	}
	wasm, err := os.ReadFile(out)
	if err != nil {
		return err
	}
	var gz bytes.Buffer
	zw, err := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := zw.Write(wasm); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	goroot, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return err
	}
	execJS, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(goroot)), "lib", "wasm", "wasm_exec.js"))
	if err != nil {
		return err
	}
	files := map[string][]byte{
		filepath.Join("server", "flowmap", "flowmap.wasm.gz"): gz.Bytes(),
		filepath.Join("server", "flowmap", "wasm_exec.js"):    execJS,
	}
	for path, b := range files {
		if check && strings.HasSuffix(path, ".gz") {
			continue // not committed (5 MB): built for release binaries and tests
		}
		if check {
			old, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if !bytes.Equal(old, b) {
				return fmt.Errorf("%s is not what this source builds: run go run ./internal/buildflowmap", path)
			}
			continue
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "flowmap.wasm: %d bytes, %d gzipped\n", len(wasm), gz.Len())
	return nil
}
