//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
)

const (
	srBehaviourSourceFile = "../../../api/attribute.pb.go"
	srBehaviourTargetFile = "srbehavior.go"
)

func main() {
	if len(os.Args) != 2 {
		panic("expected single argument: type to generate")
	}

	switch os.Args[1] {
	case "SRBehavior":
		generateSRBehaviour()
	default:
		panic("unexpected type: " + os.Args[1])
	}
}

func generateSRBehaviour() {
	content, err := os.ReadFile(srBehaviourSourceFile)
	if err != nil {
		doPanic("failed to read file %s: %w", srBehaviourSourceFile, err)
	}

	re := regexp.MustCompile(`(?ms)type SRv6Behavior int32\s+(const \(.*?\)\n)`)

	match := re.FindSubmatch(content)
	if match == nil {
		doPanic("couldn't find SRv6Behavior constants")
	}

	constants := bytes.ReplaceAll(
		bytes.ReplaceAll(match[1], []byte("SRv6Behavior_"), nil),
		[]byte("SRv6"),
		[]byte("SR"),
	)

	buf := bytes.NewBuffer([]byte("// Generated code; DO NOT EDIT.\n\npackage bgp\n\n"))
	buf.Write(constants)

	if err := os.WriteFile(srBehaviourTargetFile, buf.Bytes(), 0o664); err != nil {
		doPanic("failed to write file %s: %w", )
	}
}
func doPanic(message string, args ...interface{}) {
	panic(fmt.Errorf(message+"\n", args...))
}
