// Copyright 2023 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v2"
)

func init() {
	jt = vm.NewShanghaiEOFInstructionSetForTesting()
}

var (
	errStackOverflow  = errors.New("stack overflow")
	errStackUnderflow = errors.New("stack underflow")

	jt       vm.JumpTable
	errorMap = map[string]string{
		io.ErrUnexpectedEOF.Error():          "UnexpectedEOF",
		vm.ErrInvalidMagic.Error():           "InvalidMagic",
		vm.ErrInvalidVersion.Error():         "InvalidVersion",
		vm.ErrMissingTypeHeader.Error():      "MissingTypeHeader",
		vm.ErrInvalidTypeSize.Error():        "InvalidTypeSize",
		vm.ErrMissingCodeHeader.Error():      "MissingCodeHeader",
		vm.ErrInvalidCodeHeader.Error():      "InvalidCodeHeader",
		vm.ErrMissingDataHeader.Error():      "MissingDataHeader",
		vm.ErrMissingTerminator.Error():      "MissingTerminator",
		vm.ErrTooManyInputs.Error():          "TooManyInputs",
		vm.ErrTooManyOutputs.Error():         "TooManyOutputs",
		vm.ErrTooLargeMaxStackHeight.Error(): "TooLargeMaxStackHeight",
		vm.ErrInvalidSection0Type.Error():    "InvalidSection0Type",
		vm.ErrInvalidCodeSize.Error():        "InvalidCodeSize",
		vm.ErrInvalidContainerSize.Error():   "InvalidContainerSize",
		vm.ErrUndefinedInstruction.Error():   "UndefinedInstruction",
		vm.ErrTruncatedImmediate.Error():     "TruncatedImmediate",
		vm.ErrInvalidSectionArgument.Error(): "InvalidSectionArgument",
		vm.ErrInvalidJumpDest.Error():        "InvalidJumpDest",
		vm.ErrConflictingStack.Error():       "ConflictingStack",
		vm.ErrInvalidBranchCount.Error():     "InvalidBranchCount",
		vm.ErrInvalidOutputs.Error():         "InvalidOutputs",
		vm.ErrInvalidMaxStackHeight.Error():  "InvalidMaxStackHeight",
		vm.ErrInvalidCodeTermination.Error(): "InvalidCodeTermination",
		vm.ErrUnreachableCode.Error():        "UnreachableCode",
		errStackOverflow.Error():             "StackOverflow",
		errStackUnderflow.Error():            "StackUnderflow",
	}
)

type EOFTest struct {
	Code    string              `json:"code"`
	Results map[string]etResult `json:"results"`
}

type etResult struct {
	Result    bool   `json:"result"`
	Exception string `json:"exception,omitempty"`
}

func eofParser(ctx *cli.Context) error {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(ctx.Int(VerbosityFlag.Name)))
	log.Root().SetHandler(glogger)

	// If `--hex` is set, parse and validate the hex string argument.
	if ctx.IsSet(HexFlag.Name) {
		if _, err := parseAndValidate(ctx.String(HexFlag.Name)); err != nil {
			if err2 := errors.Unwrap(err); err2 != nil {
				err = err2
			}
			return fmt.Errorf("%s: %w", errorMap[err.Error()], err)
		}
		fmt.Println("ok.")
		return nil
	}

	// If `--test` is set, parse and validate the reference test at the provided path.
	if ctx.IsSet(RefTestFlag.Name) {
		src, err := os.ReadFile(ctx.String(RefTestFlag.Name))
		if err != nil {
			return err
		}
		var tests map[string]EOFTest
		if err = json.Unmarshal(src, &tests); err != nil {
			return err
		}
		passed, total := 0, 0
		for name, tt := range tests {
			for fork, r := range tt.Results {
				total++
				// TODO(matt): all tests currently run against
				// shanghai EOF, add support for custom forks.
				_, err := parseAndValidate(tt.Code)
				if err2 := errors.Unwrap(err); err2 != nil {
					err = err2
				}
				if u := errors.Unwrap(err); u != nil && u.Error() == errStackOverflow.Error() {
					err = errStackOverflow
				} else if u := errors.Unwrap(err); u != nil && u.Error() == errStackUnderflow.Error() {
					err = errStackUnderflow
				}
				if r.Result && err != nil {
					fmt.Fprintf(os.Stderr, "%s, %s: expected success, got %v\n", name, fork, err)
					continue
				}
				if !r.Result && err == nil {
					fmt.Fprintf(os.Stderr, "%s, %s: expected error %s, got %v\n", name, fork, r.Exception, err)
					continue
				}
				if !r.Result && err != nil && r.Exception != errorMap[err.Error()] {
					fmt.Fprintf(os.Stderr, "%s, %s: expected error %s, got: %s: %v\n", name, fork, r.Exception, errorMap[err.Error()], err)
					continue
				}
				passed++
			}
		}
		fmt.Printf("%d/%d tests passed.\n", passed, total)
		return nil
	}

	out := make(map[string]EOFTest, 0)
	i := 0
	// If neither are passed in, read input from stdin.
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		t = strings.ReplaceAll(t, " ", "")
		t = strings.ReplaceAll(t, "-", "")
		if len(t) == 0 || t[0] == '#' {
			continue
		}
		results := make(map[string]etResult)
		if _, err := parseAndValidate(t); err != nil {
			mappedErr := err
			if err2 := errors.Unwrap(err); err2 != nil {
				mappedErr = err2
			}

			if u := errors.Unwrap(mappedErr); u != nil && u.Error() == errStackOverflow.Error() {
				mappedErr = errStackOverflow
			} else if u := errors.Unwrap(mappedErr); u != nil && u.Error() == errStackUnderflow.Error() {
				mappedErr = errStackUnderflow
			}

			fmt.Fprintf(os.Stderr, "%s: %v\n", errorMap[mappedErr.Error()], err)
			results["Cancun"] = etResult{
				Result:    false,
				Exception: errorMap[mappedErr.Error()],
			}
			i++
			if errors.Is(err, hex.ErrLength) {
				continue
			}
		} else {
			i++
			results["cancun"] = etResult{
				Result: true,
			}
		}

		out[fmt.Sprintf("corpus_test_%d", i)] = EOFTest{Code: t, Results: results}
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	return nil
}

func parseAndValidate(s string) (*vm.Container, error) {
	if len(s) >= 2 && strings.HasPrefix(s, "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("unable to decode data (%s): %w", s, err)
	}
	var c vm.Container
	if err := c.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	if err := c.ValidateCode(&jt); err != nil {
		return nil, err
	}
	return &c, nil
}
