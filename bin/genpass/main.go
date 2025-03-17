package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"strconv"

	"github.com/calico32/genpass"

	"rsc.io/getopt"
)

var flagHex = flag.Bool("hex", false, "a-f0-9")
var flagAlpha = flag.Bool("alpha", false, "a-zA-Z")
var flagLower = flag.Bool("lower", false, "a-z")
var flagUpper = flag.Bool("upper", false, "A-Z")
var flagNumber = flag.Bool("number", false, "0-9")
var flagSpecial = flag.Bool("special", false, "!@#$%^&*()_+")

var flagBytes = flag.Bool("bytes", false, "interpret length as bytes (hex only)")
var flagBase64 = flag.Bool("base64", false, "show base64 (raw url) encoding of raw bytes (hex only)")
var flagEntropy = flag.Bool("entropy", false, "show entropy")
var flagCollisions = flag.Bool("collisions", false, "show collision information")

const (
	minEntropyWeak       = 28.0
	minEntropyFair       = 56.0
	minEntropyStrong     = 84.0
	minEntropyVeryStrong = 128.0
)

func init() {
	getopt.Alias("h", "hex")
	getopt.Alias("a", "alpha")
	getopt.Alias("l", "lower")
	getopt.Alias("u", "upper")
	getopt.Alias("n", "number")
	getopt.Alias("s", "special")
	getopt.Alias("b", "bytes")
	getopt.Alias("B", "base64")
	getopt.Alias("e", "entropy")
	getopt.Alias("c", "collisions")
}

func main() {
	getopt.Parse()

	charset := ""
	if *flagHex {
		charset += genpass.CharsetHex
	}
	if *flagAlpha {
		charset += genpass.CharsetAlpha
	}
	if *flagLower {
		charset += genpass.CharsetLower
	}
	if *flagUpper {
		charset += genpass.CharsetUpper
	}
	if *flagNumber {
		charset += genpass.CharsetNum
	}
	if *flagSpecial {
		charset += genpass.CharsetSpecial
	}

	if charset == "" {
		charset = genpass.CharsetAll
	}

	length := 16
	if getopt.CommandLine.NArg() > 0 {
		l, err := strconv.Atoi(getopt.CommandLine.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: invalid length")
			os.Exit(1)
		}
		length = l
	}

	if *flagBytes && *flagHex {
		length *= 2
	}

	if *flagBase64 && *flagHex && length%2 != 0 {
		fmt.Fprintln(os.Stderr, "error: length must be a multiple of 2 for base64 encoding")
		os.Exit(1)
	}

	charset = genpass.NormalizeCharset(charset)
	password := genpass.Generate(charset, length)

	fmt.Println(string(password))

	if *flagBase64 && *flagHex {
		buf := make([]byte, length/2)
		_, err := hex.Decode(buf, []byte(password))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: failed to decode hex")
			os.Exit(1)
		}
		fmt.Printf("base64url: %s\n", base64.RawURLEncoding.EncodeToString(buf))
	}

	if *flagEntropy {
		e := math.Log2(float64(len(charset))) * float64(length)
		fmt.Printf("Charset: %s\n", charset)
		c := "very weak"
		if e >= minEntropyWeak {
			c = "weak"
		}
		if e >= minEntropyFair {
			c = "fair"
		}
		if e >= minEntropyStrong {
			c = "strong"
		}
		if e >= minEntropyVeryStrong {
			c = "very strong"
		}
		fmt.Printf("Entropy: %.2f bits (%s)\n", e, c)
	}

	if *flagCollisions {
		if !*flagEntropy {
			// need to print charset
			fmt.Printf("Charset: %s\n", charset)
		}

		possibilities := new(big.Int).Exp(big.NewInt(int64(len(charset))), big.NewInt(int64(length)), nil)
		fmt.Printf("Possible passwords: %s\n", possibilities.String())

		collisions := genpass.GetCollisionSeconds(possibilities)
		fmt.Printf("Time until 1%% chance of at least one collision: %s\n", genpass.FormatDuration(collisions))
	}
}
