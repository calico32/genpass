package genpass

import (
	"fmt"
	"math"
	"math/big"
	"strings"
)

// GetCollisionSeconds calculates, given a password is generated once per
// second, the number of seconds required for a 1% probability of at least one
// collision using the birthday paradox formula.
//
// The formula is:
//
//	N = sqrt(2 * M * ln(1 / (1 - p)))
//
// where N is the number of seconds, M is the number of possible passwords, and
// p is the probability of collision.
//
// If a different number of passwords are generated per second, the result can
// be multiplied by that number.
//
// The result is rounded up to the nearest second.
func GetCollisionSeconds(possiblePasswords *big.Int) *big.Int {
	// Probability of collision
	p := 0.01

	// Compute ln(1 / (1 - p))
	lnFactor := math.Log(1 / (1 - p))

	// Compute sqrt(2 * N * lnFactor)
	N := new(big.Float).SetInt(possiblePasswords)
	factor := new(big.Float).SetFloat64(2 * lnFactor)
	mul := new(big.Float).Mul(N, factor)
	sqrt := new(big.Float).Sqrt(mul)

	// Convert result back to big.Int (rounding up)
	n := new(big.Int)
	sqrt.Int(n)

	return n // Number of seconds required
}

// GetCollisionSecondsFromLength is like [GetCollisionSeconds] but takes the
// charset length and password length as arguments.
//
// The number of possible passwords is calculated as charsetLen^passwordLen.
func GetCollisionSecondsFromLength(charsetLen int, passwordLen int) *big.Int {
	possiblePasswords := new(big.Int).Exp(big.NewInt(int64(charsetLen)), big.NewInt(int64(passwordLen)), nil)
	return GetCollisionSeconds(possiblePasswords)
}

// FormatDuration formats a number of seconds into a human-readable string using
// the largest unit of time that is less than the duration, e.g. "2 million
// years".
//
// If the duration is greater than 999 trillion years, it returns
// "an eternity", and if the duration is less than a second, it returns
// "less than a second".
func FormatDuration(seconds *big.Int) string {
	limitSeconds := new(big.Int).Mul(log10years(100), big.NewInt(999))

	if seconds.Cmp(limitSeconds) >= 0 {
		return "an eternity"
	}

	for i := len(units) - 1; i >= 0; i-- {
		if seconds.Cmp(units[i].value) >= 0 {
			unitName := units[i].name
			unitSeconds := units[i].value
			result := new(big.Int).Div(seconds, unitSeconds)
			if !strings.Contains(unitName, " ") {
				// we need to pluralize the unit if the number is 1
				if result.Cmp(big.NewInt(1)) == 0 {
					unitName += "s"
				}
			}
			return fmt.Sprintf("%s %s", result.String(), unitName)
		}
	}

	return "less than a second"
}

var oneYear = big.NewInt(31536000)

func log10years(pow int64) *big.Int {
	i := new(big.Int).Exp(big.NewInt(10), big.NewInt(pow), nil)
	return i.Mul(i, oneYear)
}

var units = []struct {
	name  string
	value *big.Int
}{
	{"second", big.NewInt(1)},
	{"minute", big.NewInt(60)},
	{"hour", big.NewInt(3600)},
	{"day", big.NewInt(86400)},
	{"year", oneYear},
	{"thousand years", log10years(3)},
	{"million years", log10years(6)},
	{"billion years", log10years(9)},
	{"trillion years", log10years(12)},
	{"quadrillion years", log10years(15)},
	{"quintillion years", log10years(18)},
	{"sextillion years", log10years(21)},
	{"septillion years", log10years(24)},
	{"octillion years", log10years(27)},
	{"nonillion years", log10years(30)},
	{"decillion years", log10years(33)},
	{"undecillion years", log10years(36)},
	{"duodecillion years", log10years(39)},
	{"tredecillion years", log10years(42)},
	{"quattuordecillion years", log10years(45)},
	{"quindecillion years", log10years(48)},
	{"sexdecillion years", log10years(51)},
	{"septendecillion years", log10years(54)},
	{"octodecillion years", log10years(57)},
	{"novemdecillion years", log10years(60)},
	{"vigintillion years", log10years(63)},
	{"unvigintillion years", log10years(66)},
	{"duovigintillion years", log10years(69)},
	{"trevigintillion years", log10years(72)},
	{"quattuorvigintillion years", log10years(75)},
	{"quinvigintillion years", log10years(78)},
	{"sexvigintillion years", log10years(81)},
	{"septenvigintillion years", log10years(84)},
	{"octovigintillion years", log10years(87)},
	{"novemvigintillion years", log10years(90)},
	{"trigintillion years", log10years(93)},
	{"untrigintillion years", log10years(96)},
	{"duotrigintillion years", log10years(99)},
	{"googol years", log10years(100)},
}
