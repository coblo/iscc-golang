package iscc

import (
	"github.com/nfnt/resize"
	"golang.org/x/text/unicode/norm"
	"image"
	"image/color"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

func imageNormalize(img image.Image) (*image.Gray, error) {
	// 1. Convert to greyscale
	bounds := img.Bounds()
	width, height := bounds.Max.X, bounds.Max.Y
	grayScaleImage := image.NewGray(image.Rectangle{image.Point{0, 0}, image.Point{width, height}})
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			pixelColor := img.At(x, y)
			red, green, blue, _ := pixelColor.RGBA()
			redNormalized := 299 * uint32(red/256)
			greenNormalized := 587 * uint32(green/256)
			blueNormalized := 114 * uint32(blue/256)
			gray := uint8(math.Floor(float64(redNormalized+greenNormalized+blueNormalized)/1000 + 0.5))
			grayColor := color.Gray{gray}
			grayScaleImage.Set(x, y, grayColor)
		}
	}

	// 2. Resize to 32x32
	resizedImage := resize.Resize(32, 32, grayScaleImage, resize.Bicubic)

	return resizedImage.(*image.Gray), nil
}

// TODO document
func textTrim(text string) string {
	if len(text) < INPUT_TRIM {
		return text
	}
	maxValidLength := 0
	for {
		_, width := utf8.DecodeRuneInString(text[maxValidLength : maxValidLength+4])
		if maxValidLength+width > INPUT_TRIM {
			break
		}
		maxValidLength += width
	}
	return string(text[:maxValidLength])
}

func textPreNormalize(text string) string {
	return strings.TrimSpace(norm.NFKC.String(text))
}

// TODO document
func textNormalize(text string) string {
	chars := []rune{}
	whitelist := []*unicode.RangeTable{unicode.L, unicode.N, unicode.S}
	for _, r := range norm.NFD.String(text) {
		if unicode.Is(unicode.Z, r) {
			if len(chars) == 0 || chars[len(chars)-1] != '\u0020' {
				chars = append(chars, '\u0020')
			}
		} else if unicode.IsOneOf(whitelist, r) {
			chars = append(chars, unicode.ToLower(r))
		}
	}
	filteredText := strings.TrimSpace(string(chars))
	return norm.NFC.String(filteredText)
}
