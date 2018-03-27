package hashes

import (
	"image"
	"math"
	"sort"
)

func ImageHash(img image.Gray) uint64 {
	bounds := img.Bounds()
	height, width := bounds.Max.Y, bounds.Max.X

	floatMat := make([]float64, len(img.Pix))
	for index, value := range img.Pix {
		floatMat[index] = float64(value)
	}
	// 1. DCT per row
	dctRowMat := make([]float64, 0, len(floatMat))
	for row := 0; row < height; row++ {
		dctRowMat = append(dctRowMat, dct(floatMat[(row*width):(row*width)+width])...)
	}

	// 2. DCT per col
	dctColMat := make([]float64, len(dctRowMat), len(dctRowMat))
	for col := 0; col < width; col++ {
		colArr := make([]float64, 0, height)
		for row := 0; row < height; row++ {
			colArr = append(colArr, dctRowMat[width*row+col])
		}
		dctArr := dct(colArr)
		for row := 0; row < height; row++ {
			dctColMat[width*row+col] = dctArr[row]
		}
	}

	// 3. Extract upper left 8x8 corner
	upperLeftCorner := make([]float64, 0, 64)
	for row := 0; row < 8; row++ {
		upperLeftCorner = append(upperLeftCorner, dctColMat[width*row:width*row+8]...)
	}

	// 4. Calculate median
	med := median(upperLeftCorner)

	// 5. Create 64-bit digest by comparing to median
	var hashDigest uint64
	for index, value := range upperLeftCorner {
		if value > med {
			hashDigest |= 1 << uint8(63-index)
		}
	}

	return hashDigest
}

func dct(inputArr []float64) []float64 {
	length := len(inputArr)
	outputArr := make([]float64, 0, length)
	for k := range inputArr {
		value := 0.0
		for i := range inputArr {
			value += inputArr[i] * math.Cos(float64(math.Pi)*float64(k)*((2*float64(i))+1)/(2*float64(length)))
		}
		outputArr = append(outputArr, 2*value)
	}
	return outputArr
}

func median(inputArr []float64) float64 {
	length := len(inputArr)
	sortedArr := make([]float64, length)
	copy(sortedArr, inputArr)
	sort.Float64s(sortedArr)
	if length%2 == 0 {
		return (sortedArr[length/2-1] + sortedArr[length/2]) / 2
	} else {
		return sortedArr[length/2]
	}
}
