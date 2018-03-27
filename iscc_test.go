package iscc

import (
	"bytes"
	"encoding/binary"
	"github.com/coblo/iscc-golang/packages/hashes"
	"os"
	"strings"
	"testing"
)

const (
	maxByte = (1 << 8) - 1
)

func TestMetaId(t *testing.T) {
	mid1, _, _, _ := MetaId("ISCC Content Identifiers", "", 1)
	if mid1 != "CCDFPFc87MhdT" {
		t.Fail()
	}
}

func TestInstanceId(t *testing.T) {
	zeroBytesEven := make([]byte, 16)
	iid, h := InstanceId(bytes.NewReader(zeroBytesEven))
	expected := "CR8UZLfpaCm1d"
	if iid != expected {
		t.Logf("Expected '%s', got '%s'", expected, iid)
		t.Fail()
	}
	expected = "2ca7f098709d37d6f6a1a7e0670f49734c735500894aab4dc14d2c13f042dddd"
	if h != expected {
		t.Logf("Expected '%s', got '%s'", expected, h)
		t.Fail()
	}

	ffBytesUneven := make([]byte, 17)
	for i := range ffBytesUneven {
		ffBytesUneven[i] = '\xff'
	}
	iid, h = InstanceId(bytes.NewReader(ffBytesUneven))
	expected = "CR6Nh6fvCxHj9"
	if iid != expected {
		t.Logf("Expected '%s', got '%s'", expected, iid)
		t.Fail()
	}
	expected = "215dadbbb627072c15b2235b521db9896e74d7ef379fdafa731efa52a67d5b7d"
	if h != expected {
		t.Logf("Expected '%s', got '%s'", expected, h)
		t.Fail()
	}

	moreBytes := make([]byte, 66000)
	for i := range moreBytes {
		moreBytes[i] = '\xcc'
	}
	iid, h = InstanceId(bytes.NewReader(moreBytes))

	expected = "CRdhBqWwY7u7i"
	if iid != expected {
		t.Logf("Expected '%s', got '%s'", expected, iid)
		t.Fail()
	}

	expected = "db5f55fc6741664fda4ebb364f2cad99f6ac166aedc7551ab0768c6c67218f71"
	if h != expected {
		t.Logf("Expected '%s', got '%s'", expected, h)
		t.Fail()
	}

}

func TestTextTrim(t *testing.T) {
	trimmed := textTrim(strings.Repeat("ü", 128))
	if len(trimmed) != 128 {
		t.Fail()
	}

	trimmed = textTrim(strings.Repeat("驩", 128))
	if len(trimmed) != 126 {
		t.Fail()
	}
}

func TestDataId(t *testing.T) {
	data := make([]byte, 1000000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	res, err := DataId(bytes.NewReader(data))

	if err != nil {
		t.Error(err)
	}

	if res != "CD86h6EiEUiJW" {
		t.Logf("Expected '%s', got '%s'", "CD86h6EiEUiJW", res)
		t.Fail()
	}
	//
	//random.Rand.Seed(1)
	//random.Rand.Read(data)
	//res, err = dataId(bytes.NewReader(data))
	//if err != nil {
	//	t.Error(err)
	//}
	//
	//if res != "CDjksN4S7LyGn" {
	//	t.Logf("Expected '%s', got '%s'", "CDjksN4S7LyGn", res)
	//	t.Fail()
	//}
}
func TestEncode(t *testing.T) {

}

func TestContentIdMixed(t *testing.T) {
	resText1, err := ContentIdText("Some Text", false)
	if err != nil {
		t.Error(err)
	}
	resText2, err := ContentIdText("Another Text", false)
	if err != nil {
		t.Error(err)
	}

	resMixed1, err := ContentIdMixed([]string{resText1}, false)
	if err != nil {
		t.Error(err)
	}
	if resMixed1 != "CM3oME4TtXogc" {
		t.Logf("Expected '%s', got '%s'", "CM3oME4TtXogc", resMixed1)
		t.Fail()
	}

	resMixed2, err := ContentIdMixed([]string{resText1, resText2}, false)
	if err != nil {
		t.Error(err)
	}
	if resMixed2 != "CM3RQtGc98nXg" {
		t.Logf("Expected '%s', got '%s'", "CM3RQtGc98nXg", resMixed2)
		t.Fail()
	}

}

func TestContentIdText(t *testing.T) {
	cIdTnp, err := ContentIdText("", false)
	if err != nil {
		t.Error(err)
	}
	if cIdTnp != "CTiesaXaMqbbU" {
		t.Fail()
	}

	cIdTp, err := ContentIdText("", true)
	if err != nil {
		t.Error(err)
	}
	if cIdTp != "CtiesaXaMqbbU" {
		t.Fail()
	}
}

func TestMinHash(t *testing.T) {
	inputs := []uint32{
		2307709831,
		4057803343,
		1189896175,
		998490104,
		1957593182,
		985638384,
		1499267049,
		3716940741,
		3418313233,
		2481613561,
	}
	expectedOutputs := []uint32{
		75667492,
		216541698,
		950333549,
		288421317,
		81024446,
		57801071,
		409488582,
		375938535,
		303004011,
		657902949,
		2620415,
		15700186,
		6723779,
		1310271832,
		657533006,
		119718069,
		699338181,
		37238553,
		775506478,
		110198212,
		592529193,
		84967396,
		20340377,
		7673251,
		685464608,
		194424385,
		550687116,
		286960529,
		817061796,
		871759368,
		260823028,
		913208259,
		232875576,
		78529930,
		754656615,
		252317355,
		61037793,
		155950424,
		353660148,
		521778615,
		198930635,
		107447501,
		280655417,
		368807219,
		1114921942,
		391519086,
		397256431,
		203121705,
		232319115,
		1305469504,
		401302502,
		732156174,
		16837457,
		766053304,
		147394004,
		271957790,
		312237764,
		105305419,
		550563271,
		106783279,
		9484381,
		705464551,
		192010509,
		860043432,
		114569197,
		64735329,
		178134804,
		1119093,
		5612941,
		308466472,
		114987232,
		1332667563,
		258560745,
		357388151,
		357326651,
		9453992,
		152582496,
		433615712,
		177421423,
		440157034,
		909147224,
		59959222,
		97961309,
		455953111,
		35915100,
		781463561,
		371917045,
		356456726,
		1096938623,
		524064545,
		102834130,
		614649171,
		140147644,
		541426965,
		355720481,
		24942812,
		606042053,
		18118878,
		182195774,
		43800407,
		27578448,
		138947941,
		436907874,
		277960215,
		3879364,
		455347909,
		323466657,
		311030382,
		1011265639,
		440275097,
		250321982,
		1121336079,
		339784037,
		452020971,
		44802773,
		119348831,
		55980820,
		153848833,
		352373796,
		22841981,
		7770309,
		536512725,
		678636049,
		70729892,
		329658505,
		47669636,
		236268280,
		1077321076,
	}
	output := hashes.MinHash(inputs)
	for i, e := range output {
		if expectedOutputs[i] != e {
			t.Fail()
			return
		}
	}
}

func TestNGramWindows(t *testing.T) {
	res, err := createNGramWindowsLetterWise("", 4)
	if err != nil {
		t.Error(err)
	}

	if len(res) != 1 || len(res[0]) != 0 {
		t.Fail()
	}

	res, err = createNGramWindowsLetterWise("A", 4)
	if err != nil {
		t.Error(err)
	}

	if len(res) != 1 || len(res[0]) != 1 || res[0][0] != byte('A') {
		t.Fail()
	}

	res, err = createNGramWindowsLetterWise("Hello", 4)
	if err != nil {
		t.Error(err)
	}

	if len(res) != 2 || string(res[0]) != "Hell" || string(res[1]) != "ello" {
		t.Fail()
	}

	words := []string{"lorem", "ipsum", "dolor", "sit", "amet"}
	resWords, err := createNGramWindowsWordWise(words, 4)
	if err != nil {
		t.Error(err)
	}

	if len(resWords) != 2 {
		t.Fail()
	}
	if resWords[0][0] != "lorem" || resWords[0][1] != "ipsum" || resWords[0][2] != "dolor" || resWords[0][3] != "sit" {
		t.Fail()
	}

	if resWords[1][0] != "ipsum" || resWords[1][1] != "dolor" || resWords[1][2] != "sit" || resWords[1][3] != "amet" {
		t.Fail()
	}
}

func TestTextNormalize(t *testing.T) {
	text := "Iñtërnâtiônàlizætiøn☃💩 is a ticky \u00A0 thing"
	normalized := textNormalize(text)
	expected := "internationalizætiøn☃💩 is a ticky thing"
	if normalized != expected {
		t.Logf("got '%s' expected '%s'", normalized, expected)
		t.Fail()
	}

}

func TestSimilarityHash(t *testing.T) {
	allZero := make([]byte, 8)
	binary.BigEndian.PutUint64(allZero, 0)
	res, err := hashes.SimilarityHash([][]byte{allZero, allZero})
	if err != nil {
		t.Error(err)
	}
	for i, e := range res {
		if e != allZero[i] {
			t.Fail()
		}
	}

	allOnes := []byte{maxByte}
	res, err = hashes.SimilarityHash([][]byte{allOnes, allOnes})
	if err != nil {
		t.Error(err)
	}

	for i, e := range res {
		if e != allOnes[i] {
			t.Fail()
		}
	}

	a := []byte{byte(6)}
	b := []byte{byte(12)}
	r := []byte{byte(14)}
	res, err = hashes.SimilarityHash([][]byte{a, b})
	if err != nil {
		t.Error(err)
	}

	for i, e := range res {
		if e != r[i] {
			t.Fail()
		}
	}
}

func TestContentIdImage(t *testing.T) {
	reader, _ := os.Open("testfiles/cat.png")
	cidI, err := ContentIdImageFromFile(reader, false)
	t.Log(cidI)
	if err != nil {
		t.Error(err)
	}
	if len(cidI) != 13 {
		t.Fail()
	}
	if cidI != "CYDfTq7Qc7Fre" {
		t.Fail()
	}
}
