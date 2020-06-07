package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

var acquisTomb tomb.Tomb
var testDir string

var AllResults []LineParseResult
var AllExpected []LineParseResult

type LineParseResult struct {
	Line          string
	ParserResults map[string]map[string]types.Event
}

//cleanForMatch : cleanup results from items that might change every run
func cleanForMatch(in map[string]map[string]types.Event) map[string]map[string]types.Event {
	for stage, val := range in {
		for parser, evt := range val {
			evt.Line.Time = time.Time{}
			in[stage][parser] = evt
		}
	}
	return in
}

func parseMatchLine(event types.Event, parserCTX *parser.UnixParserCtx, parserNodes []parser.Node) (bool, error) {
	oneResult := LineParseResult{}
	h := sha256.New()

	if event.Line.Raw == "" {
		log.Warningf("discarding empty line")
		return true, nil
	}
	h.Write([]byte(event.Line.Raw))
	log.Printf("processing '%s'", event.Line.Raw)

	//parse
	parsed, err := parser.Parse(*parserCTX, event, parserNodes)
	if err != nil {
		return false, fmt.Errorf("failed parsing : %v\n", err)
	}

	if !parsed.Process {
		log.Warningf("Unparsed: %s", parsed.Line.Raw)
	}
	//marshal current result
	oneResult.Line = parsed.Line.Raw
	//we need to clean Line's timestamp
	oneResult.ParserResults = cleanForMatch(parser.StageParseCache)
	/*
	** we are using cmp's feature to match structures.
	** because of the way marshal/unmarshal works we want to make nil == empty
	 */
	// This option handles slices and maps of any type.
	alwaysEqual := cmp.Comparer(func(_, _ interface{}) bool { return true })
	opt := cmp.FilterValues(func(x, y interface{}) bool {
		vx, vy := reflect.ValueOf(x), reflect.ValueOf(y)
		return (vx.IsValid() && vy.IsValid() && vx.Type() == vy.Type()) &&
			(vx.Kind() == reflect.Slice || vx.Kind() == reflect.Map) &&
			(vx.Len() == 0 && vy.Len() == 0)
	}, alwaysEqual)

	/*
		Iterate over the list of expected results and try to find back
	*/
	AllResults = append(AllResults, oneResult)
	matched := false
	for idx, candidate := range AllExpected {
		//not our line
		if candidate.Line != event.Line.Raw {
			continue
		}
		if cmp.Equal(candidate, oneResult, opt) {
			matched = true
			//we go an exact match
			log.Printf("Found exact match (idx:%d)", idx)
			//cleanup
			AllExpected = append(AllExpected[:idx], AllExpected[idx+1:]...)
		} else {
			// log.Printf("Mismatch for line :")
			// log.Printf("%s", )
			return false, fmt.Errorf("mismatch diff: %s", cmp.Diff(candidate, oneResult, opt))
		}
		break
	}
	if !matched && len(AllExpected) != 0 {
		return false, fmt.Errorf("Result is not in the %d expected results", len(AllExpected))
	}
	return matched, nil
}

func testOneDir(target_dir string, parserCTX *parser.UnixParserCtx) (bool, error) {
	var cConfig *csconfig.CrowdSec
	var parserNodes []parser.Node = make([]parser.Node, 0)
	var err error
	var acquisitionCTX *acquisition.FileAcquisCtx
	var inputLineChan = make(chan types.Event)
	var failure bool

	cConfig = csconfig.NewCrowdSecConfig()
	cConfig.AcquisitionFile = target_dir + "/acquis.yaml"
	//load parsers
	log.Infof("Loading parsers")
	parserNodes, err = parser.LoadStageDir(cConfig.ConfigFolder+"/parsers/", parserCTX)
	if err != nil {
		return false, fmt.Errorf("failed to load parser config : %v", err)
	}
	//Init the acqusition : from cli or from acquis.yaml file
	acquisitionCTX, err = acquisition.LoadAcquisitionConfig(cConfig)
	if err != nil {
		return false, fmt.Errorf("Failed to start acquisition : %s", err)
	}
	//load the expected results
	ExpectedPresent := false
	expectedResultsFile := target_dir + "/results.yaml"
	expected_bytes, err := ioutil.ReadFile(expectedResultsFile)
	if err != nil {
		log.Warningf("no results in %s, will dump data instead!", target_dir)
	} else {
		if err := json.Unmarshal(expected_bytes, &AllExpected); err != nil {
			return false, fmt.Errorf("file %s can't be unmarshaled : %s", expectedResultsFile, err)
		} else {
			ExpectedPresent = true
		}
	}
	//start reading in the background
	acquisition.AcquisStartReading(acquisitionCTX, inputLineChan, &acquisTomb)

	go func() {
		log.Printf("Processing lines")
		parser.ParseDump = true
		for event := range inputLineChan {
			ok, err := parseMatchLine(event, parserCTX, parserNodes)
			if !ok {
				fmt.Printf("while parsing:\n%s\n", event.Line.Raw)
				fmt.Printf("%s", err)
				failure = true
			}
		}
	}()

	if err := acquisTomb.Wait(); err != nil {
		log.Warningf("acquisition returned error : %s", err)
	}

	time.Sleep(1 * time.Second)
	/*now let's check the results*/

	//there was no data present, just dump
	if !ExpectedPresent {
		log.Warningf("No expected results loaded, dump.")
		dump_bytes, err := json.MarshalIndent(AllResults, "", " ")
		if err != nil {
			log.Fatalf("failed to marshal results : %s", err)
		}
		if err := ioutil.WriteFile(expectedResultsFile, dump_bytes, 0644); err != nil {
			log.Fatalf("failed to dump data to %s : %s", expectedResultsFile, err)
		}
	} else {
		if len(AllExpected) > 0 {
			log.Errorf("Left-over results in expected : %d", len(AllExpected))
		}
	}
	if failure {
		log.Fatalf("tests failed")
	}
	log.Infof("tests are finished.")
	return true, nil
}

func main() {
	var (
		err       error
		p         parser.UnixParser
		parserCTX *parser.UnixParserCtx

		cConfig *csconfig.CrowdSec
	)
	log.SetLevel(log.InfoLevel)

	/* load base regexps for two grok parsers */
	parserCTX, err = p.Init(map[string]interface{}{"patterns": cConfig.ConfigFolder + string("/patterns/"), "data": cConfig.DataFolder})
	if err != nil {
		log.Errorf("failed to initialize parser : %v", err)
		return
	}
	/* Load enrichers */
	log.Infof("Loading enrich plugins")
	parserPlugins, err := parser.Loadplugin(cConfig.DataFolder)
	if err != nil {
		log.Errorf("Failed to load plugin geoip : %v", err)
	}
	parser.ECTX = append(parser.ECTX, parserPlugins)
	ok, err := testOneDir(os.Args[1], parserCTX)
	if !ok {
		log.Warningf("While testing: %s", os.Args[1])
		log.Warningf("%s", err)
		os.Exit(1)
	}
}
