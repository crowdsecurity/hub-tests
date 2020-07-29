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
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
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

func getCmpOptions() cmp.Option {
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
	return opt
}

//cleanForMatch : cleanup results from items that might change every run. We strip as well strictly equal results
func cleanForMatch(in map[string]map[string]types.Event) map[string]map[string]types.Event {
	for stage, val := range in {
		for parser, evt := range val {
			evt.Line.Time = time.Time{}
			in[stage][parser] = evt
		}
	}
	return in
}

//ret : test_ok, parsed_ok, error
func parseMatchLine(event types.Event, parserCTX *parser.UnixParserCtx, parserNodes []parser.Node) (bool, bool, error) {
	oneResult := LineParseResult{}
	h := sha256.New()

	if event.Line.Raw == "" {
		log.Warningf("discarding empty line")
		return true, false, nil
	}
	h.Write([]byte(event.Line.Raw))
	//parse
	parsed, err := parser.Parse(*parserCTX, event, parserNodes)
	if err != nil {
		return false, false, fmt.Errorf("failed parsing : %v\n", err)
	}

	if !parsed.Process {
		return true, false, fmt.Errorf("unparsed line %s", parsed.Line.Raw)
	}
	//marshal current result
	oneResult.Line = parsed.Line.Raw
	//we need to clean Line's timestamp
	oneResult.ParserResults = cleanForMatch(parser.StageParseCache)

	opt := getCmpOptions()
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
			AllExpected = append(AllExpected[:idx], AllExpected[idx+1:]...)
		} else {
			return false, true, fmt.Errorf("mismatch diff (-want +got) : %s", cmp.Diff(candidate, oneResult, opt))
		}
		break
	}
	if !matched && len(AllExpected) != 0 {
		return false, true, fmt.Errorf("Result is not in the %d expected results", len(AllExpected))
	}
	return matched, true, nil
}

func testOneDir(target_dir string, parserCTX *parser.UnixParserCtx, cConfig *csconfig.CrowdSec) (bool, error) {
	var parserNodes []parser.Node = make([]parser.Node, 0)
	var err error
	var acquisitionCTX *acquisition.FileAcquisCtx
	var inputLineChan = make(chan types.Event)
	var failure bool
	var OrigExpectedLen int

	cConfig.AcquisitionFile = target_dir + "/acquis.yaml"
	//load parsers
	log.Infof("Loading parsers")
	parserNodes, err = parser.LoadStageDir(cConfig.ConfigFolder+"/parsers/", parserCTX)
	if err != nil {
		return false, fmt.Errorf("failed to load parser config : %v", err)
	}
	//Init the acquisition : from cli or from acquis.yaml file
	acquisitionCTX, err = acquisition.LoadAcquisitionConfig(cConfig)
	if err != nil {
		return false, fmt.Errorf("Failed to start acquisition : %s", err)
	}
	//load the expected results
	ExpectedPresent := false
	expectedResultsFile := target_dir + "/results.json"
	expected_bytes, err := ioutil.ReadFile(expectedResultsFile)
	if err != nil {
		log.Warningf("no results in %s, will dump data instead!", target_dir)
	} else {
		if err := json.Unmarshal(expected_bytes, &AllExpected); err != nil {
			return false, fmt.Errorf("file %s can't be unmarshaled : %s", expectedResultsFile, err)
		} else {
			ExpectedPresent = true
			OrigExpectedLen = len(AllExpected)
		}
	}
	//start reading in the background
	acquisition.AcquisStartReading(acquisitionCTX, inputLineChan, &acquisTomb)

	linesRead := 0
	linesUnparsed := 0
	testsFailed := 0

	go func() {
		//log.Printf("Processing lines")
		defer log.Printf("processing loop over")
		parser.ParseDump = true
		for event := range inputLineChan {
			linesRead++
			test_ok, parsed_ok, err := parseMatchLine(event, parserCTX, parserNodes)
			if !parsed_ok {
				if err != nil {
					log.Warningf("parser error : %s", err)
				}
				linesUnparsed++
			}
			if !test_ok {
				failure = true
				testsFailed++
				log.Errorf("test %d failed.", linesRead)
				if err != nil {
					log.Errorf("test failure : %s", err)
				}
				continue
			}
		}

	}()

	log.Printf("waiting for acquis tomb to die")
	if err := acquisTomb.Wait(); err != nil {
		log.Warningf("acquisition returned error : %s", err)
	}

	time.Sleep(1 * time.Second)
	/*now let's check the results*/

	log.Infof("%d lines read", linesRead)
	log.Infof("%d parser results, %d UNPARSED", len(AllResults), linesUnparsed)
	if linesRead != len(AllResults) {
		log.Warningf("%d out of %d lines didn't yeld result", linesRead-len(AllResults), linesRead)
	}
	log.Infof("%d/%d matched results", OrigExpectedLen-len(AllExpected), OrigExpectedLen)
	if len(AllExpected) > 0 {
		log.Warningf("%d out of %d expected results unmatched", len(AllExpected), OrigExpectedLen)
	}

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
		expectedResultsFile = expectedResultsFile + ".fail"
		log.Errorf("tests failed, writting results to %s", expectedResultsFile)
		dump_bytes, err := json.MarshalIndent(AllResults, "", " ")
		if err != nil {
			log.Fatalf("failed to marshal results : %s", err)
		}
		if err := ioutil.WriteFile(expectedResultsFile, dump_bytes, 0644); err != nil {
			log.Fatalf("failed to dump data to %s : %s", expectedResultsFile, err)
		}
		log.Printf("done")
		os.Exit(1)
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

	log.Infof("built against %s", cwversion.VersionStr())
	cConfig = csconfig.NewCrowdSecConfig()

	// Handle command line arguments
	if err := cConfig.GetOPT(); err != nil {
		log.Fatalf(err.Error())
	}

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
	ok, err := testOneDir(os.Args[len(os.Args)-1], parserCTX, cConfig)
	if !ok {
		log.Warningf("While testing: %s", os.Args[1])
		log.Warningf("%s", err)
		os.Exit(1)
	}
}
