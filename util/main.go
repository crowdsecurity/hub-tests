package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"gopkg.in/yaml.v2"

	log "github.com/sirupsen/logrus"
)

type LineParseResult struct {
	Line          string
	ParserResults map[string]map[string]types.Event
}

type ParserResults struct {
	ProvisionalResults []map[string]map[string]types.Event
	FinalResults       []types.Event
}

func main() {
	var ()
	_ = filepath.Walk(".", func(path string, f os.FileInfo, e error) error {
		var (
			err                error
			ProvisionalResults []map[string]map[string]types.Event = make([]map[string]map[string]types.Event, 0)
			FinalResults       []types.Event                       = []types.Event{}
			old                []LineParseResult                   = []LineParseResult{}
			buf                []byte
			stages             []string = []string{}
			parsers            []string = []string{}
			finalStage         string
			finalParser        string
		)
		if filepath.Base(path) == "parser_results.json" {
			if buf, err = ioutil.ReadFile(path); err != nil {
				log.Fatalf("can't open file %s: %s", path, err)
			}
			if err := json.Unmarshal(buf, &old); err != nil {
				log.Fatalf("file %s can't be unmarshaled : %s", path, err)
			}
		} else {
			return nil
		}
		log.Infof("working on path %s", path)
		for _, lineResult := range old {
			for stage := range lineResult.ParserResults {
				stages = append(stages, stage)
			}

			sort.Strings(stages)
			finalStage = stages[len(stages)-1]

			for parser := range lineResult.ParserResults[finalStage] {
				parsers = append(parsers, parser)
			}

			sort.Strings(parsers)
			finalParser = parsers[len(parsers)-1]

			FinalResults = append(FinalResults, lineResult.ParserResults[finalStage][finalParser])
			if finalStage == "s00-raw" {
				lastEvent := lineResult.ParserResults[finalStage][finalParser]
				lastEvent.Stage = "s01-parse"
				lineResult.ParserResults["s00-raw"][finalParser] = lastEvent
				lastEvent.Stage = "s02-enrich"
				lineResult.ParserResults["s01-parse"] = make(map[string]types.Event)
				lineResult.ParserResults["s01-parse"][""] = lastEvent
				lineResult.ParserResults["s02-enrich"] = make(map[string]types.Event)
				lineResult.ParserResults["s02-enrich"][""] = lastEvent
			}
			if finalStage == "s01-parse" {
				lastEvent := lineResult.ParserResults[finalStage][finalParser]
				lastEvent.Stage = "s02-enrich"
				lineResult.ParserResults[finalStage][finalParser] = lastEvent
				lineResult.ParserResults["s02-enrich"] = make(map[string]types.Event)
				lineResult.ParserResults["s02-enrich"][""] = lastEvent
			}
			if _, ok := lineResult.ParserResults["s00-raw"]; !ok {
				lineResult.ParserResults["s00-raw"] = make(map[string]types.Event)

			}
			ProvisionalResults = append(ProvisionalResults, lineResult.ParserResults)
		}
		for ind := range FinalResults {
			FinalResults[ind].Stage = "s02-enrich"
			FinalResults[ind].Process = true
		}

		toMarshal := ParserResults{
			ProvisionalResults: ProvisionalResults,
			FinalResults:       FinalResults,
		}
		if buf, err = yaml.Marshal(toMarshal); err != nil {
			log.Fatalf("unable to marshal: %+v", toMarshal)
		}

		ext := filepath.Ext(path)
		filename := path[0 : len(path)-len(ext)]
		if err = ioutil.WriteFile(filename+".yaml", buf, 0644); err != nil {
			return fmt.Errorf("Write file %s error: %s", filename+".yaml", err)
		}

		return nil

	})
}
