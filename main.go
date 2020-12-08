package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var (
	AllResults    []LineParseResult
	AllExpected   []LineParseResult
	AllPoResults  []LineParsePoResult
	AllPoExpected []LineParsePoResult

	holders []leaky.BucketFactory
	buckets *leaky.Buckets

	outputEventChan chan types.Event
)

type ConfigTest struct {
	//parsers files
	LogFile string `yaml:"log_file"`

	ParserInputFile string `yaml:"parser_input"`
	ParseResultFile string `yaml:"parser_results"`

	//bucket files
	//Nota: BucketInputFile is generated by parsing
	BucketInputFile  string `yaml:"bucket_input"`
	BucketResultFile string `yaml:"bucket_results"`

	//po files
	//Nota: poResultFile is generated by buckets
	PoInputFile  string `yaml:"postoveflow_input"`
	PoResultFile string `yaml:"postoverflow_results"`

	//configuration
	AcquisitionFile    string `yaml:"acquisition_file"`
	ReprocessInputFile string `yaml:"reprocess_file"`

	IndexFile string `yaml:"index"`
	//configuration list. For now sorting by type is mandatory
	Configurations map[string][]string `yaml:"configurations"`

	target_dir string
}

type LineParseResult struct {
	Line          string
	ParserResults map[string]map[string]types.Event
}

type LineParsePoResult struct {
	Overflow      types.RuntimeAlert
	ParserResults map[string]map[string]types.Event
}

type Flags struct {
	ConfigFile    string
	SingleFile    string
	JUnitFilename string
	GlobFiles     string
	Overall       bool
}

func (f *Flags) Parse() {
	flag.StringVar(&f.ConfigFile, "config", "./dev.yaml", "configuration file")
	flag.StringVar(&f.SingleFile, "single", "", "target test dir")
	flag.StringVar(&f.JUnitFilename, "junit", "", "junit file name")
	flag.StringVar(&f.GlobFiles, "glob", "config.yaml", "globing over all subdirs")
	flag.BoolVar(&f.Overall, "overall", false, "adding a overall checkup to tests")
	flag.Parse()
}

// dirty globing by hand
func glob(dir string, ext string) ([]string, error) {

	files := []string{}
	err := filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
		if filepath.Base(path) == ext {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

type Configuration struct {
	markdown         bool
	markdownNotEmpty bool
	count            int
	failure          int
}

func main() {
	var (
		err           error
		flags         *Flags
		matches       []string
		report        *JUnitTestSuites
		OverallResult *Overall
	)

	log.SetLevel(log.InfoLevel)
	log.SetOutput(os.Stdout)

	log.Infof("built against %s", cwversion.VersionStr())
	flags = &Flags{}
	flags.Parse()

	if flags.JUnitFilename != "" {
		if report, err = LoadJunitReport(flags.JUnitFilename); err != nil {
			log.Fatalf("Error loading JUnit file: %s", flags.JUnitFilename)
		}
	}

	OverallResult = NewOverall()
	if flags.SingleFile != "" {
		if tested, failure := doTest(flags, flags.SingleFile, report); tested != nil {
			OverallResult.AddSingleResult(tested, failure)
		}
	} else {
		//we are globbing :)
		if matches, err = glob(".", flags.GlobFiles); err != nil {
			log.Fatalf("Error in the glob pattern: %s", err)
		}
		log.Printf("Doing test on %s", matches)
		for _, match := range matches {
			log.Printf("Doing test on %s", match)
			if tested, failure := doTest(flags, match, report); tested != nil {
				OverallResult.AddSingleResult(tested, failure)
			}
		}
	}

	//We build the overall result
	overall := make(map[string]map[string]Configuration)
	if flags.Overall {
		if overall, err = buildOverallResult("."); err != nil {
			log.Errorf("Weird thing walking for building the overall test")
		}
	}

	for itemType, m := range OverallResult.overall {
		for item, testResult := range m {
			if _, ok := overall[itemType]; !ok {
				continue
			}
			if _, ok := overall[itemType][item]; !ok {
				continue
			}
			tmp := overall[itemType][item]
			tmp.count = testResult.count
			tmp.failure = testResult.failCount
			overall[itemType][item] = tmp
		}
	}
	for itemType, m := range overall {
		for item, testResult := range m {
			err = nil
			if testResult.failure > 0 {
				err = errors.New("The test failed %d times")
			}
			if testResult.count == 0 {
				err = errors.New("The test wasn't performed on this configuration item")
			}
			report.AddSingleResult("Overall test", err, fmt.Sprintf("%s/%s passed %d times", itemType, item, testResult.count))
		}
	}

	if flags.JUnitFilename != "" {
		err = report.StoreJunitReport(flags.JUnitFilename)
		if err != nil {
			log.Errorf("Unable to store junit file: %s", err)
		}
	}

}

// do the real testing on one target
// return the configurations loaded in order to build the overall thingy
func doTest(flags *Flags, targetFile string, report *JUnitTestSuites) (map[string][]string, bool) {
	var (
		err         error
		cConfig     *csconfig.GlobalConfig
		files       []string
		localConfig ConfigTest
		index       map[string]map[string]cwhub.Item
		target_dir  string
	)
	cConfig = csconfig.NewConfig()

	//fill localConfig with default
	path := targetFile
	target_dir = filepath.Dir(targetFile)
	localConfig = ConfigTest{
		LogFile:            "acquis.log",
		ParseResultFile:    "parser_result.json",
		BucketInputFile:    "bucket_input.yaml",
		BucketResultFile:   "bucket_result.json",
		PoInputFile:        "po_input.yaml",
		PoResultFile:       "postoverflow_result.json",
		ReprocessInputFile: "",
		IndexFile:          ".index.json",
		target_dir:         target_dir,
	}
	fcontent, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("failed to read config file: %s", err)
	}
	err = yaml.Unmarshal(fcontent, &localConfig)
	if err != nil {
		log.Fatalf("failed unmarshaling config: %s", err)
	}

	//Minimal configuration loading
	//TODO move this to a specific function
	cConfig.API = &csconfig.APICfg{}
	cConfig.ConfigPaths = &csconfig.ConfigurationPaths{
		ConfigDir:    "./config",
		DataDir:      "./data/",
		HubIndexFile: localConfig.IndexFile,
	}
	cConfig.Crowdsec = &csconfig.CrowdsecServiceCfg{
		AcquisitionFilePath: target_dir + "/acquis.yaml",
	}

	log.Printf("Acquisition file : %s", target_dir+"/acquis.yaml")

	err = cConfig.LoadConfiguration()
	if err != nil {
		log.Fatalf("Failed to load configuration : %s", err)
	}

	err = exprhelpers.Init()
	if err != nil {
		log.Fatalf("Failed to init expr helpers : %s", err)
	}

	//Load index file
	buf, err := ioutil.ReadFile(localConfig.IndexFile)
	if err != nil {
		log.Fatalf("failed to read index file %s: %s", localConfig.IndexFile, err)
	}

	if index, err = cwhub.LoadPkgIndex(buf); err != nil {
		log.Fatalf("failed to read index file: %s", err)
	}

	csParsers := newParsers(index, localConfig)

	if csParsers, err = parser.LoadParsers(cConfig, csParsers); err != nil {
		log.Fatalf("Failed to load parsers: %s", err)
	}

	files = newBuckets(index, localConfig)
	log.Infof("scenarios files: %+v", files)
	log.Infof("Loading %d scenario files", len(files))

	buckets = leaky.NewBuckets()
	holders, outputEventChan, err = leaky.LoadBuckets(cConfig.Crowdsec, files)

	failure := false
	if _, ok := localConfig.Configurations["parsers"]; ok {
		err := testParser(filepath.Dir(targetFile), csParsers, cConfig, localConfig)
		if err != nil {
			log.Errorf("Error: %s", err)
			failure = true
		}
		if flags.JUnitFilename != "" {
			report.AddSingleResult(cwhub.PARSERS, err, strings.Join(localConfig.Configurations[cwhub.PARSERS], ", "))
		}
	}

	_, scenarios := localConfig.Configurations["scenarios"]
	if scenarios {
		err = testBuckets(filepath.Dir(targetFile), cConfig, localConfig)
		if err != nil {
			log.Errorf("Error: %s", err)
			failure = true
		}
		if flags.JUnitFilename != "" {
			report.AddSingleResult(cwhub.SCENARIOS, err, strings.Join(localConfig.Configurations[cwhub.SCENARIOS], ", "))
		}
	}

	_, ok := localConfig.Configurations["postoverflows"]
	if ok || localConfig.ReprocessInputFile != "" && scenarios {
		err = testPwfl(filepath.Dir(targetFile), csParsers, localConfig)
		if err != nil {
			log.Errorf("Error: %s", err)
			failure = true
		}
		if flags.JUnitFilename != "" {
			report.AddSingleResult(cwhub.PARSERS_OVFLW, err, strings.Join(localConfig.Configurations[cwhub.PARSERS_OVFLW], ", "))
		}
	}
	log.Infof("tests are finished.")
	return localConfig.Configurations, failure
}
