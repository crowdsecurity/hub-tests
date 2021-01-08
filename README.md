# hub and hub-tests

This repository hosting the software tool used for testing each
configurations hosted in the [hub](https://hub.crowdsec.net) or in its
[repository](https://github.com/crowdsecurity/hub/). More precisely,
each configuration item consists of a yaml configuration file used to
describe crowdsec behaviour. The format of the configuration item
depends the type of configuration item. There're two types of
configuration item:
* parser (for parsers and postoverflows)
* scenarios 

# Hub and continuous integration

Each changes in the [hub](https://github.com/crowdsecurity/hub)
repository, in the
[hub-tests](https://github.com/crowdsecurity/hub-tests) repository or
in the [crowdsec](https://github.com/crowdsecurity/crowdsec)
repository fires a continuous integration test.

For now, these changes on mastere branches are carelessly pushed on
our [github pages](https://crowdsecurity.github.io/hub/)

## Create tests

### Create a basic test

To create such a test you'll need the the configuration item and
follow the steps:
1. Clone the [hub](https://github.com/crowdsecurity/hub) repository.
2. Put the configuration in the right place `<type>/<stage>/<provider name>/<configuration item>.yaml`
3. Run `./tests.sh -i` to init the tool and `./tests.sh -g
   <type>/<stage>/<provider name>/<configuration item>.yaml` to create
   a skeleton test.
4. The precedent step created a `config.yaml` file in a directory
`<item type>/<stage name>/<provider name>/.tests/<configuration
name>`. You have to store logs in this directory to trigger the tested
configuration item. The easiest way to do so is to craft a
`parser_input.yaml` marshaled file representing a list of events
([types.Events
](https://github.com/crowdsecurity/crowdsec/blob/eda9c03c82a2aa35d07053986c3d70fe15dd4b4e/pkg/types/event.go#L17)). (if
you are creating a test for a postoverflow, the file would be
po_input.yaml, and if you are creating a scenario the file is
bucket_input.yaml)) You can help you with already existing tests to
get inspiration.
5. Check the `config.yaml` file (defaults should be ok)
6. Run `./tests.sh --single <item type>/<stage name>/<provider
   name>/.tests/<configuration name>`. When run the first time, this
   will create a result file that will be used to compare results with
   all the following run. If you're happy with it, you can now create
   a pull request to merge the configuration item alonside with all
   the files needed to test it.

# How the tests work

## Directory tree

Each `config.yaml` in the hub repository subdirectories trigger a
test. It's meant to be stored in under a directory: `<item
type>/<stage name if applicable>/<provider name>/.tests/<configuration name>/config.yaml`

Example:
The first written test was for `crowdsecurity/sshd-logs`. This sshd configuration is `./parsers/s01-parse/crowdsecurity/sshd-logs.yaml`, thus the test should takes place in the directory `./parsers/s01-parse/crowdsecurity/.tests/sshd-logs`. The test configuration file named `config.yaml`is in this directory.

## configuration file format

```
parser_input: parser_input.yaml
parser_results: parser_results.yaml
bucket_input: bucket_input.yaml                 #unused in our example
bucket_results: bucket_result.json              #unused in our example
postoverflow_input: postoverflow_input.yaml     #unused in our example
postoverflow_results: postoverflow_results.yaml #unused in our example
reprocess: true

#configuration
index: "./config/hub/.index.json"
configurations:      
  parsers:
  - crowdsecurity/sshd-logs
  - crowdsecurity/syslog-logs
```

### File involved for the test
The paths of these of files are defined from the same directory as the config.yaml
* `parser_input.yaml`: file holding serialized events fed to the parser engine. If this configuration field is empty or missing, hub-tests will look for an `acquis.yaml` in the test directory, and will follow its directive.
* `parser_results.yaml`: file holding parser result. The test results will be compared to this file, and fail if it differs. If the file doesn't exist, it is automatically generated (this is useful to create a new test). 
* `bucket_input.yaml`: file holding serialized bucket input. It's automatically generated from parsing. This is a serialized list of events.
* `bucket_results.jdon`: same as parser_result.json, this file holds the bucket output. 
* `postoverflow_input.yaml`: same as bucket input, this file holds the serialized output of the scenarios. This is a serialized list of events.
* `postoverflow_results.json`: same as parser result, this file holds the postoverflow result.
* `reprocess`: make it true if you expect some reprocess to
  happen. Useful only for buckets test. If scenarios are enabled, it
  enforces postoverflows to pass even if no postoverflow is
  configured, to be able to repour it in the buckets.

### Other part of the configuration
* `index`: where to find the `.index.json` from the root directory of the hub repository
* `configurations`: This is dict of lists of configurations we want to load. Valid keys for the dict are `parsers`, `scenarios` and `postoverflows`. 

### Caveats or known bugs
For now a config directory is still needed with:
 * `simulation.yaml` this file can be empty
 * patterns directory with all parsers/groks patterns
 * `config/hub/.index.json` I suspect a small bug in pkg/cwversion that makes this requirement happen.

# Howto creation of a new configuration test

In the root of hub repository there's a `tests.sh` provided as a tool to help write some tests.
```
./tests.sh                                                                                                                          16:56
Usage:
    ./tests.sh -h|--help                        Display this help message.
    ./tests.sh -i                               Init tests : prepare env tests
    ./tests.sh -g <CONFIG_PATH/name.yaml>       Generate new test by specifying target config (parser|scenario|postoverflow)
    ./tests.sh --all                            Run all tests
    ./tests.sh --single <MYPATH/config.yaml>    Run single test
```

To write a new test on a pristine repository:
 ```
./tests.sh -i
./tests.sh -g <path to the item configuration yaml>
```
It'll create the needed .tests directory.

