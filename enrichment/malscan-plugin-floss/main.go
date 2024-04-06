package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/LiamHellend/malscan-plugin-floss/utils"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	name     = "floss"
	category = "av"
)

// Path to file
var (
	path string
)

// ResultsData - holds scan results
type ResultsData struct {
	Strings []string `json:"strings,omitempty" structs:"ascii_strings"`
	Error   string   `json:"error" structs:"error"`
}

type decodedStrings struct {
	Location string   `json:"location" structs:"location"`
	Strings  []string `json:"strings" structs:"strings"`
}

// floss - holds full set of results
type floss struct {
	Results ResultsData `json:"analysis" structs:"analysis"`
}

// scanFile scans file with all floss rules in the rules folder
func scanFile(ctx context.Context, all bool) floss {

	flossResults := floss{}

	output, err := exec.CommandContext(ctx, "/opt/floss", "--no-decoded-strings", "--no-stack-strings", "--minimum-length=8", "-g", path).Output()
	if ctx.Err() == context.DeadlineExceeded {
		return floss{ResultsData{Error: "timeout"}}
	}
	if err != nil {
		return floss{ResultsData{Error: "cmd failed: /opt/floss--no-decoded-strings --no-stack-strings --minimum-length=6 -g " + path}}
	}

	flossResults.Results = parseFlossOutput(string(output), all)

	return flossResults
}

func parseFlossOutput(flossOutput string, all bool) ResultsData {

	/*log.WithFields(log.Fields{
		"plugin":   name,
		"category": category,
		"path":     path,
	}).Debug("FLOSS Output: ", flossOutput)
	*/
	keepLines := []string{}
	results := ResultsData{Error: "nil"}

	lines := strings.Split(flossOutput, "\n")
	// remove empty lines
	for _, line := range lines {
		if len(strings.TrimSpace(line)) != 0 {
			keepLines = append(keepLines, strings.TrimSpace(line))
		}
	}

	// build results data
	for i := 0; i < len(keepLines); i++ {

		results.Strings = utils.RemoveDuplicates(getStrings(keepLines))

	}

	log.Debug(results)

	return results
}

func getStrings(strArray []string) []string {
	asciiStrings := []string{}
	for _, str := range strArray {
		if !strings.Contains(str, "FLOSS") {
			asciiStrings = append(asciiStrings, str)
		}

	}
	return asciiStrings
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "floss"
	app.Usage = "Malscan floss plugin"
	app.Version = "1.0.0"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "debug output",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  60,
			Usage:  "malcan plugin timeout (in seconds)",
			EnvVar: "MALSCAN_TIMEOUT",
		},
	}
	app.Action = func(c *cli.Context) error {

		if c.Bool("debug") {
			log.SetLevel(log.DebugLevel)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Int("timeout"))*time.Second)
		defer cancel()

		if c.Args().Present() {
			path, _ = filepath.Abs(c.Args().First())

			floss := scanFile(ctx, false)

			//Convert clamav results to json
			flossJSON, _ := json.Marshal(floss)

			//Print json results
			fmt.Println(string(flossJSON))

		}
		return nil
	}

	app.Run(os.Args)
}
