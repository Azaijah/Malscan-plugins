package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"capa/utils"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	name     = "capa"
	category = "av"
)

// Path to file
var (
	path string
)

// ResultsData - holds scan results
type ResultsData struct {
	Rules []string `json:"rules,omitempty" structs:"rules"`
	Error string   `json:"error" structs:"error"`
}

// floss - holds full set of results
type floss struct {
	Results ResultsData `json:"analysis" structs:"analysis"`
}

// scanFile scans file with all floss rules in the rules folder
func scanFile(ctx context.Context, all bool) floss {

	flossResults := floss{}

	output, err := exec.CommandContext(ctx, "/opt/capa", "-q", "-j", path).Output()
	if ctx.Err() == context.DeadlineExceeded {
		return floss{ResultsData{Error: "timeout"}}
	}
	if err != nil {
		return floss{ResultsData{Error: "cmd failed: /opt/capa" + path}}
	}

	flossResults.Results = parseFlossOutput(output, all)

	return flossResults
}

func parseFlossOutput(flossOutput []byte, all bool) (results ResultsData) {

	var rules map[string]map[string]map[string]map[string]string

	err := json.Unmarshal(flossOutput, &rules)
	if err != nil {
		log.Debug(errors.Wrap(err, "Error while unmarshaling summary manalyze output"))
	}

	for key, _ := range rules["rules"] {
		results.Rules = append(results.Rules, fmt.Sprintf("%s - %s", key, rules["rules"][key]["meta"]["namespace"]))
	}

	return results
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "capa"
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
