package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"psophos/utils"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	name     = "sophos"
	category = "av"
)

var (
	path string
)

// Sophos json object
type Sophos struct {
	Results ResultsData `json:"analysis" structs:"analysis"`
}

// ResultsData json object
type ResultsData struct {
	Infected bool   `json:"infected" structs:"infected"`
	Result   string `json:"result" structs:"result"`
	Engine   string `json:"engine" structs:"engine"`
	Database string `json:"database" structs:"database"`
	Updated  string `json:"updated" structs:"updated"`
	Error    string `json:"error" structs:"error"`
}

// AvScan performs antivirus scan
func AvScan(timeout int) Sophos {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	var results ResultsData

	output, err := utils.RunCommand(ctx, "/opt/sophos/bin/savscan", "-f", "-ss", path)
	if err != nil && err.Error() != "exit status 3" {
		output, err = utils.RunCommand(ctx, "/opt/sophos/bin/savscan", "-f", "-ss", path)
		if err != nil {
			log.Debug(errors.Wrap(err, "Error while trying to run scan command"))
		}
	}

	results = ParseSophosOutput(output, err)

	return Sophos{
		Results: results,
	}
}

// ParseSophosOutput convert sophos output into ResultsData struct
func ParseSophosOutput(sophosout string, err error) ResultsData {

	version, database := getSophosVersion()

	sophosResults := ResultsData{
		Infected: false,
		Engine:   version,
		Database: database,
		Updated:  getUpdatedDate(),
		Error:    "nil",
	}

	if err != nil && err.Error() != "exit status 3" {
		sophosResults.Error = err.Error()
		return sophosResults
	}

	lines := strings.Split(sophosout, "\n")

	for _, line := range lines {
		if strings.Contains(line, ">>> Virus") && strings.Contains(line, "found in file") {
			parts := strings.Split(line, "'")
			sophosResults.Result = strings.TrimSpace(parts[1])
			sophosResults.Infected = true
		}
	}

	return sophosResults
}

// Get Anti-Virus scanner version
func getSophosVersion() (version string, database string) {

	versionOut, err := utils.RunCommand(nil, "/opt/sophos/bin/savscan", "--version")
	if err != nil {
		versionOut = "version error"
	}

	return parseSophosVersion(versionOut)
}

func parseSophosVersion(versionOut string) (version string, database string) {

	lines := strings.Split(versionOut, "\n")

	for _, line := range lines {
		if strings.Contains(line, "Product version") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				version = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(line, "Virus data version") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				database = strings.TrimSpace(parts[1])
				break
			}
		}
	}

	return
}

func parseUpdatedDate(date string) string {
	layout := "Mon, 02 Jan 2006 15:04:05 +0000"
	t, err := time.Parse(layout, date)
	if err != nil {
		log.Debug(errors.Wrap(err, "Error while parsing time"))
	}
	return fmt.Sprintf("%d%02d%02d", t.Year(), t.Month(), t.Day())
}

func getUpdatedDate() string {
	if _, err := os.Stat("/var/log/malscan/updated.log"); os.IsNotExist(err) {
		return ""
	}

	updated, err := ioutil.ReadFile("/var/log/malscan/updated.log")
	if err != nil {
		updated = []byte("updated error")
	}
	return string(updated)
}

func updateAV(ctx context.Context) error {

	output, err := utils.RunCommand(ctx, "/opt/sophos/update/savupdate.sh", "-v", "5")
	if err != nil {
		fmt.Println(1)
		log.Debug(errors.Wrap(err, "Error while running update command"))
		return err
	}

	if strings.Contains(output, "SOPHOS source") {
		fmt.Println(0)
	} else {
		fmt.Println(1)
	}

	// Update updated.log file
	t := time.Now().Format("20060102")
	err = ioutil.WriteFile("/var/log/malscan/updated.log", []byte(t), 0644)
	if err != nil {
		log.Debug(errors.Wrap(err, "Error while writing to updated.log"))
	}
	return err
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = name
	app.Usage = "Malscan Sophos AntiVirus Plugin"
	app.Version = "1.0.0"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "debug output",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  900,
			Usage:  "Malscan plugin timeout (in seconds)",
			EnvVar: "MALSCAN_TIMEOUT",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:    "update",
			Aliases: []string{"u"},
			Usage:   "Update virus definitions",
			Action: func(c *cli.Context) error {
				ctx, cancel := context.WithTimeout(
					context.Background(),
					time.Duration(c.GlobalInt("timeout"))*time.Second,
				)
				defer cancel()

				return updateAV(ctx)
			},
		},
	}
	app.Action = func(c *cli.Context) error {

		if c.Bool("debug") {
			log.SetLevel(log.DebugLevel)
		}

		if c.Args().Present() {
			path, _ = filepath.Abs(c.Args().First())

			sophos := AvScan(c.Int("timeout"))

			// convert to JSON
			sophosJSON, _ := json.Marshal(sophos)

			fmt.Println(string(sophosJSON))

		}
		return nil
	}

	app.Run(os.Args)

}
