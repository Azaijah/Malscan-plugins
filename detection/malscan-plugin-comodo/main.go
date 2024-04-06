package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pcomodo/utils"

	"github.com/levigross/grequests"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const (
	name     = "comodo"
	category = "av"
)

var (
	path string
)

// ResultsData json object
type ResultsData struct {
	Infected bool   `json:"infected" structs:"infected"`
	Result   string `json:"result" structs:"result"`
	Engine   string `json:"engine" structs:"engine"`
	Updated  string `json:"updated" structs:"updated"`
	Error    string `json:"error" structs:"error"`
}

// Comodo json object
type Comodo struct {
	Results ResultsData `json:"analysis" structs:"analysis"`
}

// AvScan performs antivirus scan
func AvScan(timeout int) Comodo {

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	output, err := utils.RunCommand(ctx, "/opt/COMODO/cmdscan", "-v", "-s", path)

	if err != nil {
		log.Debug(errors.Wrap(err, "Error while running scan command"))
	}

	return Comodo{
		Results: ParseComodoOutput(output, err),
	}
}

// ParseComodoOutput convert comodo output into ResultsData struct
func ParseComodoOutput(comodoout string, err error) ResultsData {

	comodo := ResultsData{
		Infected: false,
		Engine:   getComodoVersion(),
		Error:    "nil",
	}

	if err != nil {
		comodo.Error = err.Error()
		return comodo
	}

	lines := strings.Split(comodoout, "\n")

	// Extract Virus string
	if len(lines[1]) != 0 {
		if strings.Contains(lines[1], "Found Virus") {
			result := extractVirusName(lines[1])
			comodo.Result = result
			comodo.Infected = true
			return comodo
		}
	}

	return comodo
}

// extractVirusName extracts Virus name from scan results string
func extractVirusName(line string) string {
	keyvalue := strings.Split(line, "is")
	return strings.TrimSpace(keyvalue[1])
}

func updateAV() error {

	response, err := grequests.Get("http://download.comodo.com/av/updates58/sigs/bases/bases.cav", nil)
	if err != nil {
		fmt.Println(1)
		log.Debug(errors.Wrap(err, "Error while requesting bases.cav"))

		return err
	}

	if response.Ok != true {
		fmt.Println(1)
		log.Debug(errors.Wrap(err, "Error from reponse"))
		return err
	}

	if err = response.DownloadToFile("/opt/COMODO/scanners/bases.cav"); err != nil {
		log.Println(1)
		log.Debug(errors.Wrap(err, "Error while trying to download bases.cav"))
		return err
	}
	fmt.Println(0)

	// Update UPDATED file
	t := time.Now().Format("20060102")
	err = ioutil.WriteFile("/var/log/malscan/updated.log", []byte(t), 0644)
	if err != nil {
		log.Debug(errors.Wrap(err, "Error while trying write to updated.log"))
	}
	return err
}

func getComodoVersion() string {
	file, _ := os.Open("/opt/COMODO/etc/COMODO.xml")

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "<ProductVersion>") {
			versionOut := strings.TrimSpace(strings.Replace(strings.Replace(line, "<ProductVersion>", "", 1), "</ProductVersion>", "", 1))
			return versionOut
		}
	}
	return "version error"
}

func getUpdatedDate() string {
	if _, err := os.Stat("/var/log/malscan/updated.log"); os.IsNotExist(err) {
		return "nil"
	}
	updated, err := ioutil.ReadFile("/var/log/malscan/updated.log")
	if err != nil {
		updated = []byte("updated error")
	}

	return string(updated)
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "comodo"
	app.Usage = "Malscan comodo plugin"
	app.Version = "1.0.0"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug, d",
			Usage: "verbose output",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  900,
			Usage:  "malcan plugin timeout (in seconds)",
			EnvVar: "MALSCAN_TIMEOUT",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:    "update",
			Aliases: []string{"u"},
			Usage:   "Update virus definitions",
			Action: func(c *cli.Context) error {

				return updateAV()
			},
		},
	}

	app.Action = func(c *cli.Context) error {

		if c.Bool("debug") {
			log.SetLevel(log.DebugLevel)
		}

		if c.Args().Present() {
			path, _ = filepath.Abs(c.Args().First())

			comodo := AvScan(c.Int("timeout"))

			// convert to JSON
			comodoJSON, _ := json.Marshal(comodo)

			fmt.Println(string(comodoJSON))

		}
		return nil
	}

	app.Run(os.Args)

}
