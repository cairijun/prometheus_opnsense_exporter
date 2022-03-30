package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

type PfStatsCollector struct {
	ifaceToDesc map[string]string

	fieldNameToDescs map[string]pfStatsDescs

	reIfaceLine *regexp.Regexp
	reStatsLine *regexp.Regexp
}

func NewPfStatsCollector(ifaceToDesc map[string]string) *PfStatsCollector {
	c := &PfStatsCollector{
		ifaceToDesc:      ifaceToDesc,
		fieldNameToDescs: make(map[string]pfStatsDescs),
		reIfaceLine:      regexp.MustCompile(`^\S+`),
		reStatsLine:      regexp.MustCompile(`^\s+([\w\/]+):\s*\[\s*Packets:\s*(\d+)\s*Bytes:\s*(\d+)\s*\]`),
	}
	for _, dir := range []string{"In", "Out"} {
		for _, af := range []string{"4", "6"} {
			for _, action := range []string{"Pass", "Block"} {
				fieldName := fmt.Sprintf("%s%s/%s", dir, af, action)
				constLabels := prometheus.Labels{
					"dir": dir, "af": "IPv" + af, "action": action,
				}
				c.fieldNameToDescs[fieldName] = newPfStatsDescs(constLabels)
			}
		}
	}
	return c
}

func (c *PfStatsCollector) Describe(dst chan<- *prometheus.Desc) {
	for _, descs := range c.fieldNameToDescs {
		dst <- descs.bytes
		dst <- descs.packets
	}
}

func (c *PfStatsCollector) Collect(dst chan<- prometheus.Metric) {
	cmd := exec.Command("pfctl", "-vvsInterface")
	cmdOut, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("Failed to create stdout pipe: %v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		log.Printf("Failed to run pfctl: %v", err)
		return
	}
	defer cmd.Wait()
	if err := c.parseAndGenMetrics(cmdOut, dst); err != nil {
		log.Printf("Failed to parse and generate metrics: %v", err)
		return
	}
}

func (c *PfStatsCollector) parseAndGenMetrics(
	pfCtlOut io.Reader, dst chan<- prometheus.Metric) error {
	scanner := bufio.NewScanner(pfCtlOut)
	currIface := ""
	for scanner.Scan() {
		line := scanner.Text()
		if iface := c.reIfaceLine.FindString(line); iface != "" {
			currIface = iface
			continue
		}
		desc, interested := c.ifaceToDesc[currIface]
		if !interested {
			continue
		}
		stats := c.reStatsLine.FindStringSubmatch(line)
		if stats == nil {
			continue
		}
		if len(stats) != 4 {
			panic("c.reStatsLine should have exactly 4 capturing groups")
		}
		fieldName, packetsStr, bytesStr := stats[1], stats[2], stats[3]
		descs, ok := c.fieldNameToDescs[fieldName]
		if !ok {
			continue
		}
		if packets, err := strconv.ParseUint(packetsStr, 10, 64); err == nil {
			dst <- prometheus.MustNewConstMetric(
				descs.packets, prometheus.CounterValue, WrapUint64(packets), currIface, desc)
		} else {
			dst <- prometheus.NewInvalidMetric(descs.packets, err)
		}
		if bytes, err := strconv.ParseUint(bytesStr, 10, 64); err == nil {
			dst <- prometheus.MustNewConstMetric(
				descs.bytes, prometheus.CounterValue, WrapUint64(bytes), currIface, desc)
		} else {
			dst <- prometheus.NewInvalidMetric(descs.bytes, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error occurred when reading pfctl output: %w", err)
	}
	return nil
}

type pfStatsDescs struct {
	packets *prometheus.Desc
	bytes   *prometheus.Desc
}

func newPfStatsDescs(constLabels prometheus.Labels) pfStatsDescs {
	return pfStatsDescs{
		packets: prometheus.NewDesc(
			prometheus.BuildFQName(PromNamespace, "pfstats", "packets"),
			"Number of packets processed by pf",
			[]string{"interface", "desc"},
			constLabels),
		bytes: prometheus.NewDesc(
			prometheus.BuildFQName(PromNamespace, "pfstats", "bytes"),
			"Number of bytes processed by pf",
			[]string{"interface", "desc"},
			constLabels),
	}
}
