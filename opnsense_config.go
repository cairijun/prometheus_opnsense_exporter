package main

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

type OPNsenseConfig struct {
	conf opnConf
}

type OPNsenseConfigInterface struct {
	If     string
	Descr  string
	Enable bool
}

func ParseOPNsenseConfig(xmlFile string) (*OPNsenseConfig, error) {
	fileContent, err := os.ReadFile(xmlFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", xmlFile, err)
	}
	result := new(OPNsenseConfig)
	if err := xml.Unmarshal(fileContent, &result.conf); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", xmlFile, err)
	}
	return result, nil
}

func (c *OPNsenseConfig) ListInterfaces() (result []OPNsenseConfigInterface) {
	for _, iface := range c.conf.Interfaces.List {
		descr := iface.Descr
		if descr == "" {
			descr = strings.ToUpper(iface.XMLName.Local)
		}
		result = append(result, OPNsenseConfigInterface{
			If:     iface.If,
			Descr:  descr,
			Enable: iface.Enable,
		})
	}
	return
}

func (c *OPNsenseConfig) GetCACertPem(refId string) (pem []byte, descr string, err error) {
	ca := c.findCA(refId)
	if ca == nil {
		return nil, "", fmt.Errorf("CA '%s' not found", refId)
	}
	descr = ca.Descr
	pem, err = base64.StdEncoding.DecodeString(ca.Crt)
	return
}

func (c *OPNsenseConfig) GetCertPairPem(refId string) (
	certChain []byte, key []byte, descr string, err error) {
	for _, cert := range c.conf.Certs {
		if cert.RefId != refId {
			continue
		}
		descr = cert.Descr

		if certChain, err = base64.StdEncoding.DecodeString(cert.Crt); err != nil {
			return nil, nil, "", fmt.Errorf("failed to decode the certificate: %w", err)
		}
		caRefId := cert.CaRef
		for caRefId != "" { // TODO: loop detection
			ca := c.findCA(caRefId)
			if ca == nil {
				return nil, nil, "", fmt.Errorf("CA '%s' not found", caRefId)
			}
			if caPem, err := base64.StdEncoding.DecodeString(ca.Crt); err != nil {
				return nil, nil, "", fmt.Errorf("failed to decode CA '%s': %w", caRefId, err)
			} else {
				certChain = append(certChain, caPem...)
				caRefId = ca.CaRef
			}
		}

		if key, err = base64.StdEncoding.DecodeString(cert.Prv); err != nil {
			return nil, nil, "", fmt.Errorf("failed to decode the private key: %w", err)
		}
		return
	}
	return nil, nil, "", fmt.Errorf("certificate '%s' not found", refId)
}

func (c *OPNsenseConfig) findCA(refId string) *opnConfCert {
	for _, ca := range c.conf.CAs {
		if ca.RefId == refId {
			return &ca
		}
	}
	return nil
}

type opnConf struct {
	XMLName    xml.Name          `xml:"opnsense"`
	Interfaces opnConfInterfaces `xml:"interfaces"`
	CAs        []opnConfCert     `xml:"ca"`
	Certs      []opnConfCert     `xml:"cert"`
}

type opnConfInterfaces struct {
	List []opnConfInterface `xml:",any"`
}

type opnConfInterface struct {
	XMLName xml.Name
	If      string `xml:"if"`
	Descr   string `xml:"descr"`
	Enable  bool   `xml:"enable"`
}

type opnConfCert struct {
	RefId string `xml:"refid"`
	Descr string `xml:"descr"`
	Crt   string `xml:"crt"`
	Prv   string `xml:"prv"`
	CaRef string `xml:"caref"`
}
