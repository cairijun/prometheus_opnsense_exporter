package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var pkgVersion = "dev"

type cmdOptions struct {
	opnsenseConfig string
	httpBind       string
	httpPath       string
	tlsServerCert  string
	tlsClientCA    string
	version        bool
}

func parseCmdOptions() cmdOptions {
	o := cmdOptions{opnsenseConfig: "/conf/config.xml", httpBind: ":8080", httpPath: "/metrics"}
	flag.StringVar(&o.opnsenseConfig, "opnsense.config", o.opnsenseConfig,
		"path to OPNsense's config.xml")
	flag.StringVar(&o.httpBind, "http.bind", o.httpBind,
		"address and port on which to bind")
	flag.StringVar(&o.httpPath, "http.path", o.httpPath,
		"http path on which to serve")
	flag.StringVar(&o.tlsServerCert, "tls.server-cert", o.tlsServerCert,
		"TLS server certificate (/opnsense/cert/refid in the OPNsense config)")
	flag.StringVar(&o.tlsClientCA, "tls.client-ca", o.tlsClientCA,
		"Trusted CA of client certificates (/opnsense/ca/refid in the OPNsense config)")
	flag.BoolVar(&o.version, "version", false, "print version")
	flag.Parse()
	return o
}

func registerMetrics(opnConf *OPNsenseConfig) {
	ifaceEnableGauges := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: PromNamespace,
		Subsystem: "interface",
		Name:      "enable",
		Help:      "Whether an interface is enabled or not",
	}, []string{"interface", "desc"})
	ifaceToDesc := make(map[string]string)
	for _, iface := range opnConf.ListInterfaces() {
		enableGauge := ifaceEnableGauges.WithLabelValues(iface.If, iface.Descr)
		if iface.Enable {
			enableGauge.Set(1)
			ifaceToDesc[iface.If] = iface.Descr
			log.Printf("Interface: %s -> %s", iface.If, iface.Descr)
		} else {
			enableGauge.Set(0)
			log.Printf("Interface (disabled): %s -> %s", iface.If, iface.Descr)
		}
	}

	prometheus.MustRegister(ifaceEnableGauges)
	prometheus.MustRegister(NewPfStatsCollector(ifaceToDesc))
}

func runServer(options *cmdOptions, opnConf *OPNsenseConfig) {
	http.Handle(options.httpPath, promhttp.Handler())

	server := http.Server{Addr: options.httpBind}
	if options.tlsServerCert != "" {
		certPem, keyPem, descr, err := opnConf.GetCertPairPem(options.tlsServerCert)
		if err != nil {
			log.Fatalf("Failed to load server certificate '%s': %v", options.tlsServerCert, err)
		}
		cert, err := tls.X509KeyPair(certPem, keyPem)
		if err != nil {
			log.Fatalf("Failed to load server certificate '%s': %v", options.tlsServerCert, err)
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
		}
		log.Printf("Using server certificate '%s' (%s)", descr, options.tlsServerCert)
	}
	if options.tlsClientCA != "" {
		if server.TLSConfig == nil {
			log.Fatal("Server certificate not specified for client authentication")
		}
		caPem, descr, err := opnConf.GetCACertPem(options.tlsClientCA)
		if err != nil {
			log.Fatalf("Failed to load client CA '%s': %v", options.tlsClientCA, err)
		}
		server.TLSConfig.ClientCAs = x509.NewCertPool()
		if !server.TLSConfig.ClientCAs.AppendCertsFromPEM(caPem) {
			log.Fatalf("Failed to load client CA '%s'", options.tlsClientCA)
		}
		server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		log.Printf("Verifying client certificates using '%s' (%s)", descr, options.tlsClientCA)
	}

	log.Printf("Serve at %s%s", options.httpBind, options.httpPath)
	if server.TLSConfig != nil {
		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}

func main() {
	options := parseCmdOptions()
	if options.version {
		println(pkgVersion)
		return
	}
	log.SetFlags(LoggerFlags)

	if options.opnsenseConfig == "" {
		log.Panic("OPNsense config file not specified")
	}
	opnConf, err := ParseOPNsenseConfig(options.opnsenseConfig)
	if err != nil {
		log.Panicf("Failed to parse %s: %v", options.opnsenseConfig, err)
	}

	registerMetrics(opnConf)
	runServer(&options, opnConf)
}
