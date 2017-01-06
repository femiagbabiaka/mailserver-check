package main

import (
	"net"
	"flag"
	"fmt"
	"os"
	"github.com/fatih/color"
)

const helpDocs = 
`mailserver-check

Takes a mailserver domain, checks relevant records for that domain, and returns the records as well
as whether they were found or not.
Commands:`

type mailserverRecordSet struct {
	MX []*net.MX
	ipAddress []net.IP
	spfRecords []string
	reverseAddr []string
	dkimRecord []string
}

var mailserverDomain string



func init() {
	flag.StringVar(&mailserverDomain, "domain", "", "The domain whose records you want to check.")
}

func main() {
	flag.Parse();
	
	if mailserverDomain == "" {
		color.White(helpDocs)
		flag.PrintDefaults()
		os.Exit(1)
	}
	
	ipAddress := lookupIP(mailserverDomain)

	for i := range ipAddress {
		color.Red("ipAddresses: %+v\n", ipAddress[i])
	}

	
	mxRecords := lookupMX(mailserverDomain)

	for i := range mxRecords {
		color.Green("MX Records: %+v\n", mxRecords[i])
	}
	
	reverseAddr := lookupReverseAddr(ipAddress[0].String())
	
	for i := range reverseAddr {
		color.Blue("ReverseAddr: %+v\n", reverseAddr[i])
	}
	
	spfRecord := lookupSPF(mailserverDomain)

	for i := range spfRecord {
		color.Magenta("SPF Record: %+v\n", spfRecord[i])
	}
	
	dkimRecord := lookupDKIM(mailserverDomain)

	for i := range dkimRecord {
		color.Cyan("DKIM Record: %+v\n", dkimRecord[i])
	}

}

func lookupIP (domain string) []net.IP {
	ipAddress, err := net.LookupIP(domain)

	if err != nil {
		fmt.Printf("Can't find an IP address for domain %s. Lookup result: %s.\n", mailserverDomain, err)
	} 
	
	return ipAddress
}

func lookupMX (domain string) []*net.MX {
	mxRecords, err := net.LookupMX(domain) 
	
	if err != nil {
		fmt.Printf("Domain %s is missing MX records. Lookup result: %s\n", mailserverDomain, err)
	}
	
	return mxRecords
}

func lookupReverseAddr(ip string) []string {
	reverseAddr, err := net.LookupAddr(ip)
	
	if err != nil {
		fmt.Printf("Can't find a reverse lookup for the domain %s. Lookup result: %s.\n", mailserverDomain, err)
	}
	
	return reverseAddr
}

func lookupSPF(domain string) []string {
	spfRecord, err := net.LookupTXT(domain)
	
	if err != nil {
		fmt.Printf("Can't find any Text records for the domain %s, Lookup result: %s.\n", mailserverDomain, err)
	}
	
	return spfRecord
}

func lookupDKIM(domain string) []string {
	dkimRecord, err := net.LookupTXT(fmt.Sprintf("dk._domainkey.%s", domain))
	
	if err != nil {
		fmt.Printf("Can't find and DKIM records for the domain %s, Lookup result: %s.\n", mailserverDomain, err)
	}
	
	return dkimRecord
}
