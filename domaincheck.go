package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/domainr/whois"
)

// Expiration Regex
var expirationRegexp = regexp.MustCompile("expiration(?:\\sdate)?[:]\\s(?P<expiration_date>.*)")

var dateFormats = []string{
	"01/02/2006",
	"02-Jan-2006",
	"01-02-2006",
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("No domains specified")
		os.Exit(1)
	}
	domain := os.Args[1]
	fmt.Printf("Checking %s...\n", domain)

	expirydate, err := getDomainExpiry(domain)
	if err == nil {
		duration := time.Since(expirydate)
		fmt.Printf("Expires %s, in %f days\n", expirydate, (-1 * duration.Hours() / 24))
	} else {
		fmt.Printf("Error while querying %s: %s\n", domain, err)
	}
}

func convertDomainDate(date string) (time.Time, error) {
	for _, v := range dateFormats {
		test, err := time.Parse(v, date)
		if err == nil {
			return test, nil
		}
	}
	return time.Time{}, errors.New("No conversion format found for " + date)
}

func getDomainExpiry(domain string) (time.Time, error) {
	request, _ := whois.NewRequest(domain)
	response, _ := whois.DefaultClient.Fetch(request)
	match := expirationRegexp.FindAllStringSubmatch(strings.ToLower(response.String()), -1)
	if match == nil {
		return time.Time{}, errors.New("No domain found")
	}
	var expdate = match[0][1]
	date, err := convertDomainDate(expdate)
	return date, err
}
