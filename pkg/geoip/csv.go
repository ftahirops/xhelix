package geoip

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
)

// LoadCSVFile reads a CSV file at path with rows of the form:
//
//	1.2.3.0/24,US
//	1.2.3.0/24,US,AS12345,Acme ISP
//	2001:db8::/32,DE
//
// First column = CIDR. Second column = ISO country code. Optional 3rd
// and 4th columns = ASN and org. Lines starting with `#` are skipped,
// empty lines are skipped, malformed rows are silently skipped.
//
// Used to populate an InMemory provider from operator-supplied data.
// Convert MaxMind GeoLite2-Country-Blocks-IPv4.csv with:
//
//	awk -F, 'NR>1{print $1","$5}' GeoLite2-Country-Blocks-IPv4.csv \
//	  > /var/lib/xhelix/geoip/country.csv
//
// Missing file returns (nil, nil) — operators may run without GeoIP.
func LoadCSVFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fs := strings.Split(line, ",")
		if len(fs) < 2 {
			continue
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(fs[0]))
		if err != nil {
			continue
		}
		country := strings.ToUpper(strings.TrimSpace(fs[1]))
		if len(country) != 2 {
			continue
		}
		e := Entry{
			Prefix: prefix,
			Result: Result{Country: country},
		}
		if len(fs) >= 3 {
			e.Result.ASN = strings.TrimSpace(fs[2])
		}
		if len(fs) >= 4 {
			e.Result.ASNOrg = strings.TrimSpace(fs[3])
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
