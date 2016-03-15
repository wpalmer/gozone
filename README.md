# Simple DNS ZoneFile parser

Parse a DNS ZoneFile (as specified in https://www.ietf.org/rfc/rfc1035.txt)
into a series of more-easily-processed "Record" structures

Example:
```go
stream, _ := os.Open(zonefile)
var record gozone.Record
scanner := gozone.NewScanner(h)

for {
	err := scanner.Next(&record)
	if err != nil {
		break
	}

	fmt.Printf("a '%s' Record for domain/subdomain '%s'",
		record.Type,
		record.DomainName,
	)
}
```
