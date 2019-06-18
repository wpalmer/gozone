# Simple DNS ZoneFile parser

Parse a DNS ZoneFile (as specified in https://www.ietf.org/rfc/rfc1035.txt)
into a series of more-easily-processed "Record" structures.

The list of RecordTypes, their values, and meanings, was taken from
https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml,
which in turn references RFCs:
 - [RFC1035](https://www.ietf.org/rfc/rfc1035.txt)
 - [RFC1183](https://www.ietf.org/rfc/rfc1183.txt)
 - [RFC1348](https://www.ietf.org/rfc/rfc1348.txt)
 - [RFC1637](https://www.ietf.org/rfc/rfc1637.txt)
 - [RFC1706](https://www.ietf.org/rfc/rfc1706.txt)
 - [RFC1712](https://www.ietf.org/rfc/rfc1712.txt)
 - [RFC1876](https://www.ietf.org/rfc/rfc1876.txt)
 - [RFC1995](https://www.ietf.org/rfc/rfc1995.txt)
 - [RFC2163](https://www.ietf.org/rfc/rfc2163.txt)
 - [RFC2168](https://www.ietf.org/rfc/rfc2168.txt)
 - [RFC2230](https://www.ietf.org/rfc/rfc2230.txt)
 - [RFC2535](https://www.ietf.org/rfc/rfc2535.txt)
 - [RFC2536](https://www.ietf.org/rfc/rfc2536.txt)
 - [RFC2537](https://www.ietf.org/rfc/rfc2537.txt)
 - [RFC2539](https://www.ietf.org/rfc/rfc2539.txt)
 - [RFC2782](https://www.ietf.org/rfc/rfc2782.txt)
 - [RFC2845](https://www.ietf.org/rfc/rfc2845.txt)
 - [RFC2874](https://www.ietf.org/rfc/rfc2874.txt)
 - [RFC2915](https://www.ietf.org/rfc/rfc2915.txt)
 - [RFC2930](https://www.ietf.org/rfc/rfc2930.txt)
 - [RFC2931](https://www.ietf.org/rfc/rfc2931.txt)
 - [RFC3008](https://www.ietf.org/rfc/rfc3008.txt)
 - [RFC3110](https://www.ietf.org/rfc/rfc3110.txt)
 - [RFC3123](https://www.ietf.org/rfc/rfc3123.txt)
 - [RFC3225](https://www.ietf.org/rfc/rfc3225.txt)
 - [RFC3226](https://www.ietf.org/rfc/rfc3226.txt)
 - [RFC3403](https://www.ietf.org/rfc/rfc3403.txt)
 - [RFC3596](https://www.ietf.org/rfc/rfc3596.txt)
 - [RFC3658](https://www.ietf.org/rfc/rfc3658.txt)
 - [RFC3755](https://www.ietf.org/rfc/rfc3755.txt)
 - [RFC4025](https://www.ietf.org/rfc/rfc4025.txt)
 - [RFC4034](https://www.ietf.org/rfc/rfc4034.txt)
 - [RFC4255](https://www.ietf.org/rfc/rfc4255.txt)
 - [RFC4398](https://www.ietf.org/rfc/rfc4398.txt)
 - [RFC4431](https://www.ietf.org/rfc/rfc4431.txt)
 - [RFC4701](https://www.ietf.org/rfc/rfc4701.txt)
 - [RFC5155](https://www.ietf.org/rfc/rfc5155.txt)
 - [RFC5864](https://www.ietf.org/rfc/rfc5864.txt)
 - [RFC5936](https://www.ietf.org/rfc/rfc5936.txt)
 - [RFC6563](https://www.ietf.org/rfc/rfc6563.txt)
 - [RFC6672](https://www.ietf.org/rfc/rfc6672.txt)
 - [RFC6698](https://www.ietf.org/rfc/rfc6698.txt)
 - [RFC6742](https://www.ietf.org/rfc/rfc6742.txt)
 - [RFC6891](https://www.ietf.org/rfc/rfc6891.txt)
 - [RFC6895](https://www.ietf.org/rfc/rfc6895.txt)
 - [RFC7043](https://www.ietf.org/rfc/rfc7043.txt)
 - [RFC7208](https://www.ietf.org/rfc/rfc7208.txt)
 - [RFC7344](https://www.ietf.org/rfc/rfc7344.txt)
 - [RFC7477](https://www.ietf.org/rfc/rfc7477.txt)
 - [RFC7553](https://www.ietf.org/rfc/rfc7553.txt)
 - [RFC7929](https://www.ietf.org/rfc/rfc7929.txt)
 - [RFC8005](https://www.ietf.org/rfc/rfc8005.txt)
 - [RFC8162](https://www.ietf.org/rfc/rfc8162.txt)
 - [RFC8482](https://www.ietf.org/rfc/rfc8482.txt)


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
