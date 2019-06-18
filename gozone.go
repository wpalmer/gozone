package gozone

// https://www.ietf.org/rfc/rfc1035.txt

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
)

type RecordClass int

const (
	RecordClass_UNKNOWN = 0   // unset
	RecordClass_IN      = 1   // the Internet
	RecordClass_CS      = 2   // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	RecordClass_CH      = 3   // the CHAOS class
	RecordClass_HS      = 4   // Hesiod [Dyer 87]
	RecordClass_any     = 255 // any class (spelled: *; appears only in the question section of a query; included for completeness)
)

func (rc RecordClass) String() string {
	switch rc {
	case RecordClass_IN:
		return "IN"
	case RecordClass_CS:
		return "CS"
	case RecordClass_CH:
		return "CH"
	case RecordClass_HS:
		return "HS"
	case RecordClass_any:
		return "*"
	}

	return "[UNKNOWN]"
}

type RecordType int

const (
	RecordType_UNKNOWN    = 0   // unset
	RecordType_A          = 1   // a host address
	RecordType_NS         = 2   // an authoritative name server
	RecordType_MD         = 3   // a mail destination (OBSOLETE - use MX)
	RecordType_MF         = 4   // a mail forwarder (OBSOLETE - use MX)
	RecordType_CNAME      = 5   // the canonical name for an alias
	RecordType_SOA        = 6   // marks the start of a zone of authority
	RecordType_MB         = 7   // a mailbox domain name (EXPERIMENTAL)
	RecordType_MG         = 8   // a mail group member (EXPERIMENTAL)
	RecordType_MR         = 9   // a mail rename domain name (EXPERIMENTAL)
	RecordType_NULL       = 10  // a null RR (EXPERIMENTAL)
	RecordType_WKS        = 11  // a well known service description
	RecordType_PTR        = 12  // a domain name pointer
	RecordType_HINFO      = 13  // host information
	RecordType_MINFO      = 14  // mailbox or mail list information
	RecordType_MX         = 15  // mail exchange
	RecordType_TXT        = 16  // text strings
	RecordType_RP         = 17  // for Responsible Person
	RecordType_AFSDB      = 18  // for AFS Data Base location
	RecordType_X25        = 19  // for X.25 PSDN address
	RecordType_ISDN       = 20  // for ISDN address
	RecordType_RT         = 21  // for Route Through
	RecordType_NSAP       = 22  // for NSAP address, NSAP style A record
	RecordType_NSAP_PTR   = 23  // spelled "NSAP-PTR", for domain name pointer, NSAP style
	RecordType_SIG        = 24  // for security signature
	RecordType_KEY        = 25  // for security key
	RecordType_PX         = 26  // X.400 mail mapping information
	RecordType_GPOS       = 27  // Geographical Position
	RecordType_AAAA       = 28  // IP6 Address
	RecordType_LOC        = 29  // Location Information
	RecordType_NXT        = 30  // Next Domain (OBSOLETE)
	RecordType_EID        = 31  // Endpoint Identifier
	RecordType_NIMLOC     = 32  // Nimrod Locator
	RecordType_SRV        = 33  // Server Selection
	RecordType_ATMA       = 34  // ATM Address
	RecordType_NAPTR      = 35  // Naming Authority Pointer
	RecordType_KX         = 36  // Key Exchanger
	RecordType_CERT       = 37  // CERT
	RecordType_A6         = 38  // A6 (OBSOLETE - use AAAA)
	RecordType_DNAME      = 39  // DNAME
	RecordType_SINK       = 40  // SINK
	RecordType_OPT        = 41  // OPT
	RecordType_APL        = 42  // APL
	RecordType_DS         = 43  // Delegation Signer
	RecordType_SSHFP      = 44  // SSH Key Fingerprint
	RecordType_IPSECKEY   = 45  // IPSECKEY
	RecordType_RRSIG      = 46  // RRSIG
	RecordType_NSEC       = 47  // NSEC
	RecordType_DNSKEY     = 48  // DNSKEY
	RecordType_DHCID      = 49  // DHCID
	RecordType_NSEC3      = 50  // NSEC3
	RecordType_NSEC3PARAM = 51  // NSEC3PARAM
	RecordType_TLSA       = 52  // TLSA
	RecordType_SMIMEA     = 53  // S/MIME cert association
	// Unassigned 54
	RecordType_HIP        = 55  // Host Identity Protocol
	RecordType_NINFO      = 56  // NINFO
	RecordType_RKEY       = 57  // RKEY
	RecordType_TALINK     = 58  // Trust Anchor LINK
	RecordType_CDS        = 59  // Child DS
	RecordType_CDNSKEY    = 60  // DNSKEY(s) the Child wants reflected in DS
	RecordType_OPENPGPKEY = 61  // OpenPGP Key
	RecordType_CSYNC      = 62  // Child-To-Parent Synchronization
	RecordType_ZONEMD     = 63  // message digest for DNS zone
	// Unassigned	64-98
	RecordType_SPF        = 99  // declares which hosts are, and are not, authorized to use a domain name for the "HELO" and "MAIL FROM" identities (OBSOLETE - use TXT)
	RecordType_UINFO      = 100 // [IANA-Reserved]
	RecordType_UID        = 101 // [IANA-Reserved]
	RecordType_GID        = 102 // [IANA-Reserved]
	RecordType_UNSPEC     = 103 // [IANA-Reserved]
	RecordType_NID        = 104 // values for Node Identifiers that will be used for ILNP-capable nodes
	RecordType_L32        = 105 // 32-bit Locator values for ILNPv4-capable nodes
	RecordType_L64        = 106 // unsigned 64-bit Locator values for ILNPv6-capable nodes
	RecordType_LP         = 107 // the name of a subnetwork for ILNP
	RecordType_EUI48      = 108 // an EUI-48 address
	RecordType_EUI64      = 109 // an EUI-64 address
	// Unassigned 110-248
	RecordType_TKEY       = 249 // Transaction Key
	RecordType_TSIG       = 250 // Transaction Signature
	RecordType_IXFR       = 251 // incremental transfer
	RecordType_AXFR       = 252 // transfer of an entire zone
	RecordType_MAILB      = 253 // mailbox-related RRs (MB, MG or MR)
	RecordType_MAILA      = 254 // mail agent RRs (OBSOLETE - see MX)
	RecordType_all        = 255 // Spelled "*", A request for some or all records the server has available
	RecordType_URI        = 256 // URI
	RecordType_CAA        = 257 // Certification Authority Restriction
	RecordType_AVC        = 258 // Application Visibility and Control
	RecordType_DOA        = 259 // Digital Object Architecture
	RecordType_AMTRELAY   = 260 // Automatic Multicast Tunneling Relay
	// Unassigned	261-32767
	RecordType_TA         = 32768 // DNSSEC Trust Authorities
	RecordType_DLV        = 32769 // DNSSEC Lookaside Validation
	// Unassigned	32770-65279
	// Private use	65280-65534
	// Reserved	65535
)

func (rt RecordType) String() string {
	switch rt {
	case RecordType_A:
		return "A"
	case RecordType_NS:
		return "NS"
	case RecordType_MD:
		return "MD"
	case RecordType_MF:
		return "MF"
	case RecordType_CNAME:
		return "CNAME"
	case RecordType_SOA:
		return "SOA"
	case RecordType_MB:
		return "MB"
	case RecordType_MG:
		return "MG"
	case RecordType_MR:
		return "MR"
	case RecordType_NULL:
		return "NULL"
	case RecordType_WKS:
		return "WKS"
	case RecordType_PTR:
		return "PTR"
	case RecordType_HINFO:
		return "HINFO"
	case RecordType_MINFO:
		return "MINFO"
	case RecordType_MX:
		return "MX"
	case RecordType_TXT:
		return "TXT"
	case RecordType_RP:
		return "RP"
	case RecordType_AFSDB:
		return "AFSDB"
	case RecordType_X25:
		return "X25"
	case RecordType_ISDN:
		return "ISDN"
	case RecordType_RT:
		return "RT"
	case RecordType_NSAP:
		return "NSAP"
	case RecordType_NSAP_PTR:
		return "NSAP-PTR"
	case RecordType_SIG:
		return "SIG"
	case RecordType_KEY:
		return "KEY"
	case RecordType_PX:
		return "PX"
	case RecordType_GPOS:
		return "GPOS"
	case RecordType_AAAA:
		return "AAAA"
	case RecordType_LOC:
		return "LOC"
	case RecordType_NXT:
		return "NXT"
	case RecordType_EID:
		return "EID"
	case RecordType_NIMLOC:
		return "NIMLOC"
	case RecordType_SRV:
		return "SRV"
	case RecordType_ATMA:
		return "ATMA"
	case RecordType_NAPTR:
		return "NAPTR"
	case RecordType_KX:
		return "KX"
	case RecordType_CERT:
		return "CERT"
	case RecordType_A6:
		return "A6"
	case RecordType_DNAME:
		return "DNAME"
	case RecordType_SINK:
		return "SINK"
	case RecordType_OPT:
		return "OPT"
	case RecordType_APL:
		return "APL"
	case RecordType_DS:
		return "DS"
	case RecordType_SSHFP:
		return "SSHFP"
	case RecordType_IPSECKEY:
		return "IPSECKEY"
	case RecordType_RRSIG:
		return "RRSIG"
	case RecordType_NSEC:
		return "NSEC"
	case RecordType_DNSKEY:
		return "DNSKEY"
	case RecordType_DHCID:
		return "DHCID"
	case RecordType_NSEC3:
		return "NSEC3"
	case RecordType_NSEC3PARAM:
		return "NSEC3PARAM"
	case RecordType_TLSA:
		return "TLSA"
	case RecordType_SMIMEA:
		return "SMIMEA"
	case RecordType_HIP:
		return "HIP"
	case RecordType_NINFO:
		return "NINFO"
	case RecordType_RKEY:
		return "RKEY"
	case RecordType_TALINK:
		return "TALINK"
	case RecordType_CDS:
		return "CDS"
	case RecordType_CDNSKEY:
		return "CDNSKEY"
	case RecordType_OPENPGPKEY:
		return "OPENPGPKEY"
	case RecordType_CSYNC:
		return "CSYNC"
	case RecordType_ZONEMD:
		return "ZONEMD"
	case RecordType_SPF:
		return "SPF"
	case RecordType_UINFO:
		return "UINFO"
	case RecordType_UID:
		return "UID"
	case RecordType_GID:
		return "GID"
	case RecordType_UNSPEC:
		return "UNSPEC"
	case RecordType_NID:
		return "NID"
	case RecordType_L32:
		return "L32"
	case RecordType_L64:
		return "L64"
	case RecordType_LP:
		return "LP"
	case RecordType_EUI48:
		return "EUI48"
	case RecordType_EUI64:
		return "EUI64"
	case RecordType_TKEY:
		return "TKEY"
	case RecordType_TSIG:
		return "TSIG"
	case RecordType_IXFR:
		return "IXFR"
	case RecordType_AXFR:
		return "AXFR"
	case RecordType_MAILB:
		return "MAILB"
	case RecordType_MAILA:
		return "MAILA"
	case RecordType_all:
		return "*"
	case RecordType_URI:
		return "URI"
	case RecordType_CAA:
		return "CAA"
	case RecordType_AVC:
		return "AVC"
	case RecordType_DOA:
		return "DOA"
	case RecordType_AMTRELAY:
		return "AMTRELAY"
	case RecordType_TA:
		return "TA"
	case RecordType_DLV:
		return "DLV"
	}

	return "[UNKNOWN]"
}

type Record struct {
	DomainName string
	TimeToLive int64 // uint32, expanded and signed to allow for "unset" indicator
	Class      RecordClass
	Type       RecordType
	Data       []string
	Comment    string
}

func (r Record) String() string {
	spec := []string{r.DomainName}

	if r.TimeToLive != -1 {
		spec = append(spec, fmt.Sprintf("%d", r.TimeToLive))
	}

	if r.Class != RecordClass_UNKNOWN {
		spec = append(spec, r.Class.String())
	}

	if r.Type != RecordType_UNKNOWN {
		spec = append(spec, r.Type.String())
	}

	if len(r.Data) != 0 {
		spec = append(spec, strings.Join(r.Data, " "))
	}

	if len(r.Comment) != 0 {
		spec = append(spec, r.Comment)
	}

	return strings.Join(spec, " ")
}

type scannerState int

const (
	scannerState_Default = iota
	scannerState_String
	scannerState_StringEscape
	scannerState_Paren
	scannerState_Comment
	scannerState_Space
	scannerState_ParenComment
	scannerState_ParenString
	scannerState_ParenStringEscape
)

type Scanner struct {
	src      *bufio.Reader
	state    scannerState
	nextRune rune
	nextSize int
}

func NewScanner(src io.Reader) *Scanner {
	return &Scanner{
		src:      bufio.NewReader(src),
		nextRune: 0,
		nextSize: 0,
	}
}

func (s *Scanner) nextToken() (string, error) {
	var token bytes.Buffer

	var r rune
	var size int
	var err error
	for {
		if s.nextSize != 0 {
			r = s.nextRune
			size = s.nextSize
			s.nextSize = 0
		} else {
			r, size, err = s.src.ReadRune()
			if err != nil {
				if err == io.EOF {
					if s.state != scannerState_Default &&
						s.state != scannerState_Space &&
						s.state != scannerState_Comment {
						return "", errors.New("Unexpected end of input")
					}

					if token.Len() != 0 {
						return token.String(), nil
					}
				}

				return "", err
			}
		}

		s.nextRune = r
		s.nextSize = size

		switch s.state {
		case scannerState_Default, scannerState_Paren:
			if unicode.IsSpace(r) {
				if token.Len() > 0 {
					return token.String(), nil
				}

				if s.state == scannerState_Default {
					if r == '\n' {
						s.nextSize = 0
						s.state = scannerState_Space
						return "\n", nil
					}
				}

				// ignore whitespace between tokens
				s.nextSize = 0
				continue
			}

			if s.state == scannerState_Default {
				if r == '(' {
					if token.Len() > 0 {
						return token.String(), nil
					}

					s.nextSize = 0
					s.state = scannerState_Paren
					return "(", nil
				}
			} else if s.state == scannerState_Paren {
				if r == ')' {
					if token.Len() > 0 {
						return token.String(), nil
					}

					s.nextSize = 0
					s.state = scannerState_Default
					return ")", nil
				}
			}

			if r == '"' {
				if token.Len() > 0 {
					return token.String(), nil
				}

				s.nextSize = 0
				if s.state == scannerState_Default {
					s.state = scannerState_String
				} else {
					s.state = scannerState_ParenString
				}
				_, _ = token.WriteRune(r)
				continue
			}

			if r == ';' {
				if token.Len() > 0 {
					return token.String(), nil
				}

				s.nextSize = 0
				if s.state == scannerState_Default {
					s.state = scannerState_Comment
				} else {
					s.state = scannerState_ParenComment
				}
				_, _ = token.WriteRune(r)
				continue
			}

			s.nextSize = 0
			_, _ = token.WriteRune(r)

		case scannerState_String, scannerState_ParenString:
			if r == '"' {
				s.nextSize = 0
				if s.state == scannerState_String {
					s.state = scannerState_Default
				} else {
					s.state = scannerState_Paren
				}
				_, _ = token.WriteRune(r)
				return token.String(), nil
			}

			if r == '\\' {
				s.nextSize = 0
				if s.state == scannerState_String {
					s.state = scannerState_StringEscape
				} else {
					s.state = scannerState_ParenStringEscape
				}
				_, _ = token.WriteRune(r)
				continue
			}

			s.nextSize = 0
			_, _ = token.WriteRune(r)

		case scannerState_StringEscape, scannerState_ParenStringEscape:
			s.nextSize = 0
			if s.state == scannerState_StringEscape {
				s.state = scannerState_String
			} else {
				s.state = scannerState_ParenString
			}
			_, _ = token.WriteRune(r)

		case scannerState_Comment, scannerState_ParenComment:
			if r == '\n' {
				if s.state == scannerState_Comment {
					s.state = scannerState_Default
				} else {
					s.state = scannerState_Paren
				}
				continue
			}

			s.nextSize = 0
			_, _ = token.WriteRune(r)

		case scannerState_Space:
			if unicode.IsSpace(r) {
				s.nextSize = 0
				continue
			}

			s.state = scannerState_Default
			continue
		}
	}
}

func parseClass(token string) (RecordClass, error) {
	switch token {
	case "IN":
		return RecordClass_IN, nil
	case "CS":
		return RecordClass_CS, nil
	case "CH":
		return RecordClass_CH, nil
	case "HS":
		return RecordClass_HS, nil
	case "*":
		return RecordClass_any, nil
	default:
		return RecordClass_UNKNOWN, fmt.Errorf("Unknown Record Class '%s'", token)
	}
}

func parseType(token string) (RecordType, error) {
	switch token {
	case "A":
		return RecordType_A, nil
	case "NS":
		return RecordType_NS, nil
	case "MD":
		return RecordType_MD, nil
	case "MF":
		return RecordType_MF, nil
	case "CNAME":
		return RecordType_CNAME, nil
	case "SOA":
		return RecordType_SOA, nil
	case "MB":
		return RecordType_MB, nil
	case "MG":
		return RecordType_MG, nil
	case "MR":
		return RecordType_MR, nil
	case "NULL":
		return RecordType_NULL, nil
	case "WKS":
		return RecordType_WKS, nil
	case "PTR":
		return RecordType_PTR, nil
	case "HINFO":
		return RecordType_HINFO, nil
	case "MINFO":
		return RecordType_MINFO, nil
	case "MX":
		return RecordType_MX, nil
	case "TXT":
		return RecordType_TXT, nil
	case "RP":
		return RecordType_RP, nil
	case "AFSDB":
		return RecordType_AFSDB, nil
	case "X25":
		return RecordType_X25, nil
	case "ISDN":
		return RecordType_ISDN, nil
	case "RT":
		return RecordType_RT, nil
	case "NSAP":
		return RecordType_NSAP, nil
	case "NSAP-PTR":
		return RecordType_NSAP_PTR, nil
	case "SIG":
		return RecordType_SIG, nil
	case "KEY":
		return RecordType_KEY, nil
	case "PX":
		return RecordType_PX, nil
	case "GPOS":
		return RecordType_GPOS, nil
	case "AAAA":
		return RecordType_AAAA, nil
	case "LOC":
		return RecordType_LOC, nil
	case "NXT":
		return RecordType_NXT, nil
	case "EID":
		return RecordType_EID, nil
	case "NIMLOC":
		return RecordType_NIMLOC, nil
	case "SRV":
		return RecordType_SRV, nil
	case "ATMA":
		return RecordType_ATMA, nil
	case "NAPTR":
		return RecordType_NAPTR, nil
	case "KX":
		return RecordType_KX, nil
	case "CERT":
		return RecordType_CERT, nil
	case "A6":
		return RecordType_A6, nil
	case "DNAME":
		return RecordType_DNAME, nil
	case "SINK":
		return RecordType_SINK, nil
	case "OPT":
		return RecordType_OPT, nil
	case "APL":
		return RecordType_APL, nil
	case "DS":
		return RecordType_DS, nil
	case "SSHFP":
		return RecordType_SSHFP, nil
	case "IPSECKEY":
		return RecordType_IPSECKEY, nil
	case "RRSIG":
		return RecordType_RRSIG, nil
	case "NSEC":
		return RecordType_NSEC, nil
	case "DNSKEY":
		return RecordType_DNSKEY, nil
	case "DHCID":
		return RecordType_DHCID, nil
	case "NSEC3":
		return RecordType_NSEC3, nil
	case "NSEC3PARAM":
		return RecordType_NSEC3PARAM, nil
	case "TLSA":
		return RecordType_TLSA, nil
	case "SMIMEA":
		return RecordType_SMIMEA, nil
	case "HIP":
		return RecordType_HIP, nil
	case "NINFO":
		return RecordType_NINFO, nil
	case "RKEY":
		return RecordType_RKEY, nil
	case "TALINK":
		return RecordType_TALINK, nil
	case "CDS":
		return RecordType_CDS, nil
	case "CDNSKEY":
		return RecordType_CDNSKEY, nil
	case "OPENPGPKEY":
		return RecordType_OPENPGPKEY, nil
	case "CSYNC":
		return RecordType_CSYNC, nil
	case "ZONEMD":
		return RecordType_ZONEMD, nil
	case "SPF":
		return RecordType_SPF, nil
	case "UINFO":
		return RecordType_UINFO, nil
	case "UID":
		return RecordType_UID, nil
	case "GID":
		return RecordType_GID, nil
	case "UNSPEC":
		return RecordType_UNSPEC, nil
	case "NID":
		return RecordType_NID, nil
	case "L32":
		return RecordType_L32, nil
	case "L64":
		return RecordType_L64, nil
	case "LP":
		return RecordType_LP, nil
	case "EUI48":
		return RecordType_EUI48, nil
	case "EUI64":
		return RecordType_EUI64, nil
	case "TKEY":
		return RecordType_TKEY, nil
	case "TSIG":
		return RecordType_TSIG, nil
	case "IXFR":
		return RecordType_IXFR, nil
	case "AXFR":
		return RecordType_AXFR, nil
	case "MAILB":
		return RecordType_MAILB, nil
	case "MAILA":
		return RecordType_MAILA, nil
	case "*":
		return RecordType_all, nil
	case "URI":
		return RecordType_URI, nil
	case "CAA":
		return RecordType_CAA, nil
	case "AVC":
		return RecordType_AVC, nil
	case "DOA":
		return RecordType_DOA, nil
	case "AMTRELAY":
		return RecordType_AMTRELAY, nil
	case "TA":
		return RecordType_TA, nil
	case "DLV":
		return RecordType_DLV, nil
	default:
		return 0, fmt.Errorf("Unknown Record Type '%s'", token)
	}
}

func (s *Scanner) Next(outrecord *Record) error {
	var record Record
	var token string
	var err error

	var hasClass bool
	var hasTTL bool
	var hasType bool
	var hasData bool

	record.TimeToLive = -1
	for { // ignore leading spaces / comments
		if token, err = s.nextToken(); err != nil {
			return err
		}

		if token != "\n" && token[0] != ';' {
			break
		}
	}

	record.DomainName = token

	for {
		if token, err = s.nextToken(); err != nil {
			if err == io.EOF {
				if hasData {
					*outrecord = record
					break
				}

				if hasClass || hasTTL || hasType {
					return fmt.Errorf("Incomplete record at end of file")
				}
			}

			return err
		}

		if !hasType {
			if !hasTTL {
				var i64 uint64
				i64, err = strconv.ParseUint(token, 10, 32)
				if err != nil {
					record.TimeToLive = -1
				} else {
					record.TimeToLive = int64(i64)
					hasTTL = true
					continue
				}
			}

			if !hasClass {
				record.Class, err = parseClass(token)
				if err != nil {
					record.Class = RecordClass_UNKNOWN
				} else {
					hasClass = true
					continue
				}
			}

			record.Type, err = parseType(token)
			if err != nil {
				return err
			} else {
				hasType = true
				continue
			}
		}

		if !hasData {
			if token == "\n" || token[0] == ';' {
				return fmt.Errorf("missing data part for DomainName: %s; Type: %s",
					record.DomainName,
					record.Type,
				)
			}
		}

		if token[0] == ';' {
			record.Comment = token
			continue
		}

		if token == "\n" {
			break
		}

		record.Comment = "" // ignore "internal" comments
		record.Data = append(record.Data, token)
		hasData = true
		continue
	}

	*outrecord = record
	return nil
}
