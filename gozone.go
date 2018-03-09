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
	RecordType_UNKNOWN = iota
	RecordType_A
	RecordType_NS
	RecordType_MD
	RecordType_MF
	RecordType_CNAME
	RecordType_SOA
	RecordType_MB
	RecordType_MG
	RecordType_MR
	RecordType_NULL
	RecordType_WKS
	RecordType_PTR
	RecordType_HINFO
	RecordType_MINFO
	RecordType_MX
	RecordType_TXT
	RecordType_AAAA
	RecordType_AFSDB
	RecordType_DNSKEY
	RecordType_DS
	RecordType_LOC
	RecordType_NAPTR
	RecordType_NSEC3
	RecordType_NSEC3PARAM
	RecordType_RP
	RecordType_RRSIG
	RecordType_SPF
	RecordType_SRV
	RecordType_SSHFP
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
	case RecordType_AAAA:
		return "AAAA"
	case RecordType_AFSDB:
		return "AFSDB"
	case RecordType_DNSKEY:
		return "DNSKEY"
	case RecordType_DS:
		return "DS"
	case RecordType_LOC:
		return "LOC"
	case RecordType_NAPTR:
		return "NAPTR"
	case RecordType_NSEC3:
		return "NSEC3"
	case RecordType_NSEC3PARAM:
		return "NSEC3PARAM"
	case RecordType_RP:
		return "RP"
	case RecordType_RRSIG:
		return "RRSIG"
	case RecordType_SPF:
		return "SPF"
	case RecordType_SRV:
		return "SRV"
	case RecordType_SSHFP:
		return "SSHFP"
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
	case "AAAA":
		return RecordType_AAAA, nil
	case "AFSDB":
		return RecordType_AFSDB, nil
	case "DNSKEY":
		return RecordType_DNSKEY, nil
	case "DS":
		return RecordType_DS, nil
	case "LOC":
		return RecordType_LOC, nil
	case "NAPTR":
		return RecordType_NAPTR, nil
	case "NSEC3":
		return RecordType_NSEC3, nil
	case "NSEC3PARAM":
		return RecordType_NSEC3PARAM, nil
	case "RP":
		return RecordType_RP, nil
	case "RRSIG":
		return RecordType_RRSIG, nil
	case "SPF":
		return RecordType_SPF, nil
	case "SRV":
		return RecordType_SRV, nil
	case "SSHFP":
		return RecordType_SSHFP, nil
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
