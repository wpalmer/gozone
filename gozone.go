package gozone

// https://www.ietf.org/rfc/rfc1035.txt

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
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
	RecordType_UNKNOWN = 0  // unset
	RecordType_A       = 1  // a host address
	RecordType_NS      = 2  // an authoritative name server
	RecordType_MD      = 3  // a mail destination (Obsolete - use MX)
	RecordType_MF      = 4  // a mail forwarder (Obsolete - use MX)
	RecordType_CNAME   = 5  // the canonical name for an alias
	RecordType_SOA     = 6  // marks the start of zone authority
	RecordType_MB      = 7  // a mailbox domain name (EXPERIMENTAL)
	RecordType_MG      = 8  // a mail group member (EXPERIMENTAL)
	RecordType_MR      = 9  // a mail rename domain name (EXPERIMENTAL)
	RecordType_NULL    = 10 // a null RR (EXPERIMENTAL)
	RecordType_WKS     = 11 // a well known service description
	RecordType_PTR     = 12 // a domain name pointer
	RecordType_HINFO   = 13 // host information
	RecordType_MINFO   = 14 // mailbox or mail list information
	RecordType_MX      = 15 // mail exchange
	RecordType_TXT     = 16 // text strings
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
	src        *bufio.Reader
	state      scannerState
	origin     string
	timeToLive int64
	nextRune   rune
	nextSize   int
}

func NewScanner(src io.Reader) *Scanner {
	return &Scanner{
		src:        bufio.NewReader(src),
		timeToLive: -1,
		nextRune:   0,
		nextSize:   0,
	}
}

func (s *Scanner) SetOrigin(domain string) error {
	if domain[len(domain)-1] != '.' {
		return fmt.Errorf("Tried to set $ORIGIN to relative domain")
	}

	s.origin = domain
	return nil
}

func (s *Scanner) SetTimeToLive(timeToLive int64) error {
	if timeToLive < 0 {
		timeToLive = -1
	}

	if timeToLive > math.MaxUint32 {
		return fmt.Errorf("Tried to set $TTL to number greater than MaxUint32")
	}

	s.timeToLive = timeToLive
	return nil
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
	default:
		return 0, fmt.Errorf("Unknown Record Type '%s'", token)
	}
}

func (s *Scanner) scanControlEntry(initial string) error {
	switch initial {
	case "$ORIGIN":
		return s.scanControlEntryOrigin()
	case "$TTL":
		return s.scanControlEntryTTL()
	default:
		return fmt.Errorf("Unknown Control Entry '%s'", initial)
	}
}

func (s *Scanner) scanControlEntryOrigin() error {
	var hasDomain bool
	var token string
	var err error

	for {
		if token, err = s.nextToken(); err != nil {
			if err == io.EOF {
				if hasDomain {
					break
				}

				return fmt.Errorf("Incomplete $ORIGIN control entry at end of file")
			}

			return err
		}

		if token[0] == ';' {
			if hasDomain {
				return nil
			}

			return fmt.Errorf("Incomplete $ORIGIN control entry ends in comment")
		}

		if token == "\n" {
			if !hasDomain {
				return fmt.Errorf("missing DomainName in $ORIGIN control entry")
			}
			break
		}

		if hasDomain {
			return fmt.Errorf("Multiple domains found in $ORIGIN control entry")
		}

		if err = s.SetOrigin(token); err != nil {
			return err
		}

		hasDomain = true
	}

	return nil
}

func (s *Scanner) scanControlEntryTTL() error {
	var hasTTL bool
	var token string
	var err error

	for {
		if token, err = s.nextToken(); err != nil {
			if err == io.EOF {
				if hasTTL {
					break
				}

				return fmt.Errorf("Incomplete $TTL control entry at end of file")
			}

			return err
		}

		if token[0] == ';' {
			if hasTTL {
				return nil
			}

			return fmt.Errorf("Incomplete $TTL control entry ends in comment")
		}

		if token == "\n" {
			if !hasTTL {
				return fmt.Errorf("missing TimeToLive in $TTL control entry")
			}
			break
		}

		if hasTTL {
			return fmt.Errorf("Multiple TimeToLive found in $TTL control entry")
		}

		var i64 uint64
		i64, err = strconv.ParseUint(token, 10, 32)
		if err != nil {
			return fmt.Errorf("Failed to parse TimeToLive in $TTL control entry: %s", err)
		}

		if err = s.SetTimeToLive(int64(i64)); err != nil {
			return err
		}
		hasTTL = true
	}

	return nil
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
	for { // ignore leading spaces / comments / process control entries
		if token, err = s.nextToken(); err != nil {
			return err
		}

		if token[0] == '$' {
			// control entry
			if err = s.scanControlEntry(token); err != nil {
				return err
			}
		}

		if token != "\n" && token[0] != ';' && token[0] != '$' {
			break
		}
	}

	domain := token
	if domain == "@" {
		if s.origin == "" {
			return fmt.Errorf("Record for current domain specified when no $ORIGIN defined")
		}
		domain = s.origin
	} else if domain[len(token)-1] != '.' {
		if s.origin == "" {
			return fmt.Errorf("Record relative-to-current domain specified when no $ORIGIN defined")
		}

		domain = fmt.Sprintf("%s.%s", token, s.origin)
	}
	record.DomainName = domain

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
					record.TimeToLive = s.timeToLive
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
