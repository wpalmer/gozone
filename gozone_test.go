package gozone

import (
	"reflect"
	"strings"
	"testing"
)

func TestClassMap(t *testing.T) {
	check := map[string]RecordClass{
		"IN": RecordClass_IN,
		"CS": RecordClass_CS,
		"CH": RecordClass_CH,
		"HS": RecordClass_HS,
		"*":  RecordClass_any,
	}

	for label, rc := range check {
		parsed, err := parseClass(label)
		if err != nil {
			t.Fatalf("Failed to parse RecordClass '%s'", label)
		}

		if parsed != rc {
			t.Fatalf("Parsing of '%s' did not return expected class", label)
		}

		if parsed.String() != label {
			t.Fatalf("String output of RecordClass for '%s' did not match the original input", label)
		}
	}
}

func TestTypeMap(t *testing.T) {
	check := map[string]RecordType{
		"A":          RecordType_A,
		"NS":         RecordType_NS,
		"MD":         RecordType_MD,
		"MF":         RecordType_MF,
		"CNAME":      RecordType_CNAME,
		"SOA":        RecordType_SOA,
		"MB":         RecordType_MB,
		"MG":         RecordType_MG,
		"MR":         RecordType_MR,
		"NULL":       RecordType_NULL,
		"WKS":        RecordType_WKS,
		"PTR":        RecordType_PTR,
		"HINFO":      RecordType_HINFO,
		"MINFO":      RecordType_MINFO,
		"MX":         RecordType_MX,
		"TXT":        RecordType_TXT,
		"AAAA":       RecordType_AAAA,
		"AFSDB":      RecordType_AFSDB,
		"DNSKEY":     RecordType_DNSKEY,
		"DS":         RecordType_DS,
		"LOC":        RecordType_LOC,
		"NAPTR":      RecordType_NAPTR,
		"NSEC3":      RecordType_NSEC3,
		"NSEC3PARAM": RecordType_NSEC3PARAM,
		"RP":         RecordType_RP,
		"RRSIG":      RecordType_RRSIG,
		"SPF":        RecordType_SPF,
		"SRV":        RecordType_SRV,
		"SSHFP":      RecordType_SSHFP,
	}

	for label, rt := range check {
		parsed, err := parseType(label)
		if err != nil {
			t.Fatalf("Failed to parse RecordType '%s'", label)
		}

		if parsed != rt {
			t.Fatalf("Parsing of '%s' did not return expected type", label)
		}

		if parsed.String() != label {
			t.Fatalf("String output of RecordType for '%s' did not match the original input", label)
		}
	}
}

func TestRecordTypes(t *testing.T) {
	records := map[string]Record{
		"adomain.com. 300 IN SOA ns.ahostdomain.com. hostmaster.ahostdomain.com. ( 1271271271 10800 3600 604800 300 )": Record{
			"adomain.com.", 300, RecordClass_IN, RecordType_SOA,
			[]string{"ns.ahostdomain.com.", "hostmaster.ahostdomain.com.", "(", "1271271271", "10800", "3600", "604800", "300", ")"}, "",
		},

		"adomain.com. 300 IN SOA ns.ahostdomain.com. hostmaster.ahostdomain.com.(1271271271 10800 3600 604800 300)": Record{
			"adomain.com.", 300, RecordClass_IN, RecordType_SOA,
			[]string{"ns.ahostdomain.com.", "hostmaster.ahostdomain.com.", "(", "1271271271", "10800", "3600", "604800", "300", ")"}, "",
		},

		"adomain.com. 300 IN A 192.168.0.1;aComment": Record{"adomain.com.", 300, RecordClass_IN, RecordType_A, []string{"192.168.0.1"}, ";aComment"},
		"adomain.com. IN A 192.168.0.1":              Record{"adomain.com.", -1, RecordClass_IN, RecordType_A, []string{"192.168.0.1"}, ""},

		"adomain.com. 300 IN A 192.168.0.1\n\nadomain.com. 300 IN A 192.168.0.2\n": Record{"adomain.com.", 300, RecordClass_IN, RecordType_A, []string{"192.168.0.1"}, ""},

		"adomain.com. 300 IN NS ns.ahostdomain.com.":      Record{"adomain.com.", 300, RecordClass_IN, RecordType_NS, []string{"ns.ahostdomain.com."}, ""},
		"adomain.com. 300 IN MX 10 smtp.ahostdomain.com.": Record{"adomain.com.", 300, RecordClass_IN, RecordType_MX, []string{"10", "smtp.ahostdomain.com."}, ""},
		`adomain.com. 300 IN TXT "a \"b\" c"`:             Record{"adomain.com.", 300, RecordClass_IN, RecordType_TXT, []string{`"a \"b\" c"`}, ""},
		`adomain.com. 300 IN TXT"a \"b\" c"`:              Record{"adomain.com.", 300, RecordClass_IN, RecordType_TXT, []string{`"a \"b\" c"`}, ""},
		"www.adomain.com. 300 IN CNAME adomain.com.":      Record{"www.adomain.com.", 300, RecordClass_IN, RecordType_CNAME, []string{"adomain.com."}, ""},
	}

	for spec, record := range records {
		var r Record
		s := NewScanner(strings.NewReader(spec))
		err := s.Next(&r)
		if err != nil {
			t.Fatalf("Failed to parse [%s]: %s", spec, err)
		}

		if !reflect.DeepEqual(r, record) {
			t.Fatalf("Generated Output [%#v] not equal to Input [%#v]", r, record)
		}
	}
}

func TestRecordTypesOuput(t *testing.T) {
	records := map[string]string{
		"adomain.com. 300 IN SOA ns.ahostdomain.com. hostmaster.ahostdomain.com. ( 1271271271 10800 3600 604800 300 )": "adomain.com. 300 IN SOA ns.ahostdomain.com. hostmaster.ahostdomain.com. ( 1271271271 10800 3600 604800 300 )",

		"adomain.com. 300 IN A 192.168.0.1;aComment\n": "adomain.com. 300 IN A 192.168.0.1 ;aComment",

		"adomain.com. IN A 192.168.0.1": "adomain.com. IN A 192.168.0.1",

		"adomain.com. 300 IN NS ns.ahostdomain.com.": "adomain.com. 300 IN NS ns.ahostdomain.com.",

		"adomain.com. 300 IN MX 10 smtp.ahostdomain.com.": "adomain.com. 300 IN MX 10 smtp.ahostdomain.com.",

		`adomain.com. 300 IN TXT "a \"b\" c"`: `adomain.com. 300 IN TXT "a \"b\" c"`,

		"www.adomain.com. 300 IN CNAME adomain.com.": "www.adomain.com. 300 IN CNAME adomain.com.",
	}

	for spec, expected := range records {
		var r Record
		s := NewScanner(strings.NewReader(spec))
		err := s.Next(&r)
		if err != nil {
			t.Fatalf("Failed to parse [%s]: %s", spec, err)
		}

		if r.String() != expected {
			t.Fatalf("Generated Output [%s] not equal to expected output [%s]", r.String(), expected)
		}
	}
}

func TestIncompleteTXTRecordFails(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("adomain.com. 300 IN TXT \""))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of unclosed TXT record did not return an error")
	}
}

func TestIncompleteSOARecordFails(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("adomain.com. 300 IN SOA ( 1271271271"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of unclosed SOA record did not return an error")
	}
}

func TestIncompleteTypelessRecordFailsEOF(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("adomain.com. 300 IN "))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of typeless record did not return an error")
	}
}

func TestIncompleteTypelessRecordFailsEOL(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("adomain.com. 300 IN \n"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of typeless record did not return an error")
	}
}

func TestIncompleteDatalessRecordFailsEOF(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("adomain.com. 300 IN A "))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of dataless record did not return an error")
	}
}

func TestIncompleteDatalessRecordFailsEOL(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("adomain.com. 300 IN A \n"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of dataless record did not return an error")
	}
}

func TestBadClassRecordFails(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("adomain.com. 300 FAKE A 192.168.1.1"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of bad-class record did not return an error")
	}
}

func TestBadTypeRecordFails(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("adomain.com. 300 IN FAKE 192.168.1.1"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of bad-type record did not return an error")
	}
}
