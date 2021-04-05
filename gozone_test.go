package gozone

import (
	"io"
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
		"RP":         RecordType_RP,
		"AFSDB":      RecordType_AFSDB,
		"X25":        RecordType_X25,
		"ISDN":       RecordType_ISDN,
		"RT":         RecordType_RT,
		"NSAP":       RecordType_NSAP,
		"NSAP-PTR":   RecordType_NSAP_PTR,
		"SIG":        RecordType_SIG,
		"KEY":        RecordType_KEY,
		"PX":         RecordType_PX,
		"GPOS":       RecordType_GPOS,
		"AAAA":       RecordType_AAAA,
		"LOC":        RecordType_LOC,
		"NXT":        RecordType_NXT,
		"EID":        RecordType_EID,
		"NIMLOC":     RecordType_NIMLOC,
		"SRV":        RecordType_SRV,
		"ATMA":       RecordType_ATMA,
		"NAPTR":      RecordType_NAPTR,
		"KX":         RecordType_KX,
		"CERT":       RecordType_CERT,
		"A6":         RecordType_A6,
		"DNAME":      RecordType_DNAME,
		"SINK":       RecordType_SINK,
		"OPT":        RecordType_OPT,
		"APL":        RecordType_APL,
		"DS":         RecordType_DS,
		"SSHFP":      RecordType_SSHFP,
		"IPSECKEY":   RecordType_IPSECKEY,
		"RRSIG":      RecordType_RRSIG,
		"NSEC":       RecordType_NSEC,
		"DNSKEY":     RecordType_DNSKEY,
		"DHCID":      RecordType_DHCID,
		"NSEC3":      RecordType_NSEC3,
		"NSEC3PARAM": RecordType_NSEC3PARAM,
		"TLSA":       RecordType_TLSA,
		"SMIMEA":     RecordType_SMIMEA,
		"HIP":        RecordType_HIP,
		"NINFO":      RecordType_NINFO,
		"RKEY":       RecordType_RKEY,
		"TALINK":     RecordType_TALINK,
		"CDS":        RecordType_CDS,
		"CDNSKEY":    RecordType_CDNSKEY,
		"OPENPGPKEY": RecordType_OPENPGPKEY,
		"CSYNC":      RecordType_CSYNC,
		"ZONEMD":     RecordType_ZONEMD,
		"SPF":        RecordType_SPF,
		"UINFO":      RecordType_UINFO,
		"UID":        RecordType_UID,
		"GID":        RecordType_GID,
		"UNSPEC":     RecordType_UNSPEC,
		"NID":        RecordType_NID,
		"L32":        RecordType_L32,
		"L64":        RecordType_L64,
		"LP":         RecordType_LP,
		"EUI48":      RecordType_EUI48,
		"EUI64":      RecordType_EUI64,
		"TKEY":       RecordType_TKEY,
		"TSIG":       RecordType_TSIG,
		"IXFR":       RecordType_IXFR,
		"AXFR":       RecordType_AXFR,
		"MAILB":      RecordType_MAILB,
		"MAILA":      RecordType_MAILA,
		"*":          RecordType_all,
		"URI":        RecordType_URI,
		"CAA":        RecordType_CAA,
		"AVC":        RecordType_AVC,
		"DOA":        RecordType_DOA,
		"AMTRELAY":   RecordType_AMTRELAY,
		"TA":         RecordType_TA,
		"DLV":        RecordType_DLV,
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

func TestOriginDefinesDefault(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("@ 300 IN A 192.168.1.1"))
	err := s.SetOrigin("adomain.com.")
	if err != nil {
		t.Fatalf("Unexpected error when setting Origin: %s", err)
	}

	err = s.Next(&r)
	if err != nil {
		t.Fatalf("Parsing of default-domain record returned an error: %s", err)
	}

	if r.DomainName != "adomain.com." {
		t.Fatalf("Parsing of default-domain record did not result in a Record with the default domain")
	}
}

func TestOriginControlEntrySetsOrigin(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$ORIGIN adomain.com.\n300 IN A 192.168.1.1"))

	err := s.Next(&r)
	if err != nil {
		t.Fatalf("Unexpected error when setting Origin via $ORIGIN Control Entry: %s", err)
	}

	if s.origin != "adomain.com." {
		t.Fatalf("Parsing of $ORIGIN control entry did not set the default origin")
	}

	if r.DomainName != "adomain.com." {
		t.Fatalf("Parsing of $ORIGIN control entry did not set the default domain name")
	}
}

func TestOriginControlEntryCanHaveComment(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$ORIGIN adomain.com. ; should be ignored\n@ 300 IN A 192.168.1.1"))
	err := s.Next(&r)
	if err != nil {
		t.Fatalf("Parsing of default-domain record returned an error: %s", err)
	}

	if r.DomainName != "adomain.com." {
		t.Fatalf("Parsing of default-domain record did not result in a Record with the default domain")
	}
}

func TestOriginDefinesRelative(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("www 300 IN A 192.168.1.1"))
	err := s.SetOrigin("adomain.com.")
	if err != nil {
		t.Fatalf("Unexpected error when setting Origin: %s", err)
	}

	err = s.Next(&r)
	if err != nil {
		t.Fatalf("Parsing of relative record returned an error: %s", err)
	}

	if r.DomainName != "www.adomain.com." {
		t.Fatalf("Parsing of relative record did not result in a Record within the default domain")
	}
}

func TestOriginDoesNotImpactFullyQualified(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("www.example.com. 300 IN A 192.168.1.1"))
	err := s.SetOrigin("adomain.com.")
	if err != nil {
		t.Fatalf("Unexpected error when setting Origin: %s", err)
	}

	err = s.Next(&r)
	if err != nil {
		t.Fatalf("Parsing of fully-qualified record returned an error: %s", err)
	}

	if r.DomainName != "www.example.com." {
		t.Fatalf("Parsing of fully-qualified record with an $ORIGIN defined did not result in the entry's domain as-specified")
	}
}

func TestOriginControlEntryRelativeFails(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$ORIGIN adomain.com\nwww 300 IN A 192.168.1.1"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of relative $ORIGIN control entry did not return an error")
	}
}

func TestDefaultDomainWithoutOriginFails(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("@ 300 IN A 192.168.1.1"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of default domain entry when no $ORIGIN defined did not result in an error")
	}
}

func TestRelativeDomainWithoutOriginFails(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("www 300 IN A 192.168.1.1"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of relative domain when no $ORIGIN defined did not result in an error")
	}
}

func TestIncompleteOriginControlEntry(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$ORIGIN\nwww 300 IN A 192.168.1.1"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of incomplete $ORIGIN control entry did not result in an error")
	}
}

func TestIncompleteOriginControlEntryComment(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$ORIGIN ;this should be ignored\nwww 300 IN A 192.168.1.1"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of incomplete $ORIGIN control entry (with comment) did not result in an error")
	}
}

func TestIncompleteOriginControlEntryEOF(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$ORIGIN"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of incomplete $ORIGIN control entry (at end of file) did not result in an error")
	}
}

// This one may require some explanation. It is asserting two things:
// 1) an $ORIGIN at the end of the file is not an error on its own
// 2) the presence of an $ORIGIN control entry should not cause a record to be
//    returned, ie: there should still be an error returned, but that error is
//    merely the normal "EOF" error.
func TestCompleteOriginControlEntryEOF(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$ORIGIN adomain.com."))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of a zone containing nothing but an $ORIGIN control entry did not result in an error")
	}

	if err != io.EOF {
		t.Fatalf("Parsing of a zone containing nothing but an $ORIGIN control entry did not result in EOF error")
	}
}

func TestMalformedOriginControlEntryMultipleDomains(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$ORIGIN adomain.com. andanother.com."))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of malformed $ORIGIN control entry (multiple domains) did not result in an error")
	}
}

func TestUnknownControlEntryFails(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$UNKNOWN"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of unknown control entry did not result in an error")
	}
}

func TestTimeToLiveDefinesDefault(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("adomain.com. IN A 192.168.1.1"))
	err := s.SetTimeToLive(600)
	if err != nil {
		t.Fatalf("Unexpected error when setting TimeToLive: %s", err)
	}

	err = s.Next(&r)
	if err != nil {
		t.Fatalf("Parsing of TTL-less record returned an error: %s", err)
	}

	if r.TimeToLive != 600 {
		t.Fatalf("Parsing of TTL-less record did not result in a Record with the default TTL")
	}
}

func TestTimeToLiveControlEntrySetsTimeToLive(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$TTL 600\nadomain.com. IN A 192.168.1.1"))

	err := s.Next(&r)
	if err != nil {
		t.Fatalf("Unexpected error when setting TimeToLive via $TTL Control Entry: %s", err)
	}

	if s.timeToLive != 600 {
		t.Fatalf("Parsing of $TTL control entry did not set the default TTL")
	}
}

func TestTimeToLiveControlEntryCanHaveComment(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$TTL 600 ; should be ignored\nadomain.com. IN A 192.168.1.1"))
	err := s.Next(&r)
	if err != nil {
		t.Fatalf("Parsing of TTL-less record returned an error: %s", err)
	}

	if r.TimeToLive != 600 {
		t.Fatalf("Parsing of TTL-less record did not result in a Record with the default TTL")
	}
}

func TestTimeToLiveDoesNotImpactSpecified(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("www.example.com. 300 IN A 192.168.1.1"))
	err := s.SetTimeToLive(600)
	if err != nil {
		t.Fatalf("Unexpected error when setting TimeToLive: %s", err)
	}

	err = s.Next(&r)
	if err != nil {
		t.Fatalf("Parsing of TTL-specified record returned an error: %s", err)
	}

	if r.TimeToLive != 300 {
		t.Fatalf("Parsing of TTL-specified record a $TTL defined did not result in the entry's TTL as-specified")
	}
}

func TestIncompleteTimeToLiveControlEntry(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$TTL\nwww 300 IN A 192.168.1.1"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of incomplete $TTL control entry did not result in an error")
	}
}

func TestIncompleteTimeToLiveControlEntryComment(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$TTL ;this should be ignored\nwww 300 IN A 192.168.1.1"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of incomplete $TTL control entry (with comment) did not result in an error")
	}
}

func TestIncompleteTimeToLiveControlEntryEOF(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$TTL"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of incomplete $TTL control entry (at end of file) did not result in an error")
	}
}

func TestCompleteTimeToLiveControlEntryEOF(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$TTL 600"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of a zone containing nothing but an $TTL control entry did not result in an error")
	}

	if err != io.EOF {
		t.Fatalf("Parsing of a zone containing nothing but an $TTL control entry did not result in EOF error")
	}
}

func TestMalformedTimeToLiveControlEntryMultipleTimeToLive(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$TTL 600 300"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of malformed $TTL control entry (multiple time-to-live) did not result in an error")
	}
}

func TestMalformedTimeToLiveControlEntryNonNumeric(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$TTL aaa"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of malformed $TTL control entry (non-numeric) did not result in an error")
	}
}

func TestMalformedTimeToLiveControlEntryNegative(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$TTL -600"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of malformed $TTL control entry (negative) did not result in an error")
	}
}

func TestMalformedTimeToLiveControlEntryTooLarge(t *testing.T) {
	var r Record
	s := NewScanner(strings.NewReader("$TTL 4294967296"))
	err := s.Next(&r)
	if err == nil {
		t.Fatalf("Parsing of malformed $TTL control entry (number larger than MaxUint32) did not result in an error")
	}
}

func TestSetTimeToLiveTooLargeFail(t *testing.T) {
	s := NewScanner(strings.NewReader("adomain.com. IN A 192.168.1.1"))
	err := s.SetTimeToLive(4294967296)
	if err == nil {
		t.Fatalf("Setting TimeToLive to a number larger than MaxUint32 did not result in an error")
	}
}

func TestSetTimeToLiveTooSmallFolds(t *testing.T) {
	s := NewScanner(strings.NewReader("adomain.com. IN A 192.168.1.1"))
	err := s.SetTimeToLive(-2)
	if err != nil {
		t.Fatalf("Setting TimeToLive to a number smaller than -1 (ie, to indicate unspecified) resulted in an error")
	}

	if s.timeToLive != -1 {
		t.Fatalf("Setting TimeToLive to a number smaller than -1 (ie, to indicate unspecified) did not fold the value to -1")
	}
}
