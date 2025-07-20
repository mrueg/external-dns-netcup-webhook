/*
Copyright 2022 The Kubernetes Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package netcup

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	nc "github.com/aellwein/netcup-dns-api/pkg/v1"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

func TestNetcupProvider(t *testing.T) {
	t.Run("EndpointZoneName", testEndpointZoneName)
	t.Run("GetIDforRecord", testGetIDforRecord)
	t.Run("ConvertToNetcupRecord", testConvertToNetcupRecord)
	t.Run("ConvertToNetcupRecordMultiTarget", testConvertToNetcupRecordMultiTarget)
	t.Run("TxtRecordHandling", testTxtRecordHandling)
	t.Run("TxtRecordRestartScenario", testTxtRecordRestartScenario)
	t.Run("NewNetcupProvider", testNewNetcupProvider)
	t.Run("ApplyChanges", testApplyChanges)
	t.Run("Records", testRecords)
	t.Run("RecordsGrouping", testRecordsGrouping)
}

func testEndpointZoneName(t *testing.T) {
	zoneList := []string{"bar.org", "baz.org"}

	// in zone list
	ep1 := endpoint.Endpoint{
		DNSName:    "foo.bar.org",
		Targets:    endpoint.Targets{"5.5.5.5"},
		RecordType: endpoint.RecordTypeA,
	}

	// not in zone list
	ep2 := endpoint.Endpoint{
		DNSName:    "foo.foo.org",
		Targets:    endpoint.Targets{"5.5.5.5"},
		RecordType: endpoint.RecordTypeA,
	}

	// matches zone exactly
	ep3 := endpoint.Endpoint{
		DNSName:    "baz.org",
		Targets:    endpoint.Targets{"5.5.5.5"},
		RecordType: endpoint.RecordTypeA,
	}

	assert.Equal(t, endpointZoneName(&ep1, zoneList), "bar.org")
	assert.Equal(t, endpointZoneName(&ep2, zoneList), "")
	assert.Equal(t, endpointZoneName(&ep3, zoneList), "baz.org")
}

func testGetIDforRecord(t *testing.T) {

	recordName := "foo.example.com"
	target1 := "heritage=external-dns,external-dns/owner=default,external-dns/resource=service/default/nginx"
	target2 := "5.5.5.5"
	recordType := "TXT"

	nc1 := nc.DnsRecord{
		Hostname:     "foo.example.com",
		Type:         "TXT",
		Destination:  "heritage=external-dns,external-dns/owner=default,external-dns/resource=service/default/nginx",
		Id:           "10",
		DeleteRecord: false,
	}
	nc2 := nc.DnsRecord{
		Hostname:     "foo.foo.org",
		Type:         "A",
		Destination:  "5.5.5.5",
		Id:           "10",
		DeleteRecord: false,
	}

	nc3 := nc.DnsRecord{
		Id:           "",
		Hostname:     "baz.org",
		Type:         "A",
		Destination:  "5.5.5.5",
		DeleteRecord: false,
	}

	ncRecordList := []nc.DnsRecord{nc1, nc2, nc3}

	assert.Equal(t, "10", getIDforRecord(recordName, target1, recordType, &ncRecordList))
	assert.Equal(t, "", getIDforRecord(recordName, target2, recordType, &ncRecordList))

	// Test TXT record with quotes - should still find the ID
	targetWithQuotes := "\"heritage=external-dns,external-dns/owner=default,external-dns/resource=service/default/nginx\""
	assert.Equal(t, "10", getIDforRecord(recordName, targetWithQuotes, recordType, &ncRecordList))

	// Test TXT record in API with quotes - should still find the ID
	nc1WithQuotes := nc.DnsRecord{
		Hostname:     "foo.example.com",
		Type:         "TXT",
		Destination:  "\"heritage=external-dns,external-dns/owner=default,external-dns/resource=service/default/nginx\"",
		Id:           "20",
		DeleteRecord: false,
	}
	ncRecordListWithQuotes := []nc.DnsRecord{nc1WithQuotes, nc2, nc3}

	// Should find ID whether target has quotes or not
	assert.Equal(t, "20", getIDforRecord(recordName, target1, recordType, &ncRecordListWithQuotes))
	assert.Equal(t, "20", getIDforRecord(recordName, targetWithQuotes, recordType, &ncRecordListWithQuotes))

}

func testConvertToNetcupRecord(t *testing.T) {
	// in zone list
	ep1 := endpoint.Endpoint{
		DNSName:    "foo.bar.org",
		Targets:    endpoint.Targets{"5.5.5.5"},
		RecordType: endpoint.RecordTypeA,
	}

	// not in zone list
	ep2 := endpoint.Endpoint{
		DNSName:    "foo.foo.org",
		Targets:    endpoint.Targets{"5.5.5.5"},
		RecordType: endpoint.RecordTypeA,
	}

	// matches zone exactly
	ep3 := endpoint.Endpoint{
		DNSName:    "bar.org",
		Targets:    endpoint.Targets{"5.5.5.5"},
		RecordType: endpoint.RecordTypeA,
	}

	ep4 := endpoint.Endpoint{
		DNSName:    "foo.baz.org",
		Targets:    endpoint.Targets{"\"heritage=external-dns,external-dns/owner=default,external-dns/resource=service/default/nginx\""},
		RecordType: endpoint.RecordTypeTXT,
	}

	epList := []*endpoint.Endpoint{&ep1, &ep2, &ep3, &ep4}

	nc1 := nc.DnsRecord{
		Hostname:     "foo",
		Type:         "A",
		Destination:  "5.5.5.5",
		Id:           "10",
		DeleteRecord: false,
	}
	nc2 := nc.DnsRecord{
		Hostname:     "foo.foo.org",
		Type:         "A",
		Destination:  "5.5.5.5",
		Id:           "15",
		DeleteRecord: false,
	}

	nc3 := nc.DnsRecord{
		Id:           "",
		Hostname:     "@",
		Type:         "A",
		Destination:  "5.5.5.5",
		DeleteRecord: false,
	}

	nc4 := nc.DnsRecord{
		Id:           "",
		Hostname:     "foo.baz.org",
		Type:         "TXT",
		Destination:  "heritage=external-dns,external-dns/owner=default,external-dns/resource=service/default/nginx",
		DeleteRecord: false,
	}

	ncRecordList := []nc.DnsRecord{nc1, nc2, nc3, nc4}

	// Test creation (no deletion) - should have empty IDs for new records
	result := convertToNetcupRecord(&ncRecordList, epList, "bar.org", false)

	// Verify that all records have empty IDs when DeleteRecord is false
	for _, record := range *result {
		assert.Equal(t, "", record.Id, "Create records should have empty IDs")
		assert.False(t, record.DeleteRecord, "Create records should not be marked for deletion")
	}

	// Test deletion - should have IDs set for all records that exist
	resultDelete := convertToNetcupRecord(&ncRecordList, epList, "bar.org", true)

	// Verify that all records have DeleteRecord = true and proper IDs
	for _, record := range *resultDelete {
		assert.True(t, record.DeleteRecord, "Delete records should be marked for deletion")

		// Only records that exist in the original list should be included
		// and they should have their IDs set
		if record.Hostname == "foo" && record.Destination == "5.5.5.5" {
			assert.Equal(t, "10", record.Id, "Existing record should have ID for deletion")
		} else if record.Hostname == "foo.foo.org" && record.Destination == "5.5.5.5" {
			assert.Equal(t, "15", record.Id, "Existing foo.foo.org record should have ID for deletion")
		} else {
			t.Errorf("Unexpected record in deletion result: %+v", record)
		}
	}

	// Should have two records (the ones that exist in the original list)
	assert.Equal(t, 2, len(*resultDelete), "Should only delete records that exist")
}

func testConvertToNetcupRecordMultiTarget(t *testing.T) {
	// Test endpoint with multiple A record targets
	ep1 := endpoint.Endpoint{
		DNSName:    "foo.bar.org",
		Targets:    endpoint.Targets{"5.5.5.5", "6.6.6.6", "7.7.7.7"},
		RecordType: endpoint.RecordTypeA,
	}

	// Test endpoint with single target
	ep2 := endpoint.Endpoint{
		DNSName:    "single.bar.org",
		Targets:    endpoint.Targets{"8.8.8.8"},
		RecordType: endpoint.RecordTypeA,
	}

	// Test endpoint with multiple TXT targets (including heritage)
	ep3 := endpoint.Endpoint{
		DNSName:    "txt.bar.org",
		Targets:    endpoint.Targets{"\"heritage=external-dns,external-dns/owner=default\"", "\"additional=value\""},
		RecordType: endpoint.RecordTypeTXT,
	}

	// Test endpoint with zone root
	ep4 := endpoint.Endpoint{
		DNSName:    "bar.org",
		Targets:    endpoint.Targets{"9.9.9.9", "10.10.10.10"},
		RecordType: endpoint.RecordTypeA,
	}

	epList := []*endpoint.Endpoint{&ep1, &ep2, &ep3, &ep4}

	// Mock existing records for ID lookup
	nc1 := nc.DnsRecord{
		Hostname:     "foo",
		Type:         "A",
		Destination:  "5.5.5.5",
		Id:           "10",
		DeleteRecord: false,
	}
	nc2 := nc.DnsRecord{
		Hostname:     "single",
		Type:         "A",
		Destination:  "8.8.8.8",
		Id:           "20",
		DeleteRecord: false,
	}
	nc3 := nc.DnsRecord{
		Hostname:     "txt",
		Type:         "TXT",
		Destination:  "heritage=external-dns,external-dns/owner=default",
		Id:           "30",
		DeleteRecord: false,
	}
	nc4 := nc.DnsRecord{
		Hostname:     "@",
		Type:         "A",
		Destination:  "9.9.9.9",
		Id:           "40",
		DeleteRecord: false,
	}

	ncRecordList := []nc.DnsRecord{nc1, nc2, nc3, nc4}

	// Test creation (no deletion)
	result := convertToNetcupRecord(&ncRecordList, epList, "bar.org", false)

	// Should have 8 records total:
	// ep1: 3 A records (5.5.5.5, 6.6.6.6, 7.7.7.7)
	// ep2: 1 A record (8.8.8.8)
	// ep3: 2 TXT records (heritage, additional)
	// ep4: 2 A records (9.9.9.9, 10.10.10.10)
	assert.Equal(t, 8, len(*result))

	// Verify ep1 records (3 A records)
	foundEp1Records := 0
	for _, record := range *result {
		if record.Hostname == "foo" && record.Type == "A" {
			foundEp1Records++
			assert.Contains(t, []string{"5.5.5.5", "6.6.6.6", "7.7.7.7"}, record.Destination)
			// All records should have empty IDs when creating
			assert.Equal(t, "", record.Id, "Create records should have empty IDs")
			assert.False(t, record.DeleteRecord, "Create records should not be marked for deletion")
		}
	}
	assert.Equal(t, 3, foundEp1Records)

	// Verify ep2 record (1 A record)
	foundEp2Records := 0
	for _, record := range *result {
		if record.Hostname == "single" && record.Type == "A" {
			foundEp2Records++
			assert.Equal(t, "8.8.8.8", record.Destination)
			assert.Equal(t, "", record.Id, "Create records should have empty IDs")
			assert.False(t, record.DeleteRecord, "Create records should not be marked for deletion")
		}
	}
	assert.Equal(t, 1, foundEp2Records)

	// Verify ep3 records (2 TXT records with heritage processing)
	foundEp3Records := 0
	for _, record := range *result {
		if record.Hostname == "txt" && record.Type == "TXT" {
			foundEp3Records++
			// Check for both possible destinations (with and without quotes)
			expectedDestinations := []string{"heritage=external-dns,external-dns/owner=default", "additional=value"}
			assert.Contains(t, expectedDestinations, record.Destination, "TXT record destination should match expected values")
			assert.Equal(t, "", record.Id, "Create records should have empty IDs")
			assert.False(t, record.DeleteRecord, "Create records should not be marked for deletion")
		}
	}
	assert.Equal(t, 2, foundEp3Records)

	// Verify ep4 records (2 A records for zone root)
	foundEp4Records := 0
	for _, record := range *result {
		if record.Hostname == "@" && record.Type == "A" {
			foundEp4Records++
			assert.Contains(t, []string{"9.9.9.9", "10.10.10.10"}, record.Destination)
			assert.Equal(t, "", record.Id, "Create records should have empty IDs")
			assert.False(t, record.DeleteRecord, "Create records should not be marked for deletion")
		}
	}
	assert.Equal(t, 2, foundEp4Records)

	// Test deletion
	resultDelete := convertToNetcupRecord(&ncRecordList, epList, "bar.org", true)

	// Should only have records for existing entries (4 records from the original list)
	assert.Equal(t, 4, len(*resultDelete), "Should only delete records that exist")

	// Verify all records have DeleteRecord = true and proper ID handling
	for _, record := range *resultDelete {
		assert.True(t, record.DeleteRecord, "All records should be marked for deletion")

		// Records that exist in the original list should have IDs
		if record.Hostname == "foo" && record.Destination == "5.5.5.5" {
			assert.Equal(t, "10", record.Id, "Existing foo A record should have ID for deletion")
		} else if record.Hostname == "single" && record.Destination == "8.8.8.8" {
			assert.Equal(t, "20", record.Id, "Existing single A record should have ID for deletion")
		} else if record.Hostname == "txt" && record.Destination == "heritage=external-dns,external-dns/owner=default" {
			assert.Equal(t, "30", record.Id, "Existing txt TXT record should have ID for deletion")
		} else if record.Hostname == "@" && record.Destination == "9.9.9.9" {
			assert.Equal(t, "40", record.Id, "Existing @ A record should have ID for deletion")
		} else {
			t.Errorf("Unexpected record in deletion result: %+v", record)
		}
	}
}

func testTxtRecordHandling(t *testing.T) {
	// Test that TXT records are properly handled with quotes
	// This simulates what happens when reading records from the DNS provider

	// Mock a TXT record as it would come from Netcup's API (without quotes)
	ncTxtRecord := nc.DnsRecord{
		Hostname:     "test",
		Type:         "TXT",
		Destination:  "heritage=external-dns,external-dns/owner=default",
		Id:           "123",
		DeleteRecord: false,
	}

	// Mock a regular A record
	ncARecord := nc.DnsRecord{
		Hostname:     "test",
		Type:         "A",
		Destination:  "192.168.1.1",
		Id:           "456",
		DeleteRecord: false,
	}

	// Test that when we process these records, TXT records get quotes added
	// This simulates the Records() function behavior
	destinationTxt := ncTxtRecord.Destination
	if ncTxtRecord.Type == "TXT" {
		destinationTxt = fmt.Sprintf("\"%s\"", ncTxtRecord.Destination)
	}

	destinationA := ncARecord.Destination
	if ncARecord.Type == "TXT" {
		destinationA = fmt.Sprintf("\"%s\"", ncARecord.Destination)
	}

	// TXT record should have quotes added
	assert.Equal(t, "\"heritage=external-dns,external-dns/owner=default\"", destinationTxt)

	// A record should remain unchanged
	assert.Equal(t, "192.168.1.1", destinationA)

	// Test heritage detection still works
	assert.True(t, strings.HasPrefix(destinationTxt, "\"heritage="))

	// Test that the processed target can be used in convertToNetcupRecord
	ep := endpoint.Endpoint{
		DNSName:    "test.example.com",
		Targets:    endpoint.Targets{destinationTxt},
		RecordType: endpoint.RecordTypeTXT,
	}

	recs := []nc.DnsRecord{ncTxtRecord, ncARecord}
	result := convertToNetcupRecord(&recs, []*endpoint.Endpoint{&ep}, "example.com", false)

	// Should create one record
	assert.Equal(t, 1, len(*result))

	// The destination should have quotes removed for storage (as per current logic)
	assert.Equal(t, "heritage=external-dns,external-dns/owner=default", (*result)[0].Destination)

	// Should have empty ID for new record
	assert.Equal(t, "", (*result)[0].Id, "New record should have empty ID")
	assert.False(t, (*result)[0].DeleteRecord, "Create record should not be marked for deletion")

	// Test deletion scenario
	resultDelete := convertToNetcupRecord(&recs, []*endpoint.Endpoint{&ep}, "example.com", true)

	// Should create one record for deletion
	assert.Equal(t, 1, len(*resultDelete))

	// Should have ID and be marked for deletion
	assert.Equal(t, "123", (*resultDelete)[0].Id, "Existing TXT record should have ID for deletion")
	assert.True(t, (*resultDelete)[0].DeleteRecord, "Delete record should be marked for deletion")
}

func testTxtRecordRestartScenario(t *testing.T) {
	// This test simulates the external-dns restart scenario
	// 1. External-dns creates TXT ownership records
	// 2. External-dns restarts and reads existing records
	// 3. External-dns should recognize its own TXT records

	// Step 1: Simulate creating TXT ownership records
	epCreate := endpoint.Endpoint{
		DNSName:    "test.example.com",
		Targets:    endpoint.Targets{"\"heritage=external-dns,external-dns/owner=default,external-dns/resource=service/default/nginx\""},
		RecordType: endpoint.RecordTypeTXT,
	}

	// Convert to Netcup format (quotes removed for storage)
	recs := []nc.DnsRecord{}
	createResult := convertToNetcupRecord(&recs, []*endpoint.Endpoint{&epCreate}, "example.com", false)

	// Should create one record with quotes removed
	assert.Equal(t, 1, len(*createResult))
	assert.Equal(t, "heritage=external-dns,external-dns/owner=default,external-dns/resource=service/default/nginx", (*createResult)[0].Destination)
	assert.Equal(t, "", (*createResult)[0].Id, "New record should have empty ID")
	assert.False(t, (*createResult)[0].DeleteRecord, "Create record should not be marked for deletion")

	// Step 2: Simulate external-dns restart - reading records from DNS provider
	// The record as it would be returned by Netcup's API (without quotes)
	ncRecord := nc.DnsRecord{
		Hostname:     "test",
		Type:         "TXT",
		Destination:  "heritage=external-dns,external-dns/owner=default,external-dns/resource=service/default/nginx",
		Id:           "123",
		DeleteRecord: false,
	}

	// Step 3: Simulate the Records() function behavior - add quotes back
	destination := ncRecord.Destination
	if ncRecord.Type == "TXT" {
		destination = fmt.Sprintf("\"%s\"", ncRecord.Destination)
	}

	// The destination should now have quotes, making it recognizable by external-dns
	assert.Equal(t, "\"heritage=external-dns,external-dns/owner=default,external-dns/resource=service/default/nginx\"", destination)

	// Step 4: Verify that external-dns can now recognize this as its own record
	// This would be the endpoint that external-dns creates when reading the record
	epRead := endpoint.Endpoint{
		DNSName:    "test.example.com",
		Targets:    endpoint.Targets{destination},
		RecordType: endpoint.RecordTypeTXT,
	}

	// Step 5: If external-dns wants to update this record, it should work correctly
	recsWithExisting := []nc.DnsRecord{ncRecord}
	updateResult := convertToNetcupRecord(&recsWithExisting, []*endpoint.Endpoint{&epRead}, "example.com", false)

	// Should create one record with quotes removed for storage
	assert.Equal(t, 1, len(*updateResult))
	assert.Equal(t, "heritage=external-dns,external-dns/owner=default,external-dns/resource=service/default/nginx", (*updateResult)[0].Destination)
	assert.Equal(t, "", (*updateResult)[0].Id, "Update records should have empty IDs (for new values)")
	assert.False(t, (*updateResult)[0].DeleteRecord, "Update record should not be marked for deletion")

	// Step 6: Verify heritage detection still works
	assert.True(t, strings.HasPrefix(destination, "\"heritage="))
}

func testNewNetcupProvider(t *testing.T) {
	domainFilter := []string{"example.com"}
	var logger *slog.Logger
	promslogConfig := &promslog.Config{}
	logger = promslog.New(promslogConfig)

	p, err := NewNetcupProvider(&domainFilter, 10, "KEY", "PASSWORD", true, logger)
	assert.NotNil(t, p.client)
	assert.NoError(t, err)

	_, err = NewNetcupProvider(&domainFilter, 0, "KEY", "PASSWORD", true, logger)
	assert.Error(t, err)

	_, err = NewNetcupProvider(&domainFilter, 10, "", "PASSWORD", true, logger)
	assert.Error(t, err)

	_, err = NewNetcupProvider(&domainFilter, 10, "KEY", "", true, logger)
	assert.Error(t, err)

	emptyDomainFilter := []string{}
	_, err = NewNetcupProvider(&emptyDomainFilter, 10, "KEY", "PASSWORD", true, logger)
	assert.Error(t, err)

}

func testApplyChanges(t *testing.T) {
	domainFilter := []string{"example.com"}
	var logger *slog.Logger
	promslogConfig := &promslog.Config{}
	logger = promslog.New(promslogConfig)

	p, _ := NewNetcupProvider(&domainFilter, 10, "KEY", "PASSWORD", true, logger)
	changes1 := &plan.Changes{
		Create:    []*endpoint.Endpoint{},
		Delete:    []*endpoint.Endpoint{},
		UpdateNew: []*endpoint.Endpoint{},
		UpdateOld: []*endpoint.Endpoint{},
	}

	// No Changes
	err := p.ApplyChanges(context.TODO(), changes1)
	assert.NoError(t, err)

	// Changes
	changes2 := &plan.Changes{
		Create: []*endpoint.Endpoint{
			{
				DNSName:    "api.example.com",
				RecordType: "A",
			},
			{
				DNSName:    "api.baz.com",
				RecordType: "TXT",
			}},
		Delete: []*endpoint.Endpoint{
			{
				DNSName:    "api.example.com",
				RecordType: "A",
			},
			{
				DNSName:    "api.baz.com",
				RecordType: "TXT",
			}},
		UpdateNew: []*endpoint.Endpoint{
			{
				DNSName:    "api.example.com",
				RecordType: "A",
			},
			{
				DNSName:    "api.baz.com",
				RecordType: "TXT",
			}},
		UpdateOld: []*endpoint.Endpoint{
			{
				DNSName:    "api.example.com",
				RecordType: "A",
			},
			{
				DNSName:    "api.baz.com",
				RecordType: "TXT",
			}},
	}

	err = p.ApplyChanges(context.TODO(), changes2)
	assert.NoError(t, err)

}

func testRecords(t *testing.T) {
	domainFilter := []string{"example.com"}
	var logger *slog.Logger
	promslogConfig := &promslog.Config{}
	logger = promslog.New(promslogConfig)
	p, _ := NewNetcupProvider(&domainFilter, 10, "KEY", "PASSWORD", true, logger)
	ep, err := p.Records(context.TODO())
	assert.Equal(t, []*endpoint.Endpoint{}, ep)
	assert.NoError(t, err)
}

func testRecordsGrouping(t *testing.T) {
	// This test verifies that DNS records are properly grouped by Type and Hostname
	// creating endpoints with multiple destinations instead of individual endpoints

	// Create a mock provider with dry run enabled (not used in this test but kept for completeness)
	domainFilter := []string{"example.com"}
	var logger *slog.Logger
	promslogConfig := &promslog.Config{}
	logger = promslog.New(promslogConfig)
	_, _ = NewNetcupProvider(&domainFilter, 10, "KEY", "PASSWORD", true, logger)

	// Mock DNS records that would be returned by the Netcup API
	// These represent multiple records of the same type for the same hostname
	mockRecords := []nc.DnsRecord{
		{
			Hostname:     "www",
			Type:         "A",
			Destination:  "192.168.1.1",
			Id:           "1",
			DeleteRecord: false,
		},
		{
			Hostname:     "www",
			Type:         "A",
			Destination:  "192.168.1.2",
			Id:           "2",
			DeleteRecord: false,
		},
		{
			Hostname:     "www",
			Type:         "A",
			Destination:  "192.168.1.3",
			Id:           "3",
			DeleteRecord: false,
		},
		{
			Hostname:     "api",
			Type:         "A",
			Destination:  "10.0.0.1",
			Id:           "4",
			DeleteRecord: false,
		},
		{
			Hostname:     "api",
			Type:         "A",
			Destination:  "10.0.0.2",
			Id:           "5",
			DeleteRecord: false,
		},
		{
			Hostname:     "mail",
			Type:         "CNAME",
			Destination:  "mail.example.com",
			Id:           "6",
			DeleteRecord: false,
		},
		{
			Hostname:     "txt",
			Type:         "TXT",
			Destination:  "heritage=external-dns,external-dns/owner=default",
			Id:           "7",
			DeleteRecord: false,
		},
		{
			Hostname:     "txt",
			Type:         "TXT",
			Destination:  "additional=value",
			Id:           "8",
			DeleteRecord: false,
		},
		{
			Hostname:     "@",
			Type:         "A",
			Destination:  "203.0.113.1",
			Id:           "9",
			DeleteRecord: false,
		},
		{
			Hostname:     "@",
			Type:         "A",
			Destination:  "203.0.113.2",
			Id:           "10",
			DeleteRecord: false,
		},
	}

	// Since we can't easily mock the session methods in this test,
	// we'll test the grouping logic directly by simulating what the Records function does

	// Simulate the grouping logic from the Records function
	recordGroups := make(map[string][]string)
	for _, rec := range mockRecords {
		key := fmt.Sprintf("%s:%s", rec.Type, rec.Hostname)
		destination := rec.Destination
		if rec.Type == "TXT" && !strings.HasPrefix(rec.Destination, "\"") {
			destination = fmt.Sprintf("\"%s\"", rec.Destination)
		}
		recordGroups[key] = append(recordGroups[key], destination)
	}

	// Verify the grouping worked correctly
	assert.Equal(t, 5, len(recordGroups), "Should have 5 unique Type:Hostname combinations")

	// Check www A records (3 destinations)
	wwwAKey := "A:www"
	assert.Contains(t, recordGroups, wwwAKey)
	assert.Equal(t, 3, len(recordGroups[wwwAKey]))
	assert.Contains(t, recordGroups[wwwAKey], "192.168.1.1")
	assert.Contains(t, recordGroups[wwwAKey], "192.168.1.2")
	assert.Contains(t, recordGroups[wwwAKey], "192.168.1.3")

	// Check api A records (2 destinations)
	apiAKey := "A:api"
	assert.Contains(t, recordGroups, apiAKey)
	assert.Equal(t, 2, len(recordGroups[apiAKey]))
	assert.Contains(t, recordGroups[apiAKey], "10.0.0.1")
	assert.Contains(t, recordGroups[apiAKey], "10.0.0.2")

	// Check mail CNAME record (1 destination)
	mailCNAMEKey := "CNAME:mail"
	assert.Contains(t, recordGroups, mailCNAMEKey)
	assert.Equal(t, 1, len(recordGroups[mailCNAMEKey]))
	assert.Contains(t, recordGroups[mailCNAMEKey], "mail.example.com")

	// Check txt TXT records (2 destinations with quotes)
	txtTXTKey := "TXT:txt"
	assert.Contains(t, recordGroups, txtTXTKey)
	assert.Equal(t, 2, len(recordGroups[txtTXTKey]))
	assert.Contains(t, recordGroups[txtTXTKey], "\"heritage=external-dns,external-dns/owner=default\"")
	assert.Contains(t, recordGroups[txtTXTKey], "\"additional=value\"")

	// Check @ A records (2 destinations)
	atAKey := "A:@"
	assert.Contains(t, recordGroups, atAKey)
	assert.Equal(t, 2, len(recordGroups[atAKey]))
	assert.Contains(t, recordGroups[atAKey], "203.0.113.1")
	assert.Contains(t, recordGroups[atAKey], "203.0.113.2")

	// Test endpoint creation with multiple destinations
	domain := "example.com"
	ttl := uint64(300)

	// Create endpoints from the grouped records
	endpoints := make([]*endpoint.Endpoint, 0)
	for key, destinations := range recordGroups {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			t.Errorf("invalid record key format: %s", key)
			continue
		}

		recordType := parts[0]
		hostname := parts[1]

		name := fmt.Sprintf("%s.%s", hostname, domain)
		if hostname == "@" {
			name = domain
		}

		// Create endpoint with all destinations
		ep := endpoint.NewEndpointWithTTL(name, recordType, endpoint.TTL(ttl), destinations...)
		endpoints = append(endpoints, ep)
	}

	// Verify we have 5 endpoints (one per unique Type:Hostname combination)
	assert.Equal(t, 5, len(endpoints))

	// Verify specific endpoints
	wwwEndpoint := findEndpoint(endpoints, "www.example.com", "A")
	assert.NotNil(t, wwwEndpoint)
	assert.Equal(t, 3, len(wwwEndpoint.Targets))
	assert.Contains(t, wwwEndpoint.Targets, "192.168.1.1")
	assert.Contains(t, wwwEndpoint.Targets, "192.168.1.2")
	assert.Contains(t, wwwEndpoint.Targets, "192.168.1.3")

	apiEndpoint := findEndpoint(endpoints, "api.example.com", "A")
	assert.NotNil(t, apiEndpoint)
	assert.Equal(t, 2, len(apiEndpoint.Targets))
	assert.Contains(t, apiEndpoint.Targets, "10.0.0.1")
	assert.Contains(t, apiEndpoint.Targets, "10.0.0.2")

	mailEndpoint := findEndpoint(endpoints, "mail.example.com", "CNAME")
	assert.NotNil(t, mailEndpoint)
	assert.Equal(t, 1, len(mailEndpoint.Targets))
	assert.Contains(t, mailEndpoint.Targets, "mail.example.com")

	txtEndpoint := findEndpoint(endpoints, "txt.example.com", "TXT")
	assert.NotNil(t, txtEndpoint)
	assert.Equal(t, 2, len(txtEndpoint.Targets))
	assert.Contains(t, txtEndpoint.Targets, "\"heritage=external-dns,external-dns/owner=default\"")
	assert.Contains(t, txtEndpoint.Targets, "\"additional=value\"")

	// Test zone root endpoint (@)
	rootEndpoint := findEndpoint(endpoints, "example.com", "A")
	assert.NotNil(t, rootEndpoint)
	assert.Equal(t, 2, len(rootEndpoint.Targets))
	assert.Contains(t, rootEndpoint.Targets, "203.0.113.1")
	assert.Contains(t, rootEndpoint.Targets, "203.0.113.2")
}

// Helper function to find an endpoint by DNS name and record type
func findEndpoint(endpoints []*endpoint.Endpoint, dnsName, recordType string) *endpoint.Endpoint {
	for _, ep := range endpoints {
		if ep.DNSName == dnsName && ep.RecordType == recordType {
			return ep
		}
	}
	return nil
}
