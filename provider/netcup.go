package netcup

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	nc "github.com/aellwein/netcup-dns-api/pkg/v1"
	"golang.org/x/net/idna"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

// NetcupProvider is an implementation of Provider for Netcup DNS.
type NetcupProvider struct {
	provider.BaseProvider
	client       *nc.NetcupDnsClient
	session      *nc.NetcupSession
	domainFilter *endpoint.DomainFilter
	dryRun       bool
	logger       *slog.Logger
}

// NetcupChange includes the changesets that need to be applied to the Netcup CCP API
type NetcupChange struct {
	Create    *[]nc.DnsRecord
	UpdateNew *[]nc.DnsRecord
	UpdateOld *[]nc.DnsRecord
	Delete    *[]nc.DnsRecord
}

// NewNetcupProvider creates a new provider including the netcup CCP API client
func NewNetcupProvider(domainFilterList *[]string, customerID int, apiKey string, apiPassword string, dryRun bool, logger *slog.Logger) (*NetcupProvider, error) {
	domainFilter := endpoint.NewDomainFilter(*domainFilterList)

	if !domainFilter.IsConfigured() {
		return nil, fmt.Errorf("netcup provider requires at least one configured domain in the domainFilter")
	}

	if customerID == 0 {
		return nil, fmt.Errorf("netcup provider requires a customer ID")
	}

	if apiKey == "" {
		return nil, fmt.Errorf("netcup provider requires an API Key")
	}

	if apiPassword == "" {
		return nil, fmt.Errorf("netcup provider requires an API Password")
	}

	client := nc.NewNetcupDnsClient(customerID, apiKey, apiPassword)

	return &NetcupProvider{
		client:       client,
		domainFilter: domainFilter,
		dryRun:       dryRun,
		logger:       logger,
	}, nil
}

// Records delivers the list of Endpoint records for all zones.
func (p *NetcupProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	endpoints := make([]*endpoint.Endpoint, 0)

	if p.dryRun {
		p.logger.Debug("dry run - skipping login")
	} else {
		err := p.ensureLogin()
		if err != nil {
			return nil, err
		}

		defer p.session.Logout() //nolint:errcheck

		for _, domain := range p.domainFilter.Filters {
			// Convert domain to punycode for API calls
			punycodeDomain, err := toPunycode(domain)
			if err != nil {
				return nil, fmt.Errorf("failed to convert domain '%s' to punycode: %w", domain, err)
			}

			// some information is on DNS zone itself, query it first
			zone, err := p.session.InfoDnsZone(punycodeDomain)
			if err != nil {
				return nil, fmt.Errorf("unable to query DNS zone info for domain '%v': %v", domain, err)
			}
			ttl, err := strconv.ParseUint(zone.Ttl, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("unexpected error: unable to convert '%s' to uint64", zone.Ttl)
			}
			// query the records of the domain
			recs, err := p.session.InfoDnsRecords(punycodeDomain)
			if err != nil {
				if p.session.LastResponse != nil && p.session.LastResponse.Status == string(nc.StatusError) && p.session.LastResponse.StatusCode == 5029 {
					p.logger.Debug("no records exist", "domain", domain, "error", err.Error())
				} else {
					return nil, fmt.Errorf("unable to get DNS records for domain '%v': %v", domain, err)
				}
			}
			p.logger.Info("got DNS records for domain", "domain", domain)

			// Group records by Type and Hostname
			recordGroups := make(map[string][]string)
			if recs != nil {
				for _, rec := range *recs {
					key := fmt.Sprintf("%s:%s", rec.Type, rec.Hostname)
					destination := rec.Destination
					if rec.Type == endpoint.RecordTypeMX {
						if rec.Priority != "" {
							destination = fmt.Sprintf("%s %s", rec.Priority, rec.Destination)
						}
					} else if rec.Type == endpoint.RecordTypeTXT && (!strings.HasPrefix(rec.Destination, "\"") || !strings.HasSuffix(rec.Destination, "\"")) {
						destination = fmt.Sprintf("\"%s\"", strings.Trim(rec.Destination, "\""))
					}
					recordGroups[key] = append(recordGroups[key], destination)
				}
			}

			// Create endpoints with multiple destinations
			for key, destinations := range recordGroups {
				parts := strings.SplitN(key, ":", 2)
				if len(parts) != 2 {
					p.logger.Warn("invalid record key format", "key", key)
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
		}
	}
	for _, endpointItem := range endpoints {
		p.logger.Debug("endpoints collected", "endpoints", endpointItem.String())
	}
	return endpoints, nil
}

// ApplyChanges applies a given set of changes in a given zone.
func (p *NetcupProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	if !changes.HasChanges() {
		p.logger.Debug("no changes detected - nothing to do")
		return nil
	}

	if p.dryRun {
		p.logger.Debug("dry run - skipping login")
	} else {
		err := p.ensureLogin()
		if err != nil {
			return err
		}
		defer p.session.Logout() //nolint:errcheck
	}
	perZoneChanges := map[string]*plan.Changes{}

	for _, zoneName := range p.domainFilter.Filters {
		punycodeZone, err := toPunycode(zoneName)
		if err != nil {
			return fmt.Errorf("failed to convert zone name '%s' to punycode: %w", zoneName, err)
		}
		p.logger.Debug("zone detected", "zone", punycodeZone)
		perZoneChanges[punycodeZone] = &plan.Changes{}
	}

	processChanges := func(changeType string, endpoints []*endpoint.Endpoint) {
		for _, ep := range endpoints {
			zoneName := endpointZoneName(ep, p.domainFilter.Filters)
			if zoneName == "" {
				p.logger.Debug("ignoring change since it did not match any zone", "type", changeType, "endpoint", ep)
				continue
			}
			punycodeZone, err := toPunycode(zoneName)
			if err != nil {
				p.logger.Error("failed to convert zone name to punycode", "zone", zoneName, "error", err)
				continue
			}
			p.logger.Debug("planning", "type", changeType, "endpoint", ep, "zone", punycodeZone)

			switch changeType {
			case "create":
				perZoneChanges[punycodeZone].Create = append(perZoneChanges[punycodeZone].Create, ep)
			case "updateOld":
				perZoneChanges[punycodeZone].UpdateOld = append(perZoneChanges[punycodeZone].UpdateOld, ep)
			case "updateNew":
				perZoneChanges[punycodeZone].UpdateNew = append(perZoneChanges[punycodeZone].UpdateNew, ep)
			case "delete":
				perZoneChanges[punycodeZone].Delete = append(perZoneChanges[punycodeZone].Delete, ep)
			}
		}
	}

	processChanges("create", changes.Create)
	processChanges("updateOld", changes.UpdateOld)
	processChanges("updateNew", changes.UpdateNew)
	processChanges("delete", changes.Delete)

	if p.dryRun {
		p.logger.Info("dry run - not applying changes")
		return nil
	}

	// Assemble changes per zone and prepare it for the Netcup API client
	for zoneName, c := range perZoneChanges {
		// Gather records from API to extract the record ID which is necessary for updating/deleting the record
		recs, err := p.session.InfoDnsRecords(zoneName)
		if err != nil {
			if p.session.LastResponse != nil && p.session.LastResponse.Status == string(nc.StatusError) && p.session.LastResponse.StatusCode == 5029 {
				p.logger.Debug("no records exist", "zone", zoneName, "error", err.Error())
			} else {
				p.logger.Error("unable to get DNS records for domain", "zone", zoneName, "error", err.Error())
			}
		}
		change := &NetcupChange{
			Create:    convertToNetcupRecord(recs, c.Create, zoneName, false),
			UpdateNew: convertToNetcupRecord(recs, c.UpdateNew, zoneName, false),
			UpdateOld: convertToNetcupRecord(recs, c.UpdateOld, zoneName, true),
			Delete:    convertToNetcupRecord(recs, c.Delete, zoneName, true),
		}

		// If not in dry run, apply changes
		_, err = p.session.UpdateDnsRecords(zoneName, change.UpdateOld)
		if err != nil {
			return err
		}
		_, err = p.session.UpdateDnsRecords(zoneName, change.Delete)
		if err != nil {
			return err
		}
		_, err = p.session.UpdateDnsRecords(zoneName, change.Create)
		if err != nil {
			return err
		}
		_, err = p.session.UpdateDnsRecords(zoneName, change.UpdateNew)
		if err != nil {
			return err
		}
	}

	p.logger.Debug("update completed")

	return nil
}

// convertToNetcupRecord transforms a list of endpoints into a list of Netcup DNS Records
// returns a pointer to a list of DNS Records
func convertToNetcupRecord(recs *[]nc.DnsRecord, endpoints []*endpoint.Endpoint, zoneName string, DeleteRecord bool) *[]nc.DnsRecord {
	totalRecords := 0
	for _, ep := range endpoints {
		totalRecords += len(ep.Targets)
	}
	records := make([]nc.DnsRecord, 0, totalRecords)

	punycodeZone, _ := toPunycode(zoneName)

	for _, ep := range endpoints {
		punycodeDNS, _ := toPunycode(ep.DNSName)
		recordName := strings.TrimSuffix(ep.DNSName, "."+zoneName)
		if recordName == ep.DNSName {
			recordName = strings.TrimSuffix(punycodeDNS, "."+punycodeZone)
		}
		if recordName == zoneName || recordName == punycodeZone || ep.DNSName == zoneName || punycodeDNS == punycodeZone {
			recordName = "@"
		}

		for _, target := range ep.Targets {
			priority := ""
			destination := strings.Trim(target, "\"")

			if ep.RecordType == endpoint.RecordTypeMX {
				parts := strings.Fields(strings.TrimSpace(destination))
				if len(parts) == 2 {
					_, err := strconv.ParseUint(parts[0], 10, 16)
					if err == nil {
						priority = parts[0]
						destination = parts[1]
					}
				}
			}

			id := ""
			if DeleteRecord {
				id = getIDforRecord(recordName, target, ep.RecordType, recs)
				if id == "" {
					continue
				}
			}

			record := nc.DnsRecord{
				Type:         ep.RecordType,
				Hostname:     recordName,
				Priority:     priority,
				Destination:  destination,
				Id:           id,
				DeleteRecord: DeleteRecord,
			}
			records = append(records, record)
		}
	}

	return &records
}

// getIDforRecord compares the endpoint with existing records to get the ID from Netcup to ensure it can be safely removed.
// returns empty string if no match found
func getIDforRecord(recordName string, target string, recordType string, recs *[]nc.DnsRecord) string {
	if recs == nil {
		return ""
	}
	targetToCompare := strings.Trim(target, "\"")
	priorityToCompare := ""
	if recordType == endpoint.RecordTypeMX {
		parts := strings.Fields(strings.TrimSpace(targetToCompare))
		if len(parts) == 2 {
			_, err := strconv.ParseUint(parts[0], 10, 16)
			if err == nil {
				priorityToCompare = parts[0]
				targetToCompare = parts[1]
			}
		}
	}

	for _, rec := range *recs {
		recDestinationToCompare := strings.Trim(rec.Destination, "\"")

		if recordType == rec.Type && targetToCompare == recDestinationToCompare && rec.Hostname == recordName {
			if recordType == endpoint.RecordTypeMX && priorityToCompare != "" && rec.Priority != priorityToCompare {
				continue
			}
			return rec.Id
		}
	}

	return ""
}

// endpointZoneName determines zoneName for endpoint by taking longest suffix zoneName match in endpoint DNSName
// returns empty string if no match found
func endpointZoneName(endpoint *endpoint.Endpoint, zones []string) (zone string) {
	var matchZoneName = ""
	epPuny, _ := toPunycode(endpoint.DNSName)
	for _, zoneName := range zones {
		zonePuny, _ := toPunycode(zoneName)
		if (strings.HasSuffix(endpoint.DNSName, zoneName) || strings.HasSuffix(epPuny, zonePuny)) && len(zoneName) > len(matchZoneName) {
			matchZoneName = zoneName
		}
	}
	return matchZoneName
}

// ensureLogin makes sure that we are logged in to Netcup API.
func (p *NetcupProvider) ensureLogin() error {
	p.logger.Debug("performing login to Netcup DNS API")
	session, err := p.client.Login()
	if err != nil {
		return err
	}
	p.session = session
	p.logger.Debug("successfully logged in to Netcup DNS API")
	return nil
}

// toPunycode converts a domain name to punycode format
// This is necessary for umlaut domains (e.g., müller.de -> xn--mller-kva.de)
func toPunycode(domain string) (string, error) {
	punycode, err := idna.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("failed to convert domain '%s' to punycode: %w", domain, err)
	}

	return punycode, nil
}
