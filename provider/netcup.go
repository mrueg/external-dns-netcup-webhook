package netcup

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	nc "github.com/aellwein/netcup-dns-api/pkg/v1"

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
		p.logger.DebugContext(ctx, "dry run - skipping login")
	} else {
		err := p.ensureLogin()
		if err != nil {
			return nil, err
		}

		defer p.session.Logout() //nolint:errcheck

		for _, domain := range p.domainFilter.Filters {
			// some information is on DNS zone itself, query it first
			zone, err := p.session.InfoDnsZone(domain)
			if err != nil {
				p.logger.ErrorContext(ctx, "unable to query DNS zone info for domain", "domain", domain, "error", err.Error())
				continue
				//return nil, fmt.Errorf("unable to query DNS zone info for domain '%v': %v", domain, err)
			}
			ttl, err := strconv.ParseUint(zone.Ttl, 10, 64)
			if err != nil {
				p.logger.ErrorContext(ctx, "unable to parse TTL for domain", "domain", domain, "error", err.Error())
				continue
				//return nil, fmt.Errorf("unexpected error: unable to convert '%s' to uint64", zone.Ttl)
			}
			// query the records of the domain
			recs, err := p.session.InfoDnsRecords(domain)
			if err != nil {
				if p.session.LastResponse != nil && p.session.LastResponse.Status == string(nc.StatusError) && p.session.LastResponse.StatusCode == 5029 {
					p.logger.InfoContext(ctx, "no records exist", "domain", domain, "error", err.Error())
					continue
				} else {
					p.logger.ErrorContext(ctx, "unable to get DNS records for domain", "domain", domain, "error", err.Error())
					continue
					//return nil, fmt.Errorf("unable to get DNS records for domain '%v': %v", domain, err)
				}
			}
			p.logger.InfoContext(ctx, "got DNS records for domain", "domain", domain)

			// TODO: move this into a separate function, so it can be covered in tests
			for _, rec := range *recs {
				name := fmt.Sprintf("%s.%s", rec.Hostname, domain)
				if rec.Hostname == "@" || rec.Hostname == "" {
					name = domain
				}

				// join multiple A/AAAA records for the same name
				// external-dns supports multiple targets, netcup does not
				if rec.Type == endpoint.RecordTypeA || rec.Type == endpoint.RecordTypeAAAA {
					if appendToExistingEndpoint(endpoints, name, rec) {
						p.logger.DebugContext(ctx, "added to existing Endpoint", "rec", rec)
						continue
					}
				}

				dest := rec.Destination
				if rec.Type == endpoint.RecordTypeMX {
					// MX record format is: "10 mail.foo.bar"
					dest = fmt.Sprintf("%s %s", rec.Priority, dest)
				}

				ep := endpoint.NewEndpointWithTTL(name, rec.Type, endpoint.TTL(ttl), dest)
				endpoints = append(endpoints, ep)
				p.logger.DebugContext(ctx, "add endpoint", "endpoint", ep.String(), "id", rec.Id)
			}
		}
	}
	return endpoints, nil
}

// ApplyChanges applies a given set of changes in a given zone.
func (p *NetcupProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	if !changes.HasChanges() {
		p.logger.DebugContext(ctx, "no changes detected - nothing to do")
		return nil
	}

	if p.dryRun {
		p.logger.DebugContext(ctx, "dry run - skipping login")
	} else {
		err := p.ensureLogin()
		if err != nil {
			return err
		}
		defer p.session.Logout() //nolint:errcheck
	}
	perZoneChanges := map[string]*plan.Changes{}

	for _, zoneName := range p.domainFilter.Filters {
		p.logger.DebugContext(ctx, "zone detected", "zone", zoneName)

		perZoneChanges[zoneName] = &plan.Changes{}
	}

	for _, ep := range changes.Create {
		zoneName := endpointZoneName(ep, p.domainFilter.Filters)
		if zoneName == "" {
			p.logger.DebugContext(ctx, "ignoring change since it did not match any zone", "type", "create", "endpoint", ep)
			continue
		}
		p.logger.DebugContext(ctx, "planning", "type", "create", "endpoint", ep, "zone", zoneName)

		perZoneChanges[zoneName].Create = append(perZoneChanges[zoneName].Create, ep)
	}

	for _, ep := range changes.UpdateOld {
		zoneName := endpointZoneName(ep, p.domainFilter.Filters)
		if zoneName == "" {
			p.logger.DebugContext(ctx, "ignoring change since it did not match any zone", "type", "updateOld", "endpoint", ep)
			continue
		}
		p.logger.DebugContext(ctx, "planning", "type", "updateOld", "endpoint", ep, "zone", zoneName)

		perZoneChanges[zoneName].UpdateOld = append(perZoneChanges[zoneName].UpdateOld, ep)
	}

	for _, ep := range changes.UpdateNew {
		zoneName := endpointZoneName(ep, p.domainFilter.Filters)
		if zoneName == "" {
			p.logger.DebugContext(ctx, "ignoring change since it did not match any zone", "type", "updateNew", "endpoint", ep)
			continue
		}
		p.logger.DebugContext(ctx, "planning", "type", "updateNew", "endpoint", ep, "zone", zoneName)
		perZoneChanges[zoneName].UpdateNew = append(perZoneChanges[zoneName].UpdateNew, ep)
	}

	for _, ep := range changes.Delete {
		zoneName := endpointZoneName(ep, p.domainFilter.Filters)
		if zoneName == "" {
			p.logger.DebugContext(ctx, "ignoring change since it did not match any zone", "type", "delete", "endpoint", ep)
			continue
		}
		p.logger.DebugContext(ctx, "planning", "type", "delete", "endpoint", ep, "zone", zoneName)
		perZoneChanges[zoneName].Delete = append(perZoneChanges[zoneName].Delete, ep)
	}

	if p.dryRun {
		p.logger.InfoContext(ctx, "dry run - not applying changes")
		return nil
	}

	// Assemble changes per zone and prepare it for the Netcup API client
	for zoneName, c := range perZoneChanges {
		// Gather records from API to extract the record ID which is necessary for updating/deleting the record
		recs, err := p.session.InfoDnsRecords(zoneName)
		if err != nil {
			if p.session.LastResponse != nil && p.session.LastResponse.Status == string(nc.StatusError) && p.session.LastResponse.StatusCode == 5029 {
				p.logger.InfoContext(ctx, "no records exist", "zone", zoneName, "error", err.Error())
				continue
			} else {
				p.logger.ErrorContext(ctx, "unable to get DNS records for domain", "zone", zoneName, "error", err.Error())
				continue
			}
		}
		change := &NetcupChange{
			Create:    convertToNetcupRecord(recs, c.Create, zoneName, false),
			UpdateNew: convertToNetcupRecord(recs, c.UpdateNew, zoneName, false),
			UpdateOld: convertToNetcupRecord(recs, c.UpdateOld, zoneName, true),
			Delete:    convertToNetcupRecord(recs, c.Delete, zoneName, true),
		}

		// If not in dry run, apply changes
		// we don't need to delete old records, we can just update
		//p.logger.DebugContext(ctx, fmt.Sprintf("UpdateOld"), "zone", zoneName, "records", change.UpdateOld)
		//_, err = p.session.UpdateDnsRecords(zoneName, change.UpdateOld)
		//if err != nil {
		//	return err
		//}
		p.logger.DebugContext(ctx, "Delete", "zone", zoneName, "records", change.Delete)
		_, err = p.session.UpdateDnsRecords(zoneName, change.Delete)
		if err != nil {
			return err
		}
		p.logger.DebugContext(ctx, "Create", "zone", zoneName, "records", change.Create)
		_, err = p.session.UpdateDnsRecords(zoneName, change.Create)
		if err != nil {
			return err
		}
		p.logger.DebugContext(ctx, "UpdateNew", "zone", zoneName, "records", change.UpdateNew)
		_, err = p.session.UpdateDnsRecords(zoneName, change.UpdateNew)
		if err != nil {
			return err
		}
	}

	p.logger.DebugContext(ctx, "update completed")

	return nil
}

// convertToNetcupRecord transforms a list of endpoints into a list of Netcup DNS Records
// returns a pointer to a list of DNS Records
func convertToNetcupRecord(recs *[]nc.DnsRecord, endpoints []*endpoint.Endpoint, zoneName string, DeleteRecord bool) *[]nc.DnsRecord {
	records := []nc.DnsRecord{}
	for _, ep := range endpoints {
		recordName := strings.TrimSuffix(ep.DNSName, "."+zoneName)
		if recordName == zoneName {
			recordName = "@"
		}
		target := ep.Targets[0]
		if ep.RecordType == endpoint.RecordTypeTXT && strings.HasPrefix(target, "\"heritage=") {
			target = strings.Trim(ep.Targets[0], "\"")
		}
		priority := ""
		if ep.RecordType == endpoint.RecordTypeMX {
			// MX record target includes priority: "10 mail.foo.bar"
			// FIXME: this ignores all errors, i.e. only applies if the format matches
			parts := strings.Fields(strings.TrimSpace(target))
			if len(parts) == 2 {
				_, err := strconv.ParseUint(parts[0], 10, 16)
				if err == nil {
					priority = parts[0]
					target = parts[1]
				}
			}
		}

		records = append(records, nc.DnsRecord{
			Id:           getIDforRecord(recordName, target, ep.RecordType, recs),
			Hostname:     recordName,
			Type:         ep.RecordType,
			Priority:     priority,
			Destination:  target,
			DeleteRecord: DeleteRecord,
		})

		// split A/AAAA multiple targets into separate records, because nc.DnsRecord only supports one target
		if ep.RecordType == endpoint.RecordTypeA || ep.RecordType == endpoint.RecordTypeAAAA {
			for _, target := range ep.Targets[1:] {
				records = append(records, nc.DnsRecord{
					Id:           getIDforRecord(recordName, target, ep.RecordType, recs),
					Hostname:     recordName,
					Type:         ep.RecordType,
					Priority:     priority,
					Destination:  target,
					DeleteRecord: DeleteRecord,
				})
			}
		}
	}
	return &records
}

// getIDforRecord compares the endpoint with existing records to get the ID from Netcup to ensure it can be safely removed.
// returns empty string if no match found
func getIDforRecord(recordName string, target string, recordType string, recs *[]nc.DnsRecord) string {
	for _, rec := range *recs {
		if recordType == rec.Type && target == rec.Destination && rec.Hostname == recordName {
			return rec.Id
		}
	}

	return ""
}

// endpointZoneName determines zoneName for endpoint by taking longest suffix zoneName match in endpoint DNSName
// returns empty string if no match found
func endpointZoneName(endpoint *endpoint.Endpoint, zones []string) (zone string) {
	var matchZoneName = ""
	for _, zoneName := range zones {
		if strings.HasSuffix(endpoint.DNSName, zoneName) && len(zoneName) > len(matchZoneName) {
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

// appendToExistingEndpoint appends the destination of the given record to an existing record with same name and type
func appendToExistingEndpoint(endpoints []*endpoint.Endpoint, name string, record nc.DnsRecord) bool {
	for i, ep := range endpoints {
		if ep.DNSName == name && ep.RecordType == record.Type {
			endpoints[i].Targets = append(ep.Targets, record.Destination)
			return true
		}
	}
	return false
}
