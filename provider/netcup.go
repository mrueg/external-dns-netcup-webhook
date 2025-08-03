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
		p.logger.Debug("dry run - skipping login")
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
				return nil, fmt.Errorf("unable to query DNS zone info for domain '%v': %v", domain, err)
			}
			ttl, err := strconv.ParseUint(zone.Ttl, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("unexpected error: unable to convert '%s' to uint64", zone.Ttl)
			}
			// query the records of the domain
			recs, err := p.session.InfoDnsRecords(domain)
			if err != nil {
				if p.session.LastResponse != nil && p.session.LastResponse.Status == string(nc.StatusError) && p.session.LastResponse.StatusCode == 5029 {
					p.logger.Debug("no records exist", "domain", domain, "error", err.Error())
				} else {
					return nil, fmt.Errorf("unable to get DNS records for domain '%v': %v", domain, err)
				}
			}
			p.logger.Info("got DNS records for domain", "domain", domain)
			for _, rec := range *recs {
				name := fmt.Sprintf("%s.%s", rec.Hostname, domain)
				if rec.Hostname == "@" {
					name = domain
				}

				ep := endpoint.NewEndpointWithTTL(name, rec.Type, endpoint.TTL(ttl), rec.Destination)
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
		p.logger.Debug("zone detected", "zone", zoneName)

		perZoneChanges[zoneName] = &plan.Changes{}
	}

	for _, ep := range changes.Create {
		zoneName := endpointZoneName(ep, p.domainFilter.Filters)
		if zoneName == "" {
			p.logger.Debug("ignoring change since it did not match any zone", "type", "create", "endpoint", ep)
			continue
		}
		p.logger.Debug("planning", "type", "create", "endpoint", ep, "zone", zoneName)

		perZoneChanges[zoneName].Create = append(perZoneChanges[zoneName].Create, ep)
	}

	for _, ep := range changes.UpdateOld {
		zoneName := endpointZoneName(ep, p.domainFilter.Filters)
		if zoneName == "" {
			p.logger.Debug("ignoring change since it did not match any zone", "type", "updateOld", "endpoint", ep)
			continue
		}
		p.logger.Debug("planning", "type", "updateOld", "endpoint", ep, "zone", zoneName)

		perZoneChanges[zoneName].UpdateOld = append(perZoneChanges[zoneName].UpdateOld, ep)
	}

	for _, ep := range changes.UpdateNew {
		zoneName := endpointZoneName(ep, p.domainFilter.Filters)
		if zoneName == "" {
			p.logger.Debug("ignoring change since it did not match any zone", "type", "updateNew", "endpoint", ep)
			continue
		}
		p.logger.Debug("planning", "type", "updateNew", "endpoint", ep, "zone", zoneName)
		perZoneChanges[zoneName].UpdateNew = append(perZoneChanges[zoneName].UpdateNew, ep)
	}

	for _, ep := range changes.Delete {
		zoneName := endpointZoneName(ep, p.domainFilter.Filters)
		if zoneName == "" {
			p.logger.Debug("ignoring change since it did not match any zone", "type", "delete", "endpoint", ep)
			continue
		}
		p.logger.Debug("planning", "type", "delete", "endpoint", ep, "zone", zoneName)
		perZoneChanges[zoneName].Delete = append(perZoneChanges[zoneName].Delete, ep)
	}

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
	records := make([]nc.DnsRecord, len(endpoints))

	for i, ep := range endpoints {
		recordName := strings.TrimSuffix(ep.DNSName, "."+zoneName)
		if recordName == zoneName {
			recordName = "@"
		}
		target := ep.Targets[0]
		if ep.RecordType == endpoint.RecordTypeTXT && strings.HasPrefix(target, "\"heritage=") {
			target = strings.Trim(ep.Targets[0], "\"")
		}

		records[i] = nc.DnsRecord{
			Type:         ep.RecordType,
			Hostname:     recordName,
			Destination:  target,
			Id:           getIDforRecord(recordName, target, ep.RecordType, recs),
			DeleteRecord: DeleteRecord,
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
