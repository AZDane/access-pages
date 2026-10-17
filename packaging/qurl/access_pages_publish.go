package main

// Access Pages compatibility patch for qURL 3.5.0. The deployed LayerV API
// rejects the new private field. This opt-in path is only for the public
// transport resources whose guest authorization is enforced by Access Pages.
// Remove with the patch when an official release passes the fresh-resource probe.

import (
	"context"
	"fmt"
	"regexp"

	connectorshare "github.com/layervai/qurl-connector/pkg/share"
	qurl "github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-integrations/apps/cli/internal/connector/agent"
)

var accessPagesResourceID = regexp.MustCompile(`^ha-(page|guest)-[0-9a-f]{40}$`)

func prepareAccessPagesPublicResource(ctx context.Context, opts *globalOpts, enrollment *localEnrollment, stateDir string, cfg *connectorshare.NativeRuntimeConfig) (*agent.ResolvedResource, string, error) {
	if !enrollment.access.Public || enrollment.access.AllowRequests || len(enrollment.access.AllowedDeviceKeys) != 0 || !accessPagesResourceID.MatchString(enrollment.requestedID) {
		return nil, "", fmt.Errorf("%w: Access Pages compatibility requires an explicit public page or guest resource without device grants", qurl.ErrInvalidResourceRequest)
	}
	// Use the signed native find-or-create protocol. Never manufacture a
	// successful response to a failed REST request or retry an arbitrary 400.
	var requestedID string
	resolved, err := opts.resolveLocalResource(ctx, cfg, func(agentID string) (string, error) {
		id, err := enrollment.resolveID(ctx, stateDir, agentID)
		requestedID = id
		return id, err
	})
	if err != nil {
		return nil, "", err
	}
	if requestedID != enrollment.requestedID || resolved == nil || resolved.Resource == nil || resolved.Resource.Slug != requestedID {
		return nil, "", fmt.Errorf("%w: Access Pages Connector resource does not match the requested identity", qurl.ErrInvalidAPIResponse)
	}
	client, err := opts.newClient(ctx)
	if err != nil {
		return nil, "", err
	}
	// Confirm the owner-facing row names the same signed resource before any
	// serving mutation. Reject a known private/restricted row; never relax it.
	row, err := client.Resource(ctx, resolved.Resource.CRID)
	if err != nil {
		return nil, "", err
	}
	if row == nil || row.Type != "tunnel" || row.CRID != resolved.Resource.CRID || row.ResourceID != resolved.Resource.ResourcePublicKey {
		return nil, "", fmt.Errorf("%w: Access Pages resource read-back identity mismatch", qurl.ErrInvalidAPIResponse)
	}
	if (row.Private != nil && *row.Private) || (resolved.Private != nil && *resolved.Private) || (row.AccessRequests != nil && *row.AccessRequests) || len(row.AllowedDeviceKeys) != 0 || len(row.AllowedPasskeys) != 0 {
		return nil, "", fmt.Errorf("%w: Access Pages compatibility cannot publish a restricted resource", qurl.ErrInvalidAPIResponse)
	}
	// Older deployments omit privacy. Preserve that as unknown, not a false
	// assertion that the service confirmed public access. Access Pages already
	// requests public transport and enforces its own guest grants at the endpoint.
	resolved.Private = row.Private
	resolved.AccessRequests = row.AccessRequests
	knockID, err := agent.KnockResourceID(resolved.Resource)
	if err != nil {
		return nil, "", err
	}
	return resolved, knockID, nil
}
