package main

import (
	"encoding/json"
	"fmt"
	"os"
	"context"
	"strings"

	"github.com/jayground8/cert-manager-ncpcloud-webhook/client"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&ncpDNSProviderSolver{},
	)
}

// ncpDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type ncpDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	//client kubernetes.Clientset
	ncpDNSClient *openapi.APIClient
}

// ncpDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type ncpDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	//APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *ncpDNSProviderSolver) Name() string {
	return "ncp-dns-solver"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *ncpDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	// TODO: do something more useful with the decoded configuration
	fmt.Printf("Decoded configuration %v", cfg)

	// TODO: add code that sets a record in the DNS provider's console
	config := openapi.NewConfiguration()
	client := openapi.NewAPIClient(config)
	c.ncpDNSClient = client
	domainName := strings.TrimSuffix(ch.ResolvedZone, ".")
	domainId := c.getDomainId(client, domainName)
	host := strings.Split(ch.ResolvedFQDN, ".")[0]
	recordId := c.getRecordId(client, domainId, "TXT", host, ch.Key)
	if recordId == nil {
		c.createRecord(client, domainId, host, "TXT", ch.Key, 300)
		c.applyRecordChange(client, domainId)
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *ncpDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	// TODO: add code that deletes a record from the DNS provider's console
	domainName := strings.TrimSuffix(ch.ResolvedZone, ".")
	domainId := c.getDomainId(c.ncpDNSClient, domainName)
	host := strings.Split(ch.ResolvedFQDN, ".")[0]
	recordId := c.getRecordId(c.ncpDNSClient, domainId, "TXT", host, ch.Key)
	if recordId != nil {
		c.deleteRecord(c.ncpDNSClient, domainId, *recordId)
		c.applyRecordChange(c.ncpDNSClient, domainId)
	} 
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *ncpDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER

	//cl, err := kubernetes.NewForConfig(kubeClientConfig)
	//if err != nil {
	//	return err
	//}
	//
	//c.client = cl

	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (ncpDNSProviderConfig, error) {
	cfg := ncpDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *ncpDNSProviderSolver) getDomainId(client *openapi.APIClient, domainName string) *int64 {
	req := client.DefaultAPI.GetDomain(context.Background()).
		Page(0).
		Size(10).
		DomainName(domainName)
	value, res, err := client.DefaultAPI.GetDomainExecute(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", res)
		panic(err)
	}

	if res.StatusCode != 200 || len(value.GetContent()) <= 0 {
		return nil
	}

	content := value.GetContent()[0]

	return content.Id
}

func (c *ncpDNSProviderSolver) applyRecordChange(client *openapi.APIClient, domainId *int64) {
	req := client.DefaultAPI.ApplyRecordChange(context.Background(), *domainId)
	res, err := client.DefaultAPI.ApplyRecordChangeExecute(req)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", res)
		panic(err)
	}
}

func (c *ncpDNSProviderSolver) getRecordId(client *openapi.APIClient, domainId *int64, recordType string, recordName string, recordValue string) *int64 {
	req := client.DefaultAPI.GetRecord(context.Background(), *domainId).
		Page(0).
		Size(10).
		RecordType(recordType)

	value, res, err := client.DefaultAPI.GetRecordExecute(req)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", res)
		panic(err)
	}

	for _, c := range value.GetContent() {
		if c.GetHost() == recordName && c.GetContent() == fmt.Sprintf("\"%s\"", recordValue) {
			recordId := c.GetId()
			return &recordId
		}
	}

	return nil
}

func (c *ncpDNSProviderSolver) createRecord(client *openapi.APIClient, domainId *int64, host string, recordType string, content string, ttl int64) {
	body := []openapi.CreateRecordRequestInner{{Host: host, Type: recordType, Content: content, Ttl: ttl}}
	req := client.DefaultAPI.CreateRecord(context.Background(), *domainId).
		CreateRecordRequestInner(body)
	res, err := client.DefaultAPI.CreateRecordExecute(req)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", res)
		panic(err)
	}
}

func (c *ncpDNSProviderSolver) deleteRecord(client *openapi.APIClient, domainId *int64, recordId int64) {
	req := client.DefaultAPI.DeleteRecord(context.Background(), *domainId).RequestBody([]int64{recordId})
	res, err := client.DefaultAPI.DeleteRecordExecute(req)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", res)
		panic(err)
	}
}
