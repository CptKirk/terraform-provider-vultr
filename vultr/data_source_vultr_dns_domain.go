package vultr

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/vultr/govultr"
)

func dataSourceVultrDnsDomain() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceVultrDnsDomainRead,
		Schema: map[string]*schema.Schema{
			"domain": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.NoZeroValues,
			},
			"date_created": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"dnssec_info": {
				Type:        schema.TypeList,
				Description: "test",
				Computed:    true,
				Elem:        schema.TypeMap,
			},
		},
	}
}

func dataSourceVultrDnsDomainRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*Client).govultrClient()

	domain := d.Get("domain").(string)

	dnsDomains, err := client.DNSDomain.List(context.Background())
	if err != nil {
		return fmt.Errorf("error getting dns domains: %v", err)
	}

	dnsList := []govultr.DNSDomain{}

	for _, d := range dnsDomains {
		if d.Domain == domain {
			dnsList = append(dnsList, d)
		}
	}

	if len(dnsList) > 1 {
		return errors.New("your search returned too many results. Please refine your search to be more specific")
	}

	if len(dnsList) < 1 {
		return errors.New("no results were found")
	}

	d.SetId(dnsDomains[0].Domain)
	d.Set("date_created", dnsDomains[0].DateCreated)

	dnssecInfo, err := client.DNSDomain.DNSSecInfo(context.Background(), domain)
	if err != nil {
		return fmt.Errorf("error getting dnssec info: %v", err)
	}

	result := make([]map[string]string, 0)

	for _, member := range dnssecInfo {
		main := strings.Split(member, ";")
		mainSplitted := strings.Split(main[0], " ")

		if mainSplitted[5] == "1" || mainSplitted[5] == "2" {
			dnssecMap := make(map[string]string, 4)
			dnssecMap["keyTag"] = mainSplitted[3]
			dnssecMap["algorithm"] = mainSplitted[4]
			dnssecMap["digestType"] = mainSplitted[5]
			dnssecMap["digest"] = mainSplitted[6]

			result = append(result, dnssecMap)
		} else {
			continue
		}
	}

	d.Set("dnssec_info", result)

	return nil
}
