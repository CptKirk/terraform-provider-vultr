---
layout: "vultr"
page_title: "Vultr: vultr_reverse_ipv4"
sidebar_current: "docs-vultr-resource-reverse-ipv4"
description: |-
  Provides a Vultr Reverse IPv4 resource. This can be used to create, read, and modify reverse DNS records for IPv4 addresses.
---

# vultr_reverse_ipv4

Provides a Vultr Reverse IPv4 resource. This can be used to create, read, and
modify reverse DNS records for IPv4 addresses. Upon success, DNS
changes may take 6-12 hours to become active.

## Example Usage

Create a new reverse DNS record for an IPv4 address:

```hcl
resource "vultr_server" "my_server" {
	plan_id = "201"
	region_id = "6"
	os_id = "167"
	enable_ipv4 = true
}

resource "vultr_reverse_ipv4" "my_reverse_ipv4" {
	instance_id = "${vultr_server.my_server.id}"
	ip = "${vultr_server.my_server.main_ip}"
	reverse = "host.example.com"
}
```

## Argument Reference

The following arguments are supported:

* `instance_id` - (Required) The ID of the server you want to set an IPv4
  reverse DNS record for.
* `ip` - (Required) The IPv4 address used in the reverse DNS record.
* `reverse` - (Required) The hostname used in the IPv4 reverse DNS record.

## Attributes Reference

The following attributes are exported:

* `id` - The ID is the IPv4 address in canonical format.
* `instance_id` - The ID of the server the IPv4 reverse DNS record was set for.
* `ip` - The IPv4 address in canonical format used in the reverse DNS record.
* `reverse` - The hostname used in the IPv4 reverse DNS record.
