from illumio import PolicyComputeEngine
import csv
import os
 
# Set the API credentials
auth_username = os.environ.get("illumio_auth_username")
secret = os.environ.get("illumio_secret")

# Create the PCE and authenticate
pce = PolicyComputeEngine(url='https://pce.lot48labs.com:8443', port='8443', version='v2', org_id='1')
pce.set_credentials(auth_username, secret)

# Create a dictionary of services, labels, and IP lists for look ups
iplist_href = {}
service_href = {}
label_href = {}
iplists = pce.ip_lists.get()
for iplist in iplists:
    iplist_href[iplist.href] = iplist

services = pce.services.get()
for service in services:
    service_href[service.href] = service

labels = pce.labels.get()
for label in labels:
   label_href[label.href] = label

# Start the CSV output
csv_data = [["ruleset", "srcs", "dsts", "services"]]

# Setup a protocol map to convert proto to value
proto_map = {
    6: "TCP",
    17: "UDP"
}

# Get the all rulesets out of the PCE (could optionally pass in parameters to filter)
rulesets = pce.rule_sets.get()

# Iterate over each ruleset
for ruleset in rulesets:
    # Iterate over each rule in the ruleset
    for rule in ruleset.rules:
        # Process sources
        srcs = []
        for src in rule.consumers:
            if src.actors != None:
                srcs.append("all workloads")
            if src.label != None:
                srcs.append(label_href[src.label.href].key + ":" + label_href[src.label.href].value)
            if src.ip_list != None:
                srcs.append("ipl:" + iplist_href[src.ip_list.href].name)
        # Process destinations
        dsts = []
        for dst in rule.providers:
            if dst.actors != None:
                dsts.append("all workloads")
            if dst.label != None:
                dsts.append(label_href[dst.label.href].key + ":" + label_href[dst.label.href].value)
            if dst.ip_list != None:
                dsts.append("ipl" + iplist_href[dst.ip_list.href].name)
        # Process services
        services = []
        for service in rule.ingress_services:
            if hasattr(service, 'href'):
                services.append(service_href[service.href].name)
            if hasattr(service, 'port'):
                if service.icmp_type != None or service.icmp_code != None:
                    services.append("ICMP")
                elif service.to_port != None:
                    service.append(f"{service.port}-{service.to_port} {proto_map[service.proto]}")
                else:
                    services.append(f"{service.port} {proto_map[service.proto]}")
        # Add to csv output
        csv_data.append([ruleset.name, ";".join(srcs), ";".join(dsts), ";".join(services)])

# Output the file
filename = "rules.csv"
with open(filename, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerows(csv_data)

print(f"csv written to {filename}")

