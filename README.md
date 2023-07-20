# Packet Hunter

This tool scans large packet capture files (pcapng) for interesting data and dumps the output into separate files for later analysis. 

Let's say you have multiple large captures from Wireshark, and you are only interested in HTTP only traffic (not HTTPS), then Packet Hunter will
extract the necessary packets from the input files and merge them into a single file. If you are only interested in TLS traffic that is older 
than TLS 1.2, then Packet Hunter can extract the necessary packets.

**Usage**
```
usage: packet_hunter.py [-h] [-i SOURCE] [-d DESTINATION] [-c CONFIG] [-f FILTER]

Extract packet data for threat hunting

options:
  -i SOURCE      - Path to a packet capture file (pcapng)
  -d DESTINATION - Path to store extracted files
  -c CONFIG      - Path to configuration
  -f FILTER      - Specific filters from the filter config to apply (i.e. -f dns nmap-scan http)
```
## Config
The configuration file defines what filters to apply when reading the packet capture file(s).

```yaml
dns:
  filter: dns
strange-ports:
  filter: "!tcp.port in {22,23,25,80,443,445,993,995,8000..8005}"
tls-version:
  filter: "tls.handshake.version < 0x0303"
nmap-scan:
  filter: "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size<=1024"
bad-country:
  filter: "ip.geoip.country_iso in {CN,RU,NK}"
http:
  filter: 'http'
```

In the example above, the following filters are defined:

- dns (filtered results showing DNS requests)
- strange-ports (filtered results showing non-standard ports)
- tls-version (filtered results showing TLS requests older than 1.2)
- nmap (filtered results showing possible nmap scans)
- country (filtered results showing results limited to specific countries)
- http (filtered results showing http only traffic - not https)

When scanning, a directory for each filter is created and the corresponding filtered output will be dumped to that directory.

## Use cases
### Scanning a single capture file
`packet_hunter.py -i ~/captures/dump.pcapng -d ~/captures/output -c packhunt.conf`

This will use the default config `/etc/packhunt/packhunt.conf` and will populate the following directories with filtered results:

- dns 
- strange-ports
- tls-version 
- nmap 
- country
- http 

Each output filename will contain the current date-time.

### Scanning a multiple capture files
`packet_hunter.py -i ~/captures/ -d ~/captures/output -c packhunt.conf`

This will use the default config `/etc/packhunt/packhunt.conf` and will populate the following directories with filtered results:

- dns (merged results from each capture file)
- strange-ports (merged results from each capture file)
- tls-version (merged results from each capture file)
- nmap (merged results from each capture file)
- country (merged results from each capture file)
- http (merged results from each capture file)

Each output filename will contain the current date-time.

### Specific filters
By default, all filters from the config file will be used to create individual filtered files. You can choose specific filters from this list by
supplying them as an argument:

#### DNS only
`packet_hunter.py -i ~/captures/ -d ~/captures/output -c packhunt.conf -f dns`

#### DNS and HTTP
`packet_hunter.py -i ~/captures/ -d ~/captures/output -c packhunt.conf -f dns http`





