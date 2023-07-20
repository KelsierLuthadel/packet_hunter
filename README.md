# Packet Hunter

This tool scans large packet capture files (pcapng) for interesting data and dumps the output into separate files for later analysis. 

**Usage**
```
usage: packet_hunter.py [-h] [-i SOURCE] [-d DESTINATION] [-c CONFIG]

Extract packet data for threat hunting

options:
  -i SOURCE      - Path to a packet capture file (pcapng)
  -d DESTINATION - Path to store extracted files
  -c CONFIG      -  Path to configuration
```
## Config
The configuration file defines what filters to apply when reading the packet capture file(s).

```yaml
dns:
  filter: dns
strange-ports:
  filter: "!tcp.port in {22,23,25,80,443,445}"
tls-version:
  filter: "tls.handshake.version < 0x0303"
nmap:
  filter: "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size<=1024"
country:
  filter: "ip.geoip.country_iso in {CN,RU,NK}"
http:
  filter: "http"
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



