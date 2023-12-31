#!/usr/bin/python3

import argparse
import os.path
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import yaml

DEFAULT_CONFIG = "/etc/packhunt/packhunt.conf"

SOURCE_HELP = """Path to a packet capture file (pcapng)"""
DESTINATION_HELP = """Path to store extracted files"""
CONFIG_HELP = """Path to configuration"""
FILTER_HELP = """Specific filters from the filter config to apply (i.e. -f dns nmap-scan http)"""


@dataclass
class PacketFilter:
    name: str
    filter: str


class PacketHunter:
    def __init__(self, source, destination, config, filter_override=None):
        self.source = source
        self.destination = destination

        if config is not None:
            self.config = config
        else:
            self.config = DEFAULT_CONFIG

        self.filter_override = filter_override
        self.filters = []

        self.date_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.merge = False

        self.verify_files()
        self.read_filters()
        self.create_destination()

    def verify_files(self):
        # Make sure the source exists
        if not os.path.exists(self.source):
            raise FileNotFoundError("Source file does not exist")

        # Make sure the config exists
        if not os.path.exists(self.config):
            raise FileNotFoundError("Config file does not exist")

        # If the source is a directory, set a flag for later merging
        if os.path.isdir(self.source):
            self.merge = True

    def read_filters(self):
        # Read the filters as YAML
        with open(self.config, 'r') as file:
            filters = yaml.safe_load(file)

        # If a filter override has been applied, filter out anything that is not in the override list
        if self.filter_override is not None:
            filters = dict((key, filters[key]) for key in self.filter_override if key in filters)

        # Save a copy of the filter names and values
        self.filters = [PacketFilter(f, filters[f].get('filter')) for f in filters]

    def create_destination(self):
        # Ensure a directory exists to hold each filter
        for filter_type in self.filters:
            filter_dir = Path(self.destination) / filter_type.name
            filter_dir.mkdir(parents=True, exist_ok=True)

    def extract_filter(self, source):
        # Attempt to run a filter on the source provided
        for filter_type in self.filters:
            # the output directory will be the destination path + filter name
            output = Path(self.destination) / filter_type.name
            self.extract_packets(filter_type.filter, source, output)

    def merge_filters(self):
        # For each filter, attempt to merge captures
        for filter_type in self.filters:
            self.merge_packets(filter_type.name)

    def extract_packets(self, filter_options, source, destination):
        if self.merge is False:
            # If we are not merging, take the original capture file and append the current date-time to the output file
            file_name = Path(source).stem + "-" + self.date_time + Path(source).suffix
        else:
            # If we are merging, the output filename then prepend dump-
            file_name = "dump-" + Path(source).name

        output = Path(destination) / file_name

        # Run tshark to filter the capture file
        subprocess.run(["tshark", "-r", source, "-Y", filter_options, "-w", output])

    def merge_packets(self, filter_name):
        names = []

        merge_path = Path(self.destination) / filter_name

        # Find all captures that begin with dump-, these will be merged and removed
        for file in merge_path.glob('dump-*.pcapng'):
            names.append(file)

        destination_file = f"all-{filter_name}-{self.date_time}.pcapng"
        destination = Path(merge_path) / destination_file

        # Merge all files beginning with dump- and save into a separate file
        subprocess.run(["mergecap", "-w", destination, *names])

        # Remove all temporary dump files
        for file in names:
            Path(file).unlink()


def parse_args():
    parser = argparse.ArgumentParser(
        prog='Packet extraction',
        description='Extract packet data for threat hunting',
        epilog='packet_hunter.py -i capture.pcapng -d ./captures')

    parser.add_argument('-i', action='store', dest='source', help=SOURCE_HELP)
    parser.add_argument('-d', action='store', dest='destination', help=DESTINATION_HELP)
    parser.add_argument('-c', action='store', dest='config', help=CONFIG_HELP)
    parser.add_argument('-f', action='store', dest='filter', nargs='+', required=False, help=FILTER_HELP)

    return parser


def main():
    parser = parse_args()
    args = parser.parse_args()

    if args.source is None or args.destination is None:
        parser.print_help(sys.stderr)
        sys.exit(1)

    try:
        hunter = PacketHunter(args.source, args.destination, args.config, args.filter)
    except TypeError:
        print("Error: Invalid config")
        sys.exit(1)
    except FileNotFoundError as e:
        print("Error: " + str(e))
        sys.exit(1)

    if os.path.isfile(args.source):
        hunter.extract_filter(args.source)
    else:
        files = Path(args.source).glob('*.pcapng')
        for file in files:
            hunter.extract_filter(file)
        hunter.merge_filters()


if __name__ == '__main__':
    main()
