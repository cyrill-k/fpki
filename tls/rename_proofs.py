#!/usr/bin/env python3

import argparse
import csv
from os import makedirs, listdir
from os.path import basename, join
from shutil import copyfile
from os import path

from utils import get_or_update_second_tld, apply_second_tld_map

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Rename proofs from domain file names to rank file names",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--source-folder", "-s", default="output/proofs")
    parser.add_argument("--destination-folder", "-d", default="output/proofsbyrank")
    parser.add_argument("--toplist", "-t", default="top-1k-filtered.domains", help="toplist file to use for the mapping")
    parser.add_argument("--no-translate", action="store_true")
    parser.add_argument("--domain-translation-csv", default=join("output", "domain-translation.csv"))
    parser.add_argument("--domain-input-file", default="top-1k-filtered.domains")

    return parser.parse_args()


def main():
    args = parse_arguments()

    makedirs(args.destination_folder, exist_ok=True)

    domain_file = path.abspath(args.domain_input_file)
    translation_csv_file = path.abspath(args.domain_translation_csv)

    if not args.no_translate:
        second_tld_map = {}
        with open(translation_csv_file, newline='') as f:
            reader = csv.reader(f)
            for row in reader:
                second_tld_map[row[1]] = row[0]
        domain_map = {}
        with open(domain_file, newline='') as f:
            reader = csv.reader(f)
            # enumerate is used here as a hack since the scrape script used enumerate instead of using the same rank id as the toplist...
            for i, row in enumerate(reader, 1):
                domain_map[row[1]] = str(i)

    for domain in listdir(args.source_folder):
        domain_proof = join(args.source_folder, domain)
        if not args.no_translate:
            original_domain = apply_second_tld_map(basename(domain), second_tld_map)
            rank = domain_map[original_domain]
            rank_str = f"{int(rank):06d}"
        else:
            rank_str = basename(domain).removeprefix("d").removesuffix(".com")
        rank_proof = join(args.destination_folder, f"{rank_str}.proof")
        copyfile(domain_proof, rank_proof)


if __name__ == '__main__':
    main()
