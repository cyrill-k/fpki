#!/usr/bin/env python3

import argparse
from os import path, listdir
from os.path import join
import csv

from utils import get_or_update_second_tld, apply_second_tld_map


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Generate various config files based on the existing certificates",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument('cmd', metavar='CMD', choices=['experiment-input-dns', 'experiment-input', 'hosts-file', 'nginx-config', 'domains'])
    parser.add_argument("--cert-folder", default="output/finalservercerts")
    parser.add_argument("--key-folder", default="output/serverkeys")
    parser.add_argument("--www-folder", default="www")
    parser.add_argument("--ip", default="127.0.0.1")
    parser.add_argument("--exclude-domain", default=["w55c.net", "api.cylance.com", "cdn.krxd.net", "detectportal.firefox.com"])
    parser.add_argument("--no-translate", action="store_true")
    parser.add_argument("--domain-translation-csv", default=join("output", "domain-translation.csv"))
    parser.add_argument("--domain-input-file", default="top-1k-filtered.domains")

    return parser.parse_args()


def main():
    args = parse_arguments()

    cert_folder = path.abspath(args.cert_folder)
    domain_file = path.abspath(args.domain_input_file)
    translation_csv_file = path.abspath(args.domain_translation_csv)

    if args.cmd == 'experiment-input-dns':
        with open(domain_file, newline='') as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader, 1):
                print(f"{i},{row[1]}")
    else:
        if not args.no_translate:
            second_tld_map = {}
            with open(translation_csv_file, newline='') as f:
                reader = csv.reader(f)
                for row in reader:
                    second_tld_map[row[0]] = row[1]
            domain_map = {}
            with open(domain_file, newline='') as f:
                reader = csv.reader(f)
                # enumerate is used here as a hack since the scrape script used enumerate instead of using the same rank id as the toplist...
                for i, row in enumerate(reader, 1):
                    domain_map[str(i)] = row[1]

        for x in sorted([int(y.removeprefix("cert-").removesuffix(".pem")) for y in listdir(cert_folder)]):
            rank = f"{int(x):06d}"
            server_name = f"d{rank}.com"
            if not args.no_translate:
                server_name = apply_second_tld_map(domain_map[str(x)], second_tld_map)
                if server_name is None:
                    continue

            if args.cmd.startswith("experiment-input"):
                print(f"{rank},{server_name}")
            elif args.cmd.startswith("hosts-file"):
                print(f"{args.ip} {server_name}")
            elif args.cmd.startswith("nginx-config"):
                key_folder = path.abspath(args.key_folder)
                www_folder = path.abspath(args.www_folder)
                ssl_certificate = join(cert_folder, f"cert-{rank}.pem")
                ssl_certificate_key = join(key_folder, f"key-{rank}.pem")
                print(f"""server {{
        listen 443 ssl;
        server_name {server_name};
        ssl_certificate {ssl_certificate};
        ssl_certificate_key {ssl_certificate_key};
        location / {{
            root {www_folder};
        }}
    }}""")
            elif args.cmd == "domains":
                print(server_name)


if __name__ == '__main__':
    main()
