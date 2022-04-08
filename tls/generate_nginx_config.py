#!/usr/bin/env python3

import argparse
import csv
from os import path, listdir
from os.path import join


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Update hosts file with hardcoded IP addresses",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--cert-folder", default="output/finalservercerts")
    parser.add_argument("--key-folder", default="output/serverkeys")
    parser.add_argument("--www-folder", default="www")
    parser.add_argument("--action", choices=["extend"], default="extend")

    return parser.parse_args()


def main():
    args = parse_arguments()

    cert_folder = path.abspath(args.cert_folder)
    key_folder = path.abspath(args.key_folder)
    www_folder = path.abspath(args.www_folder)

    # with open(args.hosts_file, "a") as hosts_file:
    for x in sorted([int(y.removeprefix("cert-").removesuffix(".pem")) for y in listdir(cert_folder)]):
        rank = f"{int(x):06d}"
        server_name = f"d{rank}.com"
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


if __name__ == '__main__':
    main()
