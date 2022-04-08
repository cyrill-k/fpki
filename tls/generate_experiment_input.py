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

    return parser.parse_args()


def main():
    args = parse_arguments()

    cert_folder = path.abspath(args.cert_folder)

    # with open(args.hosts_file, "a") as hosts_file:
    for x in sorted([int(y.removeprefix("cert-").removesuffix(".pem")) for y in listdir(cert_folder)]):
        rank = f"{int(x):06d}"
        server_name = f"d{rank}.com"
        print(f"{rank},{server_name}")


if __name__ == '__main__':
    main()
