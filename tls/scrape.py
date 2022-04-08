#!/usr/bin/env python3

import socket
from OpenSSL import SSL, crypto
import certifi
import csv
import os
import argparse
import multiprocessing
import sys


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Scrape TLS certificates from a set of domains",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--input-type", "-i", default="toplist", choices=["domain", "toplist"], help="Whether the input parameters describe domains or toplists containing one [rank, domain] entry per line")

    parser.add_argument('input', metavar='INPUT', type=str, nargs='*', default=["top-1k-filtered.domains"])

    return parser.parse_args()


def get_certificate_chain(hostname, port, output_queue: multiprocessing.Queue = None):
    context = SSL.Context(method=SSL.TLSv1_2_METHOD)
    context.load_verify_locations(cafile=certifi.where())

    conn = SSL.Connection(context, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    conn.settimeout(5)
    conn.connect((hostname, port))
    conn.setblocking(1)
    conn.do_handshake()
    conn.set_tlsext_host_name(hostname.encode())
    certs = conn.get_peer_cert_chain()
    conn.close()
    if certs is not None:
        pemCerts = [crypto.dump_certificate(crypto.FILETYPE_PEM, x).decode(encoding="utf-8") for x in certs]
        if output_queue is not None:
            output_queue.put(pemCerts)
        return pemCerts
    return None


def get_certificate_chain_with_timeout(hostname, port, timeout=60):
    queue = multiprocessing.Queue()
    p = multiprocessing.Process(target=get_certificate_chain, args=(hostname, port, queue))
    p.start()
    p.join(timeout)
    if p.is_alive():
        print(f"killing process after timeout for {hostname}:{port}", file=sys.stderr)
        p.terminate()
        p.join()
    if not queue.empty():
        return queue.get()
    return None


if __name__ == '__main__':
    args = parse_arguments()
    for input_parameter in args.input:
        if args.input_type == "domain":
            certchain = get_certificate_chain_with_timeout(input_parameter, 443)
            print(''.join(certchain))
        elif args.input_type == "toplist":
            ignore = []
            with open(input_parameter, newline='') as csvfile:
                os.makedirs("certchains")
                r = csv.reader(csvfile, delimiter=',')
                for i, row in enumerate(r, 1):
                    print(f'{int(row[0]):06d}: {row[1]}')
                    if i in ignore:
                        print("ignoring")
                        continue
                    try:
                        pemCertchain = get_certificate_chain_with_timeout(row[1], 443)
                        if pemCertchain is not None:
                            with open(f'certchains/c_{row[0]:06d}', 'w') as o:
                                o.write(''.join(pemCertchain))
                            print("success")
                    except Exception as e:
                        print(e)

                    if i >= 1000:
                        break
