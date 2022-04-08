#!/usr/bin/env python3

import sys
import argparse
import re
from os.path import join, abspath
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.x509.oid import NameOID, ExtensionOID, SignatureAlgorithmOID
from os import makedirs, listdir
from pathlib import Path
import random
import datetime
from publicsuffixlist import PublicSuffixList
import csv

from collections.abc import Iterable, Mapping, Sequence, Iterator
from typing import Union, Tuple, List, Optional

from utils import get_or_update_second_tld

psl = PublicSuffixList()

PrivateKey = Union[ed25519.Ed25519PrivateKey, rsa.RSAPrivateKeyWithSerialization, ec.EllipticCurvePrivateKeyWithSerialization]
Certificates = Iterable[x509.Certificate]
CertificateMap = Mapping[x509.Name, x509.Certificate]
CertificateKeyTuple = Tuple[x509.Certificate, PrivateKey]
CertificateKeyMap = Mapping[x509.Name, CertificateKeyTuple]
CertificateKeyIter = Iterable[CertificateKeyTuple]

DEFAULT_OUTPUT_FOLDER = "output"
ROOTKEY_FOLDER = "rootkeys"
ROOTCERT_FOLDER = "rootcerts"
INTKEY_FOLDER = "intkeys"
SERVERKEY_FOLDER = "serverkeys"
SERVERCERT_FOLDER = "servercerts"
FINAL_SERVERCERT_FOLDER = "finalservercerts"


# Solve FF error: SEC_ERROR_INADEQUATE_KEY_USAGE
# https://support.mozilla.org/en-US/questions/1310266

# security.enterprise_roots.enabled = true

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Transform a web PKI cert with a complete chain. Replaces chain with chain rooted in own root certificate and staples F-PKI proofs as non-critical extension",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--root-cert", help="root certificate in pem format", default=join(DEFAULT_OUTPUT_FOLDER, ROOTCERT_FOLDER, "cert-fpki.pem"))
    parser.add_argument("--root-key", help="private key of root certificate in pem format", default=join(DEFAULT_OUTPUT_FOLDER, ROOTKEY_FOLDER, "key-fpki.pem"))
    parser.add_argument('certificates', metavar='C', nargs='*', help="Certificate chains to transform in pem format")
    parser.add_argument("--output-dir", help="directory to store generated keys and certificates", default="output")
    parser.add_argument("--certificate-trust-store", type=str, default="/etc/ssl/certs/ca-certificates.crt", help="File containing all trusted root certificates")
    parser.add_argument("--action", "-a", choices=["generate-initial-certs", "add-proof-extension"])
    parser.add_argument("--multiple-root-certs", action="store_true")
    parser.add_argument("--proof-dir", default=join(DEFAULT_OUTPUT_FOLDER, "proofsbyrank"))
    parser.add_argument("--no-translate", action="store_true")
    parser.add_argument("--domain-translation-csv", default=join(DEFAULT_OUTPUT_FOLDER, "domain-translation.csv"))

    return parser.parse_args()


def create_key(key_type="secp256", key_size=2048) -> PrivateKey:
    key: PrivateKey
    if key_type == "rsa":
        public_exponent = 65537
        key = rsa.generate_private_key(public_exponent, key_size)
    elif key_type == "ed25519":
        key = ed25519.Ed25519PrivateKey.generate()
    elif key_type == "secp256":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise NotImplementedError()
    return key


def save_key(key: PrivateKey, path: str):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            # format=serialization.PrivateFormat.TraditionalOpenSSL,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))


def save_certs(certs: Certificates, path: str):
    with open(path, "wb") as f:
        for cert in certs:
            pem = cert.public_bytes(serialization.Encoding.PEM)
            f.write(pem)


def save_cert(cert: x509.Certificate, path: str):
    save_certs([cert], path)


def create_key_for_cert(cert: x509.Certificate) -> PrivateKey:
    key: PrivateKey
    public_key = cert.public_key()
    # always use ed25519
    if True:
        # key = ed25519.Ed25519PrivateKey.generate()
        key = ec.generate_private_key(ec.SECP256R1())
        return key
    if isinstance(public_key, rsa.RSAPublicKey):
        public_exponent = public_key.public_numbers().e
        if public_exponent != 3 and public_exponent != 65537:
            print(f"Overwriting invalid public RSA exponent: {public_exponent}", file=sys.stderr)
            public_exponent = 65537
        key = rsa.generate_private_key(public_exponent, public_key.key_size)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key = ed25519.Ed25519PrivateKey.generate()
        # ec.generate_private_key(
        # key = ec.generate_private_key(public_key.curve())
    else:
        raise NotImplementedError()
    return key


def adjust_name(name: x509.Name, cn: str) -> x509.Name:
    rdns_entries = []
    for attribute in name:
        if attribute.oid == NameOID.COMMON_NAME:
            rdns_entries.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        else:
            rdns_entries.append(attribute)
    return x509.Name(rdns_entries)


def adjust_san_entries_with_second_tld(san_entry: x509.SubjectAlternativeName, second_tld_map: Mapping[str, str]):
    dns_entries = [get_or_update_second_tld(x, second_tld_map) for x in san_entry.get_values_for_type(x509.DNSName)]
    return x509.SubjectAlternativeName([x509.DNSName(x) for x in dns_entries])

def get_common_name(name: x509.Name) -> Optional[str]:
    for attribute in name:
        if attribute.oid == NameOID.COMMON_NAME:
            return attribute.value
    return None


def get_fpki_name(name: x509.Name) -> x509.Name:
    rdns_entries = []
    for attribute in name:
        if attribute.oid == NameOID.COMMON_NAME:
            rdns_entries.append(x509.NameAttribute(NameOID.COMMON_NAME, u'fpki-'+attribute.value))
        else:
            rdns_entries.append(attribute)
    return x509.Name(rdns_entries)


def create_fpki_root_cert_and_key(key_type="secp256"):
    key = create_key(key_type)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    serial_number = x509.random_serial_number()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'fpki CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'fpki ORG'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'fpki ORG UNIT'),
    ])

    builder = x509.CertificateBuilder()
    builder = builder.issuer_name(name)
    builder = builder.subject_name(name)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(serial_number)
    one_day = datetime.timedelta(1, 0, 0)
    builder = builder.not_valid_before(datetime.datetime.today() - (one_day * 1000))
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 1000))
    builder = builder.add_extension(ski, critical=False)
    # builder = builder.add_extension(x509.AuthorityKeyIdentifier(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), name.rdns, serial_number), critical=True)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    builder = builder.add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)

    if isinstance(key.public_key(), rsa.RSAPublicKey) or isinstance(key.public_key(), ec.EllipticCurvePublicKey):
        return builder.sign(key, hashes.SHA256()), key
    else:
        return builder.sign(key, None), key


def modify_key_in_cert(cert: x509.Certificate, key, signing_key, random_serial: bool = False, issuer_name: x509.Name = None, transform_issuer_to_fpki_names: bool = False, transform_subject_to_fpki_names: bool = False, proof_byte_extension: bytes = None, adjust_subject_and_san: Optional[str] = None, parent_cert: Optional[x509.Certificate] = None, second_tld_map: Mapping[str, str] = None):
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key())
    ext_replacement = {ski.oid: (ski, False), aki.oid: (aki, False)}

    builder = x509.CertificateBuilder()
    if transform_issuer_to_fpki_names:
        if issuer_name is None:
            builder = builder.issuer_name(get_fpki_name(cert.issuer))
        else:
            builder = builder.issuer_name(get_fpki_name(issuer_name))
    else:
        if issuer_name is None:
            builder = builder.issuer_name(cert.issuer)
        else:
            builder = builder.issuer_name(issuer_name)
    if transform_subject_to_fpki_names:
        name = get_fpki_name(cert.subject)
    elif adjust_subject_and_san is not None:
        name = adjust_name(cert.subject, adjust_subject_and_san)
    elif second_tld_map is not None:
        cn = get_common_name(cert.subject)
        if cn:
            name = adjust_name(cert.subject, get_or_update_second_tld(cn, second_tld_map))
        else:
            name = cert.subject
    else:
        name = cert.subject
        # name = x509.Name([
        #     x509.NameAttribute(NameOID.COMMON_NAME, u'000000.cyrill.com'),
        #     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'SC fpki ORG'),
        #     x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'SC fpki ORG UNIT'),
        # ])
    builder = builder.subject_name(name)
        # builder = builder.subject_name(cert.subject)
    builder = builder.public_key(key.public_key())
    if random_serial:
        # rand_bytes = bytearray(random.randbytes(20))
        # print(rand_bytes.hex())
        # print(int.from_bytes(rand_bytes, byteorder='big', signed=True))
        # print(rand_bytes[0] & 0x7f)
        # print(rand_bytes[-1] & 0x7f)
        # only generate positive serials
        # rand_bytes[0] &= 0x7f
        # print(int.from_bytes(rand_bytes, byteorder='big', signed=True))
        # builder = builder.serial_number(int.from_bytes(rand_bytes, byteorder='big', signed=True))
        builder = builder.serial_number(x509.random_serial_number())
    else:
        if cert.serial_number <= 0:
            builder = builder.serial_number(1)
        else:
            builder = builder.serial_number(cert.serial_number)
    if parent_cert is None:
        builder = builder.not_valid_before(cert.not_valid_before)
        builder = builder.not_valid_after(cert.not_valid_after)
    else:
        one_day = datetime.timedelta(1, 0, 0)
        builder = builder.not_valid_before(parent_cert.not_valid_before + one_day)
        builder = builder.not_valid_after(parent_cert.not_valid_after - one_day)
    for ext in cert.extensions:
        if adjust_subject_and_san is not None and ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(adjust_subject_and_san)]), critical=ext.critical)
        elif second_tld_map is not None and ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            builder = builder.add_extension(adjust_san_entries_with_second_tld(ext.value, second_tld_map), critical=ext.critical)
        elif ext.oid in ext_replacement:
            builder = builder.add_extension(ext_replacement[ext.oid][0], critical=ext_replacement[ext.oid][1])
        else:
            builder = builder.add_extension(ext.value, critical=ext.critical)
    if proof_byte_extension is not None:
        oid = x509.ObjectIdentifier("1.2.3.4.5.6.7.8.9")
        proof_type_ext = x509.UnrecognizedExtension(oid, proof_byte_extension)
        builder = builder.add_extension(proof_type_ext, critical=False)
    if isinstance(signing_key.public_key(), rsa.RSAPublicKey) or isinstance(signing_key.public_key(), ec.EllipticCurvePublicKey):
        return builder.sign(signing_key, hashes.SHA256())
    else:
        return builder.sign(signing_key, None)


def create_new_cert_for_cert(cert: x509.Certificate, key_folder: Optional[str], cert_folder: Optional[str], key_base_file_name: str, cert_base_file_name: str, signing_key: PrivateKey = None, intermediate_certs: Certificates = [], random_serial: bool = False, issuer_name: x509.Name = None, transform_subject_to_fpki_names: bool = False, transform_issuer_to_fpki_names: bool = False, proof_byte_extension: bytes = None, key: Optional[PrivateKey] = None, adjust_subject_and_san: Optional[str] = None, parent_cert: Optional[x509.Certificate] = None, second_tld_map: Mapping[str, str] = None) -> CertificateKeyTuple:
    if key is None:
        key = create_key_for_cert(cert)
    if key_folder is not None:
        save_key(key, join(key_folder, f"key-{key_base_file_name}.pem"))

    if signing_key is None:
        signing_key = key
    mod_cert = modify_key_in_cert(cert, key, signing_key, random_serial=random_serial, issuer_name=issuer_name, transform_subject_to_fpki_names=transform_subject_to_fpki_names, transform_issuer_to_fpki_names=transform_issuer_to_fpki_names, proof_byte_extension=proof_byte_extension, adjust_subject_and_san=adjust_subject_and_san, parent_cert=parent_cert, second_tld_map=second_tld_map)
    certs = [mod_cert]
    if intermediate_certs is not None:
        for int_cert in intermediate_certs:
            certs.append(int_cert)
    if cert_folder is not None:
        save_certs(certs, join(cert_folder, f"cert-{key_base_file_name}.pem"))

    return (mod_cert, key)


# openssl x509 -x509toreq -signkey ./server.key -in ./server.pem -out server.csr


def read_key(keyfile) -> PrivateKey:
    with open(keyfile, "rb") as f:
        return serialization.load_pem_private_key(f.read(), None)
    return None


def read_certs(certfile) -> List[x509.Certificate]:
    with open(certfile, "r") as f:
        pem_data = f.read()
        certs_pem = re.findall("-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_data, re.S)
        certs = []
        for cert_pem in certs_pem:
            certs.append(x509.load_pem_x509_certificate(cert_pem.encode('ascii')))
        return certs


def read_server_certs_and_keys(servercert_folder: str, serverkey_folder: str, int_key_folder: str, rank: str) -> Tuple[List[x509.Certificate], List[PrivateKey]]:
    certs = read_certs(join(servercert_folder, f"cert-{rank}.pem"))
    keys = [read_key(join(serverkey_folder, f"key-{rank}.pem"))]
    for x in range(1, len(certs)):
        keys.append(read_key(join(int_key_folder, f"key-{rank}-{x-1}.pem")))
    return certs, keys


def generate_issuer_name_mapping(cert_trust_store_file: str, single_root_cert: x509.Certificate = None):
    certs = read_certs(cert_trust_store_file)
    # get_fpki_name(certs[0].subject)
    if single_root_cert is not None:
        return {c.subject: single_root_cert.subject for c in certs}
    else:
        return {c.subject: get_fpki_name(c.subject) for c in certs}


# /etc/ssl/certs/ca-certificates.crt
def create_self_signed_root_certs(cert_trust_store_file: str, rootcert_folder: str, rootkey_folder: str):
    certs = read_certs(cert_trust_store_file)
    issuer_root_cert_map = {}
    negative_serials = 0
    for i, cert in enumerate(certs):
        if cert.serial_number <= 0:
            print(f"Ignoring {cert} with non-positive serial: {cert.serial_number}", file=sys.stderr)
            negative_serials += 1
            continue
        mod_cert = create_new_cert_for_cert(cert, rootkey_folder, rootcert_folder, f"{i}", f"{i}", random_serial=True, transform_subject_to_fpki_names=True, transform_issuer_to_fpki_names=True)[0]
        issuer_root_cert_map[mod_cert.issuer] = mod_cert
    print(f"negative serials: {negative_serials}", file=sys.stderr)
    return issuer_root_cert_map


def list_cert_dir_content_ordered(cert_folder: str, reverse: bool = False) -> Iterator[Tuple[str, str]]:
    certs = listdir(cert_folder)
    ranks = [int(x.removeprefix("cert-").removesuffix(".pem")) if re.match(r'cert-\d+\.pem', x) else -1 for x in certs]
    certs_with_rank = zip(map(abspath, certs), ranks)
    certs_with_rank = sorted(certs_with_rank, key=lambda x: x[1])
    if reverse:
        certs_with_rank = reversed(certs_with_rank)
    certs_with_rank_str = map(lambda x: (x[0], f"{x[1]:06d}"), certs_with_rank)
    return certs_with_rank_str
    # sorted(listdir(rootcert_folder), key=lambda x: int(x.removeprefix("cert-").removesuffix(".pem")) if re.match(r'\d+', x.removeprefix("cert-").removesuffix(".pem")) else -1)


def read_self_signed_root_certs(rootcert_folder: str, rootkey_folder: str):
    issuer_root_cert_map = {}
    for cert_file in sorted(listdir(rootcert_folder), key=lambda x: int(x.removeprefix("cert-").removesuffix(".pem")) if re.match(r'\d+', x.removeprefix("cert-").removesuffix(".pem")) else -1):
        cert = read_certs(join(rootcert_folder, cert_file))[0]
        key = read_key(join(rootkey_folder, cert_file.replace("cert-", "key-")))
        # with open(join(ROOTKEY_FOLDER, cert_file.replace("cert-", "key-")), "rb") as f:
        #     key = serialization.load_pem_private_key(f.read(), None)
        issuer_root_cert_map[cert.issuer] = (cert, key)
    return issuer_root_cert_map


def get_root_cert_and_key(certs: Certificates, issuer_root_cert_map: CertificateKeyMap, mapping: Mapping[x509.Name, x509.Name] = None) -> CertificateKeyTuple:
    for x in certs:
        issuer = x.issuer if mapping is None or x.issuer not in mapping else mapping[x.issuer]
        if issuer in issuer_root_cert_map:
            # additionally check key identifiers and KU_KEY_CERT_SIGN bit
            # https://stackoverflow.com/questions/56763385/determine-if-ssl-certificate-is-self-signed-using-python
            return issuer_root_cert_map[issuer]
            # print("\t"+f"is in issuer root map: {issuer_root_cert_map[x.issuer]}")
        # print(f"\t{x.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value}")
        # print(f"\t{x.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value}")
        # print()
    return None, None


def generate_root_cert_if_necessary(root_cert):
    return None


def create_endpoint_cert_chain(certs: Sequence[x509.Certificate], root_cert: x509.Certificate, root_key: PrivateKey, rank: str, proof_bytes: bytes, servercert_folder: str, serverkey_folder: str, intkey_folder: str, enable_adjust_subject_and_san: bool, second_tld_map: Mapping[str, str]) -> Certificates:
    mod_certs = []
    parent_key = None
    parent_cert_chain: List[x509.Certificate] = []
    key_folder: str
    cert_folder: Optional[str] = None
    basename: str
    proof_byte_extension: Optional[bytes] = None
    negative_serials = 0
    for i, cert in reversed(list(enumerate(certs))):
        if i == 0:
            key_folder = serverkey_folder
            cert_folder = servercert_folder
            basename = rank
            # transform_subject_to_fpki_names = False
            proof_byte_extension = proof_bytes
        else:
            key_folder = intkey_folder
            cert_folder = None
            basename = f"{rank}-{i-1}"
            # transform_subject_to_fpki_names = True
            proof_byte_extension = None
        cur_parent_cert = parent_cert_chain[0] if len(parent_cert_chain) > 0 else root_cert
        issuer_name = cur_parent_cert.subject
        signing_key = parent_key if i+1 < len(certs) else root_key
        if cert.serial_number <= 0:
            print(f"Replacing {cert}'s non-positive serial with a random serial", file=sys.stderr)
            negative_serials += 1
            random_serial = True
        else:
            # always use random serial
            random_serial = True
        if enable_adjust_subject_and_san:
            mod_cert, mod_key = create_new_cert_for_cert(cert, key_folder, cert_folder, basename, basename, signing_key=signing_key, intermediate_certs=parent_cert_chain, issuer_name=issuer_name, transform_subject_to_fpki_names=False, proof_byte_extension=proof_byte_extension, random_serial=random_serial, adjust_subject_and_san=f"d{basename}.com", parent_cert=cur_parent_cert)
        else:
            mod_cert, mod_key = create_new_cert_for_cert(cert, key_folder, cert_folder, basename, basename, signing_key=signing_key, intermediate_certs=parent_cert_chain, issuer_name=issuer_name, transform_subject_to_fpki_names=False, proof_byte_extension=proof_byte_extension, random_serial=random_serial, second_tld_map=second_tld_map, parent_cert=cur_parent_cert)
        parent_key = mod_key
        parent_cert_chain = [mod_cert] + parent_cert_chain
        mod_certs.append(mod_cert)
    # print(f"Replaced {negative_serials} endpoint certificate serials with random serials", file=sys.stderr)
    return reversed(mod_certs)


def add_proof_bytes_to_endpoint_cert_chain(certs_with_keys: Sequence[CertificateKeyTuple], root_cert: x509.Certificate, root_key: PrivateKey, rank: str, proof_bytes: bytes, servercert_folder: str) -> Certificates:
    mod_certs = []
    parent_key: Optional[PrivateKey] = None
    parent_cert_chain: List[x509.Certificate] = []
    key_folder: Optional[str] = None
    cert_folder: Optional[str] = None
    basename: str
    proof_byte_extension: Optional[bytes] = None
    for i, cert_with_key in reversed(list(enumerate(certs_with_keys))):
        cert = cert_with_key[0]
        key = cert_with_key[1]
        if i == 0:
            cert_folder = servercert_folder
            basename = rank
            proof_byte_extension = proof_bytes
        else:
            cert_folder = None
            basename = f"{rank}-{i-1}"
            proof_byte_extension = None
        signing_key = parent_key if parent_key is not None else root_key
        mod_cert, mod_key = create_new_cert_for_cert(cert, key_folder, cert_folder, basename, basename, signing_key=signing_key, intermediate_certs=parent_cert_chain, proof_byte_extension=proof_byte_extension, key=key)
        parent_key = mod_key
        parent_cert_chain = [mod_cert] + parent_cert_chain
        mod_certs.append(mod_cert)
    return reversed(mod_certs)


def save_cert_chain_as_crt(cert: x509.Certificate, rank: int) -> None:
    return None


def read_proof_bytes(proof_dir: str, rank: str) -> Optional[bytes]:
    try:
        with open(join(proof_dir, f"{rank}.proof"), "rb") as f:
            return f.read()
    except:
        return None


def main():
    args = parse_arguments()

    rootkey_folder = join(args.output_dir, ROOTKEY_FOLDER)
    rootcert_folder = join(args.output_dir, ROOTCERT_FOLDER)
    intkey_folder = join(args.output_dir, INTKEY_FOLDER)
    servercert_folder = join(args.output_dir, SERVERCERT_FOLDER)
    serverkey_folder = join(args.output_dir, SERVERKEY_FOLDER)
    final_servercert_folder = join(args.output_dir, FINAL_SERVERCERT_FOLDER)

    makedirs(rootkey_folder, exist_ok=True)
    makedirs(rootcert_folder, exist_ok=True)
    makedirs(intkey_folder, exist_ok=True)
    makedirs(servercert_folder, exist_ok=True)
    makedirs(serverkey_folder, exist_ok=True)
    makedirs(final_servercert_folder, exist_ok=True)

    if args.action == "generate-initial-certs":
        if not args.multiple_root_certs:
            root_cert, root_key = create_fpki_root_cert_and_key()
            save_key(root_key, args.root_key)
            save_cert(root_cert, args.root_cert)

            issuer_root_cert_map = read_self_signed_root_certs(rootcert_folder, rootkey_folder)
            issuer_mapping = generate_issuer_name_mapping(args.certificate_trust_store, single_root_cert=root_cert)
        else:
            issuer_root_cert_map = create_self_signed_root_certs(args.certificate_trust_store, rootcert_folder, rootkey_folder)
            issuer_mapping = generate_issuer_name_mapping(args.certificate_trust_store)

        second_tld_map = {}
        n_certs = 0
        for certfile in args.certificates:
            rank = re.match(r".*?(\d+)$", certfile).group(1)

            certs = read_certs(certfile)

            root_cert, root_key = get_root_cert_and_key(certs, issuer_root_cert_map, issuer_mapping)
            if root_cert is None:
                print(f"failed to get root cert for: {certs[0]}", file=sys.stderr)
                continue

            if args.no_translate:
                ep_cert_chain = create_endpoint_cert_chain(certs, root_cert, root_key, rank, None, servercert_folder, serverkey_folder, intkey_folder, enable_adjust_subject_and_san=True, second_tld_map=None)
            else:
                ep_cert_chain = create_endpoint_cert_chain(certs, root_cert, root_key, rank, None, servercert_folder, serverkey_folder, intkey_folder, enable_adjust_subject_and_san=False, second_tld_map=None)
            ep_cert_chain = list(ep_cert_chain)

            n_certs += 1
            # print(ep_cert_chain)
            # for x in ep_cert_chain:
            #     print(f"{x.subject} <- {x.issuer}")

            save_cert_chain_as_crt(ep_cert_chain, rank)
        print(f"created {n_certs} certificates", file=sys.stderr)
        if not args.no_translate:
            with open(args.domain_translation_csv, 'w', newline='') as f:
                second_tld_writer = csv.writer(f)
                for entry in sorted(second_tld_map.items(), key=lambda x: int(x[1].removeprefix("d")[:6])):
                    second_tld_writer.writerow(entry)
    elif args.action == "add-proof-extension":
        issuer_root_cert_map = read_self_signed_root_certs(rootcert_folder, rootkey_folder)
        if not args.multiple_root_certs:
            root_cert = read_certs(args.root_cert)[0]
            root_key = read_key(args.root_key)

            issuer_mapping = generate_issuer_name_mapping(args.certificate_trust_store, single_root_cert=root_cert)
        else:
            issuer_mapping = generate_issuer_name_mapping(args.certificate_trust_store)

        n_certs = 0
        for certfile, rank in list_cert_dir_content_ordered(servercert_folder):
        # for certfile in args.certificates:
        #     rank = re.match(r".*?(\d+)$", certfile).group(1)

            certs, keys = read_server_certs_and_keys(servercert_folder, serverkey_folder, intkey_folder, rank)

            root_cert, root_key = get_root_cert_and_key(certs, issuer_root_cert_map, issuer_mapping)
            if root_cert is None:
                print(f"failed to get root cert for: {certs[0]}", file=sys.stderr)
                continue

            proof_bytes = read_proof_bytes(args.proof_dir, rank)

            ep_cert_chain = add_proof_bytes_to_endpoint_cert_chain(zip(certs, keys), root_cert, root_key, rank, proof_bytes, final_servercert_folder)

            n_certs += 1
        print(f"Added proofs to {n_certs} certificates", file=sys.stderr)


if __name__ == '__main__':
    main()
