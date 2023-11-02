import argparse
import re
from acme_types import URL

DNS_CHALLENGE_TYPE = "dns01"
HTTP_CHALLENGE_TYPE = "http01"


def acquire_certificate(
    challenge_type: str, dir_url: URL, record: str, domains: list[str]
):
    print(
        f"acquire_certificate: {challenge_type}, {dir_url}, {record}, {domains}"
    )

    return "certificate"


def revoke_certificate(certificate: str):
    print("revoke_certificate", certificate)

def parse_cli_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "challenge_type", choices=[DNS_CHALLENGE_TYPE, HTTP_CHALLENGE_TYPE], type=str, help="Name of the user"
    )
    parser.add_argument(
        "--dir",
        metavar="DIR_URL",
        required=True,
        type=str,
        help="Directory URL of the ACME server that should be used.",
    )
    parser.add_argument(
        "--record",
        metavar="IPv4_ADDRESS",
        required=True,
        type=str,
        help="DNS answer to all  A-record queries",
    )
    parser.add_argument(
        "--domain",
        metavar="DOMAIN",
        dest="domains",
        action="append",
        required=True,
        type=str,
        help="Domain name for which the certificate should be issued",
    )
    parser.add_argument(
        "--revoke",
        action="store_true",
        help="Revoke certificates immediately after they are created",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_cli_args()

    certificate = acquire_certificate(
        args.challenge_type, args.dir, args.record, args.domains
    )

    if args.revoke:
        revoke_certificate(certificate)