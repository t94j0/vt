import sys
import re
from virus_total_apis import PublicApi as VirusTotalPublicApi

API_KEY = ''
vt = VirusTotalPublicApi(API_KEY)


def is_md5(hsh):
    return re.match(r"([a-fA-F\d]{32})", hsh) is not None


def is_sha1(hsh):
    return re.match(r"^[a-fA-F0-9]{40}$", hsh) is not None


def is_sha256(hsh):
    return re.match(r"^([a-f0-9]{64})$", hsh) is not None


def is_valid_hash(hsh):
    return is_md5(hsh) or is_sha1(hsh) or is_sha256(hsh)


def virus_total(hsh):
    response = vt.get_file_report(hsh)
    if 'results' not in response:
        return None
    if response['results']['response_code'] == 0:
        return None
    return response['results'] if response['results']['positives'] > 0 else None


def lookup(hsh):
    if not is_valid_hash(hsh):
        print('Error: {} is not a valid SHA1/SHA256/MD5 hash'.format(hsh))
        return
    result = virus_total(hsh)
    if result is not None:
        print(hsh)


def clean_and_check(hsh):
    hsh = hsh.strip()
    lookup(hsh)


def main():
    [clean_and_check(hsh) for hsh in sys.stdin]


if __name__ == '__main__':
    main()
