import sys
import re
import configparser
from functools import partial
from os import path
from virus_total_apis import PublicApi as VirusTotalPublicApi


def is_md5(hsh):
    return re.match(r"([a-fA-F\d]{32})", hsh) is not None


def is_sha1(hsh):
    return re.match(r"^[a-fA-F0-9]{40}$", hsh) is not None


def is_sha256(hsh):
    return re.match(r"^([a-f0-9]{64})$", hsh) is not None


def is_valid_hash(hsh):
    return is_md5(hsh) or is_sha1(hsh) or is_sha256(hsh)


def has_positives(hsh):
    response = vt.get_file_report(hsh)
    if 'results' not in response:
        return None
    if response['results']['response_code'] == 0:
        return None
    return response['results'] if response['results']['positives'] > 0 else None


def vt_checker(vt: 'VirusTotalPublicApi', hsh: str):
    if not is_valid_hash(hsh):
        print('Error: {} is not a valid SHA1/SHA256/MD5 hash'.format(hsh))
        return
    result = has_positives(hsh)
    if result is not None:
        yield result


def create_checker() -> 'VirusTotalPublicApi':
    config = configparser.ConfigParser()
    config.read([
        'vt.conf',
        path.expanduser('~/.vt.conf'),
        path.expanduser('~/.config/vt.conf')
    ])
    api_key = config.get('config', 'API_KEY')
    return VirusTotalPublicApi(api_key)


def main():
    vt = create_checker()
    for hsh in sys.stdin:
        vt_checker(vt, hsh.strip())


if __name__ == '__main__':
    main()
