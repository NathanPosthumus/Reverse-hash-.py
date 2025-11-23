#!/usr/bin/env python3
# Minimal brute-force script (from scratch)
# First asks for a plaintext password to hash (so you can test cracking),
# or you can leave it blank and paste a hash directly. Then asks algorithm
# and max length and brute-forces lowercase strings.
"""
Improved brute-force hash reverser.

Features added:
- Compare raw digest bytes (avoid hexdigest overhead).
- Optional multiprocessing to use multiple CPU cores.
- Configurable charset (lowercase, lowercase+digits, lowercase+digits+upper).
- CLI flags with interactive fallback.
- Prints total attempts and elapsed time.

Keep in mind: Python is still much slower than GPU tools like hashcat. Use small max lengths.
"""

import argparse
import hashlib
import itertools
import sys
import time
from multiprocessing import Pool, cpu_count, Manager
import string


CHARSETS = {
    'lower': string.ascii_lowercase,
    'lower_digits': string.ascii_lowercase + string.digits,
    'all': string.ascii_lowercase + string.digits + string.ascii_uppercase,
    # special includes letters, digits and common punctuation
    'special': string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation,
}


def parse_args():
    p = argparse.ArgumentParser(description='Brute-force reverse a hash (improved).')
    p.add_argument('--password', '-p', help='Plaintext password to hash-and-crack (interactive if omitted).')
    p.add_argument('--hash', '-t', help='Target hash (hex). If omitted, prompted).')
    p.add_argument('--alg', '-a', default='md5', help='Hash algorithm (md5, sha1, sha256, ...)')
    p.add_argument('--max', '-m', type=int, default=3, help='Max length to try (default 3)')
    p.add_argument('--charset', '-c', choices=CHARSETS.keys(), default='special', help='Character set to use')
    p.add_argument('--workers', '-w', type=int, default=1, help='Number of worker processes (1 = single-process)')
    return p.parse_args()


def make_prefixes(charset, workers):
    # Create a list of prefixes to split the keyspace; try single-letter prefixes first
    # If more workers than charset length, use two-letter prefixes.
    if workers <= 1:
        return ['']
    L = len(charset)
    prefixes = [c for c in charset]
    if len(prefixes) >= workers:
        return prefixes[:workers]
    # need more prefixes: use 2-letter combos
    prefixes = []
    for a in charset:
        for b in charset:
            prefixes.append(a + b)
            if len(prefixes) >= workers:
                return prefixes
    return prefixes


def worker_task(args):
    # Unpack arguments to avoid closure pickling issues
    prefix, target_bytes, alg, max_len, charset, counter, show_each = args
    local_tries = 0
    start = time.time()
    charset_bytes = [c.encode('utf-8') for c in charset]
    prefix_bytes = prefix.encode('utf-8') if prefix else b''
    hasher_name = alg
    # For lengths >= len(prefix)
    for length in range(len(prefix), max_len + 1):
        rem = length - len(prefix)
        if rem == 0:
            cand = prefix_bytes
            local_tries += 1
            if show_each:
                print(cand.decode())
            if hashlib.new(hasher_name, cand).digest() == target_bytes:
                # update counter with remaining local_tries
                with counter.get_lock():
                    counter.value += local_tries
                return (cand.decode(), local_tries, time.time() - start)
        else:
            for tup in itertools.product(charset_bytes, repeat=rem):
                cand = prefix_bytes + b''.join(tup)
                local_tries += 1
                if show_each:
                    try:
                        print(cand.decode())
                    except Exception:
                        print(repr(cand))
                if hashlib.new(hasher_name, cand).digest() == target_bytes:
                    with counter.get_lock():
                        counter.value += local_tries
                    return (cand.decode(), local_tries, time.time() - start)
        # periodically flush local tries into shared counter to reduce locking
        if local_tries and local_tries % 1000 == 0:
            with counter.get_lock():
                counter.value += local_tries
            local_tries = 0
    # last flush
    if local_tries:
        with counter.get_lock():
            counter.value += local_tries
    return (None, 0, time.time() - start)


def single_process_search(target_bytes, alg, max_len, charset, show_each):
    tries = 0
    start = time.time()
    for length in range(1, max_len + 1):
        for tup in itertools.product(charset, repeat=length):
            s = ''.join(tup)
            tries += 1
            if show_each:
                print(s)
            if hashlib.new(alg, s.encode('utf-8')).digest() == target_bytes:
                elapsed = time.time() - start
                return s, tries, elapsed
    elapsed = time.time() - start
    return None, tries, elapsed


def main():
    args = parse_args()

    # interactive fallbacks
    password = args.password
    target = args.hash
    # force md5 per user request
    alg = 'md5'
    max_len = args.max
    charset_name = args.charset
    workers = args.workers
    # do NOT show each attempt (faster)
    show_each = False

    # Read password: prefer piped stdin when present, otherwise prompt interactively
    if not sys.stdin.isatty():
        piped = sys.stdin.read().strip()
        password = piped or None
    else:
        if not password:
            password = input('Enter the password to hash-and-crack (required): ').strip() or None
    if not password:
        print('No password entered. Exiting.')
        sys.exit(1)

    # Resolve charset
    charset = CHARSETS.get(charset_name, CHARSETS['lower'])

    # Perform a real brute-force search up to the length of the provided password.
    # WARNING: using the full charset with length > 4 may be very slow.
    charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    target_bytes = hashlib.new(alg, password.encode('utf-8')).digest()

    tries = 0
    start = time.time()

    for length in range(1, len(password) + 1):
        for tup in itertools.product(charset, repeat=length):
            cand = ''.join(tup)
            tries += 1
            if hashlib.new(alg, cand.encode('utf-8')).digest() == target_bytes:
                elapsed = time.time() - start
                print('Found:', cand)
                print(f'Tries: {tries}')
                print(f'Time: {elapsed:.2f}s')
                return

    elapsed = time.time() - start
    print('Not found')
    print(f'Tries: {tries}')
    print(f'Time: {elapsed:.2f}s')
    return


if __name__ == '__main__':
    main()

