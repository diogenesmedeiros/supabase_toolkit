import os

from .constants import DEFAULT_WORDLIST, IDENT_RE


def load_wordlist(path):
    names = []
    skipped = 0

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                name = raw.strip()

                if not name or name.startswith("#"):
                    continue

                if IDENT_RE.fullmatch(name):
                    names.append(name)
                else:
                    skipped += 1
    except OSError as error:
        raise ValueError(f"Could not read wordlist: {error}")

    if skipped:
        print(f"[!] {skipped} invalid name(s) ignored in the wordlist.")

    print(f"[+] {len(names)} name(s) loaded from {path}")

    return names


def load_builtin_wordlist():
    if os.path.isfile(DEFAULT_WORDLIST):
        try:
            return load_wordlist(DEFAULT_WORDLIST)
        except ValueError as error:
            print(f"[!] {error}")

    print(f"[!] Default wordlist missing: {DEFAULT_WORDLIST}")

    return []
