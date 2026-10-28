#!/usr/bin/env python3
"""Validate shipped gettext catalogs without a network or translation service."""
import ast
from collections import Counter
import gettext
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "wordpress-plugin"
LANG = ROOT / "languages"
LOCALES = {"ja", "es_ES", "de_DE", "fr_FR", "pt_BR", "it_IT", "ru_RU", "nl_NL", "zh_CN", "pl_PL", "tr_TR", "id_ID", "zh_TW", "ko_KR"}


def read_po(path):
    result = {}
    entry = {}
    field = None
    fuzzy = False

    def save():
        if "msgid" in entry:
            assert not fuzzy, f"{path.name}: fuzzy entry {entry['msgid']}"
            assert entry["msgid"] not in result, f"{path.name}: duplicate msgid"
            result[entry["msgid"]] = entry.get("msgstr", "")

    for line in path.read_text(encoding="utf-8").splitlines() + [""]:
        if not line:
            save()
            entry, field, fuzzy = {}, None, False
        elif line.startswith("#~"):
            raise AssertionError(f"{path.name}: obsolete entry")
        elif line.startswith("#"):
            fuzzy = fuzzy or (line.startswith("#,") and "fuzzy" in line)
        elif line.startswith(("msgid ", "msgstr ")):
            field, literal = line.split(" ", 1)
            entry[field] = ast.literal_eval(literal)
        elif line.startswith('"'):
            assert field, f"{path.name}: continuation without a field"
            entry[field] += ast.literal_eval(line)
        else:
            raise AssertionError(f"{path.name}: unsupported entry syntax {line}")
    return result


source = set(read_po(LANG / "atshift-ip-blocker.pot")) - {""}
assert len(source) == 117, "Update the expected catalog size after reviewing new strings."
actual = {p.stem.removeprefix("atshift-ip-blocker-") for p in LANG.glob("atshift-ip-blocker-*.po")}
assert actual == LOCALES, f"Locale set mismatch: {actual ^ LOCALES}"
placeholder = re.compile(r"%(?:\d+\$)?[-+0 #]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[bcdeEfFgGosuxXdi%]")
technical = (".htaccess", "REMOTE_ADDR", "SERVER_ADDR", "CloudSecure", "Wordfence", "Semantic Deterrence", "SDN", "SFTP", "WordPress", "Apache", "IPv4", "IPv6", "blocked:waf")

for locale in sorted(LOCALES):
    path = LANG / f"atshift-ip-blocker-{locale}.po"
    entries = read_po(path)
    assert set(entries) - {""} == source, f"{locale}: missing or extra source strings"
    assert f"Language: {locale}\n" in entries[""], f"{locale}: incorrect Language header"
    with tempfile.TemporaryDirectory(prefix="ipbw-gettext-") as tmp:
        compiled = Path(tmp) / "catalog.mo"
        subprocess.run(["msgfmt", "--check", "--check-format", "-o", str(compiled), str(path)], check=True)
        assert compiled.read_bytes() == path.with_suffix(".mo").read_bytes(), f"{locale}: stale compiled MO"
    with path.with_suffix(".mo").open("rb") as handle:
        catalog = gettext.GNUTranslations(handle)
    for msgid in source:
        translated = entries[msgid]
        assert translated.strip(), f"{locale}: untranslated {msgid}"
        assert Counter(placeholder.findall(msgid)) == Counter(placeholder.findall(translated)), f"{locale}: changed placeholders: {msgid}"
        for token in technical:
            if token in msgid:
                assert token in translated, f"{locale}: lost technical token {token}: {msgid}"
        assert "<" not in translated and ">" not in translated, f"{locale}: unexpected markup"
        assert catalog.gettext(msgid) == translated, f"{locale}: compiled translation mismatch"
    print(f"PASS {locale}: {len(source)} complete translations, formats, tokens and compiled MO")
print(f"PASS {len(LOCALES)} catalogs plus English source: 15 interface languages")
