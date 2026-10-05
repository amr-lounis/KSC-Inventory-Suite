"""Canonical software names: arch/locale/channel/version variants unify."""
import vuln_check as vc


def test_firefox_variants_unify():
    names = {vc.canonical_name("Mozilla Firefox (x64 fr)", "128.0"),
             vc.canonical_name("Mozilla Firefox ESR (x86 fr)", "115.13.0"),
             vc.canonical_name("Mozilla Firefox (x64 en-US)", "128.0")}
    assert names == {"Mozilla Firefox"}


def test_branding_years_kept_distinct():
    a = vc.canonical_name("Microsoft Office Professional Plus 2019 - fr-fr", "16.0.1")
    b = vc.canonical_name("Microsoft Office Professional Plus 2007", "12.0.1")
    assert a == "Microsoft Office Professional Plus 2019"
    assert b == "Microsoft Office Professional Plus 2007"
    assert a != b


def test_edition_arch_parens_stripped_but_real_editions_kept():
    names = {vc.canonical_name("7-Zip 18.05 (x64 edition)", "18.05"),
             vc.canonical_name("7-Zip 22.01 (x64 edition)", "22.01"),
             vc.canonical_name("7-Zip 9.20 (x64 edition)", "9.20"),
             vc.canonical_name("7-Zip", "")}
    assert names == {"7-Zip"}
    # real SKU editions are preserved
    assert "Professional" in vc.canonical_name(
        "ABBYY FineReader 8.0 Professional Edition", "8.0")


def test_version_in_name_stripped_only_when_matching():
    assert vc.canonical_name("Opera Stable 135.0.5973.92", "135.0.5973.92") == "Opera"
    assert vc.canonical_name("Python 3.12", "3.12.0") == "Python"
    # dotted version baked into the name unifies even without version context
    assert vc.canonical_name("Mozilla Firefox 50.1.0", "") == "Mozilla Firefox"
    assert vc.canonical_name("Mozilla Firefox 50.1.0", "99.0") == "Mozilla Firefox"
    # branding year is NOT the record version -> kept
    assert "2008" in vc.canonical_name(
        "Fichiers de support Microsoft SQL Server 2008", "10.0.1600.22")
    assert vc.canonical_name("Microsoft Office Professional Plus 2019 - fr-fr",
                             "16.0.1") == "Microsoft Office Professional Plus 2019"


def test_merge_groups_variants(tmp_path=None):
    def item(name, version, score):
        return {"name": name, "version": version, "publisher": "X",
                "family": None, "os": ["windows"], "count": 1, "hosts": ["h1"],
                "os_counts": {}, "hosts_by_os": {"windows": ["h1"]},
                "score": score, "level": "High", "reasons": [f"r-{version}"],
                "action": "-", "cves": []}
    items = [item("Mozilla Firefox (x64 fr)", "128.0", 9),
             item("Mozilla Firefox ESR (x86 fr)", "115.13.0", 7),
             item("Safe Tool", "1.0", 0)]
    groups = vc._merge_by_software(items, "windows")
    assert len(groups) == 2
    ff = next(g for g in groups if g["name"] == "Mozilla Firefox")
    assert ff["name"] == "Mozilla Firefox"
    assert sorted(ff["versions"]) == ["115.13.0", "128.0"]
    assert ff["score"] == 9
