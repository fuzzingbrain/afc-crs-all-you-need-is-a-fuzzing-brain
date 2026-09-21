#!/usr/bin/env python3
"""Assemble the per-target seed corpus for the 40 AIxCC C targets.

Every seed comes from the organizer-pinned sources recorded in
paper/reports/aixcc-c-seed-audit-2026-09-18/refs.csv.  The rules below mirror
what each project's pinned build.sh does when it produces
``<harness>_seed_corpus.zip``; a target whose build never produces that zip
gets an empty corpus, exactly as base-runner's run_fuzzer would start it.

Inputs are read from ``_cache/`` (populated by --fetch, or by hand from the
pinned URLs listed in SOURCES).  Outputs go to ``corpus/<id>/`` (the
directory the fuzzer mounts) and ``cfg/<id>/`` (dict files), plus
``corpus_manifest.json`` with file counts and provenance.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CACHE = HERE / "_cache"
CORPUS = HERE / "corpus"
CFG = HERE / "cfg"

TOOLING = "https://github.com/aixcc-finals/oss-fuzz-aixcc"
MEDIA = "https://media.githubusercontent.com/media/aixcc-finals/oss-fuzz-aixcc"
RAW = "https://raw.githubusercontent.com/aixcc-finals/oss-fuzz-aixcc"

# Pinned sources.  LFS objects come from media.githubusercontent.com; plain
# files from raw.githubusercontent.com; challenge repos as archive tarballs.
SOURCES = {
    # identical across the four curl challenge-state commits (sha256 7a034aa7...)
    "curl_fuzzer.tar.gz": f"{MEDIA}/61f1bbdf4e2da72ca7a7246753aa8035fcbcb99e/projects/curl/pkgs/curl_fuzzer.tar.gz",
    # identical across the two libexif challenge-state commits (sha256 13731064...)
    "exif-samples.tar.gz": f"{MEDIA}/49994aeb9f13e7790a184b8046a112a763fd7297/projects/libexif/pkgs/exif-samples.tar.gz",
    "afc-libexif.ex-delta-02.tar.gz": "https://github.com/AIxCyberChallenge/afc-libexif/archive/69dc7e5fbe4e52090138ccb06b23fb6d90334e7e.tar.gz",
    "afc-libexif.ex-delta-03.tar.gz": "https://github.com/AIxCyberChallenge/afc-libexif/archive/c741954045bddcec61aaba21c761b561958391ec.tar.gz",
    "afc-little-cms.tar.gz": "https://github.com/AIxCyberChallenge/afc-little-cms/archive/cf5b21c614c3e9da26bba12eed76ae2bd73cfeed.tar.gz",
    "dav1d.dec_fuzzer_seed_corpus.zip": f"{RAW}/82bf1c30c1c898f828a9f0c60d30fa1188b2e826/projects/dav1d/pkgs/dec_fuzzer_seed_corpus.zip",
    "dav1d.dav1d_fuzzer_seed_corpus.zip": f"{RAW}/82bf1c30c1c898f828a9f0c60d30fa1188b2e826/projects/dav1d/pkgs/dav1d_fuzzer_seed_corpus.zip",
    "icc.dict": f"{RAW}/5ecd08d06e3e1409e1002459fc57500a30af0440/projects/lcms/icc.dict",
    "afc-libxml2.tar.gz": "https://github.com/AIxCyberChallenge/afc-libxml2/archive/d4e471ea07377053775f3d46f69c60a8d8763214.tar.gz",
}
SYSTEMD_REPO = "https://github.com/AIxCyberChallenge/afc-systemd.git"
SYSTEMD_SHA = "9a0853cc6e5bf507286f759f9d21b04bbec06fdc"

TARGETS = [l.split() for l in """
av2-del-02  delta av-delta-02          avif-002             libavif     avif_fuzztest_yuvrgb@YuvRgbFuzzTest.Convert
cu2-del-06  delta cu-delta-02          curl-006             curl        curl_fuzzer_ws
cu3-del-07  delta cu-delta-03          curl-007             curl        curl_fuzzer_ws
cu4-del-03  delta cu-delta-04          curl-003             curl        curl_fuzzer_http
cu4-del-08  delta cu-delta-04          curl-008             curl        curl_fuzzer_ws
cu5-del-01  delta cu-delta-05          curl-001             curl        curl_fuzzer_dict
cu5-del-02  delta cu-delta-05          curl-002             curl        curl_fuzzer_ftp
ex2-del-01  delta ex-delta-02          exif-001             libexif     exif_from_data_fuzzer
ex3-del-02  delta ex-delta-03          exif-002             libexif     exif_from_data_fuzzer
fp2-del-02  delta fp-delta-02          vuln_002             freerdp     TestFuzzCryptoCertificateDataSetPEM
fp3-del-03  delta fp-delta-03          vuln_003             freerdp     TestFuzzCodecs
lx3-del-04  delta lx-delta-03          vuln_004             libxml2     html
mg1-del-01  delta mg-delta-01          mongoose_1           mongoose    fuzz
mg2-del-02  delta mg-delta-02          mongoose_2           mongoose    fuzz
ws1-del-03  delta ws-delta-01          vuln_003             wireshark   handler_ber
ws2-del-04  delta ws-delta-02          vuln_004             wireshark   handler_icmp
ws3-del-06  delta ws-delta-03          vuln_006             wireshark   handler_irc
ws4-del-07  delta ws-delta-04          vuln_007             wireshark   handler_json
ws5-del-08  delta ws-delta-05          vuln_008             wireshark   handler_netbios
ws7-del-13  delta ws-delta-07          vuln_013             wireshark   handler_gvcp
cm1-fu-01   full  cm-full-01           lcms-001             lcms        cms_postscript_fuzzer
cm1-fu-02   full  cm-full-01           lcms-002             lcms        cms_virtual_profile_fuzzer
da1-fu-01   full  da-full-01           dav1d-001            dav1d       dav1d_fuzzer_mt@NO_OOM
mg1-fu-00   full  mg-full-01           mongoose_0           mongoose    fuzz
sd1-fu-01   full  systemd-full-001     systemd-001          systemd     fuzz-udev-rule-parse-value
sd1-fu-03   full  systemd-full-001     systemd-003          systemd     fuzz-catalog
sd1-fu-04   full  systemd-full-001     systemd-004          systemd     fuzz-link-parser
sd1-fu-05   full  systemd-full-001     systemd-005          systemd     fuzz-systemctl-parse-argv
ss1-fu-00   full  shadowsocks-full-01  shadowsocks-libev_0  shadowsocks json_fuzz
ss1-fu-01   full  shadowsocks-full-01  shadowsocks-libev_1  shadowsocks json_fuzz
ss1-fu-02   full  shadowsocks-full-01  shadowsocks-libev_2  shadowsocks json_fuzz
ss1-fu-03   full  shadowsocks-full-01  shadowsocks-libev_3  shadowsocks json_fuzz
ss1-fu-04   full  shadowsocks-full-01  shadowsocks-libev_4  shadowsocks json_fuzz
ws1-fu-01   full  ws-full-01           vuln_001             wireshark   handler_openvpn.udp
ws1-fu-02   full  ws-full-01           vuln_002             wireshark   handler_telnet
ws1-fu-05   full  ws-full-01           vuln_005             wireshark   handler_bat.vis
ws1-fu-10   full  ws-full-01           vuln_010             wireshark   handler_netbios
ws1-fu-11   full  ws-full-01           vuln_011             wireshark   handler_aim
ws1-fu-12   full  ws-full-01           vuln_012             wireshark   handler_zbee_zdp
xz1-fu-01   full  xz-full-01           xz-001               xz          fuzz_encode_stream
""".strip().splitlines()]


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch() -> None:
    CACHE.mkdir(exist_ok=True)
    for name, url in SOURCES.items():
        dst = CACHE / name
        if dst.exists():
            continue
        print("fetch", name)
        subprocess.run(["curl", "-sfL", url, "-o", str(dst)], check=True)
        if dst.stat().st_size < 200 and b"git-lfs" in dst.read_bytes():
            raise SystemExit(f"{name}: got an LFS pointer, not the object")
    sd = CACHE / "systemd-test-fuzz"
    if not sd.exists():
        tmp = CACHE / "_afc-systemd"
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout",
                        SYSTEMD_REPO, str(tmp)], check=True)
        subprocess.run(["git", "-C", str(tmp), "sparse-checkout", "set", "--no-cone",
                        "test/fuzz/fuzz-catalog", "test/fuzz/fuzz-link-parser",
                        "test/fuzz/fuzz-systemctl-parse-argv",
                        "test/fuzz/fuzz-udev-rule-parse-value"], check=True)
        subprocess.run(["git", "-C", str(tmp), "checkout", "-q", SYSTEMD_SHA], check=True)
        shutil.copytree(tmp / "test" / "fuzz", sd)
        shutil.rmtree(tmp)
    if not (CACHE / "libxml2-html-seed").exists():
        gen_libxml2_seed()


def gen_libxml2_seed() -> None:
    """fuzz/Makefile.am: ./genSeed html '$(top_srcdir)/test/HTML/*'.

    genSeed links against the libxml2 of the same commit, so it is built from
    the pinned source inside the libxml2 challenge image (which carries the
    autotools that base-builder lacks).  Capped like every other container.
    """
    src = CACHE / "_afc-libxml2"
    if not src.exists():
        with tarfile.open(CACHE / "afc-libxml2.tar.gz") as t:
            t.extractall(CACHE / "_x")
        shutil.move(str(next((CACHE / "_x").glob("afc-libxml2-*"))), src)
    out = CACHE / "libxml2-html-seed"
    out.mkdir()
    script = (
        "set -e; cp -r /work/libxml2 /tmp/lx && cd /tmp/lx && "
        "export CC=clang CXX=clang++ CFLAGS=-O1 CXXFLAGS=-O1; "
        "./autogen.sh --disable-shared --without-debug --without-http --without-python "
        "--with-zlib --with-lzma >/dev/null 2>&1; make -j4 >/dev/null 2>&1; cd fuzz; "
        "make genSeed >/dev/null 2>&1; mkdir -p seed/html; ./genSeed html ../test/HTML/*; "
        "cp seed/html/* /seedout/; cp html.dict /seedout/../html.dict"
    )
    subprocess.run(["timeout", "900", "docker", "run", "--rm", "--entrypoint", "",
                    "--memory=4096m", "--memory-swap=4096m", "--cpus=4", "--pids-limit=512",
                    "-v", f"{src}:/work/libxml2", "-v", f"{out}:/seedout",
                    "aixcc-afc/libxml2:latest", "bash", "-c", script], check=True)


def untar(name: str) -> Path:
    d = CACHE / "_x" / name
    if not d.exists():
        d.mkdir(parents=True)
        with tarfile.open(CACHE / name) as t:
            t.extractall(d)
    return d


def put(dst: Path, files: list[Path]) -> int:
    dst.mkdir(parents=True, exist_ok=True)
    for f in files:
        shutil.copy2(f, dst / f.name)
    return len(files)


def build() -> None:
    if CORPUS.exists():
        shutil.rmtree(CORPUS)
    if CFG.exists():
        shutil.rmtree(CFG)
    prov: dict[str, dict] = {}

    curl = next(untar("curl_fuzzer.tar.gz").glob("*/corpora"))
    exif_ext = [p for p in untar("exif-samples.tar.gz").rglob("*") if p.suffix in (".jpg", ".tiff")]
    lcms = next(untar("afc-little-cms.tar.gz").glob("*/testbed"))
    lcms_icc = [lcms / f"{n}.icc" for n in
                "bad toosmall test1 crayons ibm-t61 bad_mpe new test2 test3 test4 test5".split()]
    systemd = CACHE / "systemd-test-fuzz"
    html_seed = sorted((CACHE / "libxml2-html-seed").iterdir())

    for tid, mode, ch, bug, proj, harness in TARGETS:
        dst = CORPUS / tid
        cfg = CFG / tid
        entry: dict = {"challenge": ch, "bug": bug, "harness": harness, "seeds": 0,
                       "source": "", "libfuzzer_extra": [], "note": ""}
        if proj == "curl":
            entry["seeds"] = put(dst, sorted((curl / harness).iterdir()))
            entry["source"] = f"tooling pkgs/curl_fuzzer.tar.gz -> corpora/{harness}/ (scripts/create_zip.sh)"
        elif proj == "libexif":
            # build.sh: find exif-samples -name '*.jpg' -exec mv -n ...; then
            # cp libexif/test/testdata/*.jpg exif_corpus (overwrites same names).
            by_name: dict[str, Path] = {}
            for p in sorted(exif_ext):
                by_name.setdefault(p.name, p)
            src = next(untar(f"afc-libexif.{ch}.tar.gz").glob("*/test/testdata"))
            for p in sorted(src.glob("*.jpg")):
                by_name[p.name] = p
            entry["seeds"] = put(dst, list(by_name.values()))
            entry["source"] = "tooling pkgs/exif-samples.tar.gz (*.jpg,*.tiff) + challenge test/testdata/*.jpg"
            entry["note"] = "mv -n keeps the first of duplicate basenames; find order is filesystem-dependent"
        elif proj == "lcms":
            entry["seeds"] = put(dst, lcms_icc)
            entry["source"] = "challenge testbed/*.icc, the 11 named in tooling Dockerfile -> seed_corpus.zip"
            cfg.mkdir(parents=True)
            shutil.copy2(CACHE / "icc.dict", cfg / f"{harness}.dict")
            entry["libfuzzer_extra"] = [f"-dict=/cfg/{harness}.dict"]
        elif proj == "libxml2":
            entry["seeds"] = put(dst, html_seed)
            entry["source"] = "genSeed html test/HTML/* at the pinned commit (fuzz/Makefile.am seed/html.stamp)"
            cfg.mkdir(parents=True)
            shutil.copy2(CACHE / "html.dict", cfg / "html.dict")
            entry["libfuzzer_extra"] = ["-dict=/cfg/html.dict"]
        elif proj == "systemd":
            d = systemd / harness
            files = sorted(p for p in d.iterdir() if p.is_file()) if d.exists() else []
            entry["seeds"] = put(dst, files)
            entry["source"] = f"challenge test/fuzz/{harness}/ (tools/oss-fuzz.sh zips every test/fuzz/fuzz-* dir)"
            if not files:
                entry["note"] = "no test/fuzz dir for this harness -> no seed zip is produced"
            else:
                entry["note"] = "build-generated corpora ($build/test/fuzz/<harness>*) are not reproduced here"
        elif proj == "dav1d":
            dst.mkdir(parents=True)
            entry["source"] = "none: run_fuzzer looks for dav1d_fuzzer_mt@NO_OOM_seed_corpus.zip, which build.sh never creates"
            alt = HERE / "corpus_alt" / tid
            if alt.exists():
                shutil.rmtree(alt)
            n = 0
            with zipfile.ZipFile(CACHE / "dav1d.dec_fuzzer_seed_corpus.zip") as z:
                z.extractall(alt); n += len(z.namelist())
            with zipfile.ZipFile(CACHE / "dav1d.dav1d_fuzzer_seed_corpus.zip") as z:
                z.extractall(alt / "testdata"); n += len(z.namelist())
            entry["note"] = (f"corpus_alt/{tid} holds the {n} files of dav1d_fuzzer_mt_seed_corpus.zip "
                             "(dec zip + testdata/) for a non-competition variant")
        elif proj == "wireshark":
            dst.mkdir(parents=True)
            entry["source"] = "none: fuzzdb has no samples/<proto>/ for this handler, so fuzzshark build.sh zips nothing"
            entry["libfuzzer_extra"] = ["-max_len=1024"]   # written by tools/oss-fuzzshark/build.sh
        elif proj == "xz":
            dst.mkdir(parents=True)
            entry["source"] = "none: build.sh only zips *.lzma/*.xz for the two decoder harnesses"
            entry["libfuzzer_extra"] = ["-max_len=4096"]   # tests/ossfuzz/config/fuzz_encode_stream.options
            entry["note"] = "fuzz_xz.dict/fuzz_lzma.dict are copied to $OUT but no fuzz_encode_stream.dict exists, so run_fuzzer passes no dict"
        elif proj == "libavif":
            dst.mkdir(parents=True)
            entry["source"] = "none: Convert uses a FuzzTest generative domain; the wrapper sets TEST_DATA_DIRS=<bindir>/corpus itself"
            entry["note"] = "FuzzTest wrapper, not a plain libFuzzer target; SoK KF4 lists av2 as a broken-dependency CP"
        else:  # mongoose, shadowsocks, freerdp
            dst.mkdir(parents=True)
            entry["source"] = "none: pinned build.sh copies only *.options, creates no seed zip"
        prov[tid] = entry

    (HERE / "corpus_manifest.json").write_text(json.dumps(prov, indent=1, ensure_ascii=False) + "\n")
    inputs = {n: sha256(CACHE / n) for n in SOURCES if (CACHE / n).exists()}
    (HERE / "corpus_inputs.sha256.json").write_text(json.dumps(inputs, indent=1) + "\n")
    tot = sum(e["seeds"] for e in prov.values())
    print(f"{len(prov)} targets, {tot} seed files, {sum(1 for e in prov.values() if e['seeds'])} targets with seeds")


if __name__ == "__main__":
    if "--fetch" in sys.argv:
        fetch()
    build()
