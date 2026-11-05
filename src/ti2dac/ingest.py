"""Report ingestion: file/URL -> normalized text + provenance.

The original bytes are preserved unchanged (written to the run folder by the renderer) and
hashed with SHA-256. URL fetching is SSRF-hardened: http(s) only, every redirect hop is
re-checked, private/loopback/link-local/reserved addresses are refused, size is capped.
"""
from __future__ import annotations

import hashlib
import io
import ipaddress
import re
import socket
import time
import unicodedata
import zipfile
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import getproxies, proxy_bypass

import httpx

from .config import FetchConfig
from .models import ReportMeta


class IngestError(Exception):
    pass


@dataclass
class LoadedReport:
    meta: ReportMeta
    raw: bytes
    filename: str
    text: str            # normalized full text (markdown-ish for HTML, [page N] markers for PDF)
    redaction_map: dict = field(default_factory=dict)      # placeholder -> original value (local only)
    embedded_events: list = field(default_factory=list)    # raw log events found in the report


# Zero-width / bidi / control characters are a common carrier for hidden prompt-injection text.
_INVISIBLE = re.compile(r"[​-‏‪-‮⁠-⁤﻿­]")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# Hostile documents: a few hundred KB can expand to GBs (zip bomb) or take hours to parse (pypdf ~5s/page).
_DOCX_MAX_UNZIPPED = 100 * 1024 * 1024    # all parts, images included
_DOCX_MAX_XML = 16 * 1024 * 1024           # parsed into an lxml tree at ~25x its size
_PDF_MAX_PAGES = 500
_PDF_BUDGET_S = 120.0
# A slow-drip server resets the per-read timeout forever; the whole download gets this many timeouts.
_FETCH_TOTAL_FACTOR = 4
_DNS_TIMEOUT_S = 10.0


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    text = _CTRL.sub(" ", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- converters
def _html_to_text(raw: bytes) -> tuple[str, dict[str, str]]:
    import trafilatura

    html = raw.decode("utf-8", errors="replace")
    meta: dict[str, str] = {}
    try:
        m = trafilatura.extract_metadata(html)
        if m:
            meta = {"title": m.title or "", "authors": m.author or "", "published": m.date or "", "url": m.url or ""}
    except Exception:
        pass
    text = trafilatura.extract(
        html, include_tables=True, include_comments=False, include_links=False,
        favor_recall=True, output_format="markdown",
    )
    if not text or len(text) < 500:
        # Fallback: plain soup text of the largest content container.
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "lxml")
        for t in soup(["script", "style", "nav", "footer", "header", "aside", "form", "noscript", "svg"]):
            t.decompose()
        candidates = soup.find_all(["article", "main", "div", "body"]) or [soup]
        best = max(candidates, key=lambda c: len(c.get_text(" ", strip=True)))
        text = best.get_text("\n", strip=True)
        if not meta.get("title") and soup.title:
            meta["title"] = soup.title.get_text(strip=True)
    return text, meta


def _pdf_to_text(raw: bytes) -> tuple[str, dict[str, str]]:
    from pypdf import PdfReader

    try:
        reader = PdfReader(io.BytesIO(raw))
    except Exception as e:
        raise IngestError(f"malformed PDF: {e}") from e
    pages = []
    total, deadline = len(reader.pages), time.monotonic() + _PDF_BUDGET_S
    for i, page in enumerate(reader.pages, 1):
        if i > _PDF_MAX_PAGES or time.monotonic() > deadline:   # keep what was extracted
            why = f"{_PDF_MAX_PAGES}-page limit" if i > _PDF_MAX_PAGES else f"{_PDF_BUDGET_S:.0f}s time limit"
            pages.append(f"[text extraction stopped at page {i - 1} of {total}: {why}]")
            break
        try:
            pages.append(f"[page {i}]\n{page.extract_text() or ''}")
        except Exception:
            pages.append(f"[page {i}]\n")
    info = reader.metadata or {}
    meta = {"title": str(info.get("/Title") or ""), "authors": str(info.get("/Author") or "")}
    return "\n\n".join(pages), meta


def _docx_to_text(raw: bytes) -> tuple[str, dict[str, str]]:
    """Word incident reports: paragraphs, headings and tables (timelines) in document order."""
    from docx import Document          # python-docx parses with resolve_entities=False (no XXE)
    from docx.table import Table
    from docx.text.paragraph import Paragraph

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:   # zipfile never inflates a member past its declared size
            parts = zf.infolist()
    except (zipfile.BadZipFile, ValueError) as e:
        raise IngestError(f"malformed DOCX: {e}") from e
    unzipped = sum(i.file_size for i in parts)
    xml = sum(i.file_size for i in parts if i.filename.endswith((".xml", ".rels")))
    if unzipped > _DOCX_MAX_UNZIPPED or xml > _DOCX_MAX_XML:
        raise IngestError(f"DOCX expands to {unzipped // 2**20} MB ({xml // 2**20} MB of XML) uncompressed; limits are "
                          f"{_DOCX_MAX_UNZIPPED // 2**20} MB and {_DOCX_MAX_XML // 2**20} MB of XML. Refusing a likely zip bomb.")
    try:
        doc = Document(io.BytesIO(raw))
    except Exception as e:
        raise IngestError(f"malformed DOCX: {e}") from e
    out: list[str] = []
    for child in doc.element.body.iterchildren():
        tag = child.tag.rsplit("}", 1)[-1]
        if tag == "p":
            para = Paragraph(child, doc)
            txt = para.text.strip()
            if txt:
                style = (para.style.name or "") if para.style is not None else ""
                out.append(("## " + txt) if style.lower().startswith(("heading", "title")) else txt)
        elif tag == "tbl":
            for row in Table(child, doc).rows:
                cells = [c.text.strip().replace("\n", " ") for c in row.cells]
                out.append("| " + " | ".join(dict.fromkeys(cells)) + " |")
            out.append("")
    props = doc.core_properties
    return "\n\n".join(out), {"title": props.title or "", "authors": props.author or ""}


def _eml_to_text(raw: bytes) -> tuple[str, dict[str, str]]:
    """Incident notifications sent by email; attachments are ignored."""
    from email import policy
    from email.parser import BytesParser

    msg = BytesParser(policy=policy.default).parsebytes(raw)
    body = msg.get_body(preferencelist=("plain", "html"))
    text = ""
    if body is not None:
        content = body.get_content()
        text = _html_to_text(content.encode())[0] if body.get_content_type() == "text/html" else content
    header = "\n".join(f"{h}: {msg[h]}" for h in ("From", "To", "Date", "Subject") if msg[h])
    return f"{header}\n\n{text}", {"title": str(msg["Subject"] or "")}


def _convert(raw: bytes, name: str, content_type: str) -> tuple[str, dict[str, str], str]:
    lname, ctype = name.lower(), content_type.lower()
    if lname.endswith(".docx") or "wordprocessingml" in ctype:
        text, meta = _docx_to_text(raw)
        return normalize_text(text), meta, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    if lname.endswith(".eml") or ctype.startswith("message/rfc822"):
        text, meta = _eml_to_text(raw)
        return normalize_text(text), meta, "message/rfc822"
    if raw[:5] == b"%PDF-" or lname.endswith(".pdf") or "pdf" in ctype and "html" not in ctype:
        text, meta = _pdf_to_text(raw)
        kind = "application/pdf"
    elif lname.endswith((".html", ".htm")) or "html" in ctype or raw.lstrip()[:15].lower().startswith((b"<!doctype", b"<html")):
        text, meta = _html_to_text(raw)
        kind = "text/html"
    else:
        text, meta = raw.decode("utf-8", errors="replace"), {}
        kind = "text/markdown" if lname.endswith(".md") else "text/csv" if lname.endswith((".csv", ".tsv")) else "text/plain"
    return normalize_text(text), meta, kind


# --------------------------------------------------------------------------- URL fetching
def _check_host(host: str, cfg: FetchConfig) -> None:
    if cfg.allowed_domains and not any(host == d or host.endswith("." + d) for d in cfg.allowed_domains):
        raise IngestError(f"host {host!r} is not in fetch.allowed_domains")
    infos = None
    for attempt in range(2):   # one retry: transient resolver failures are common on busy hosts/VPNs
        ex = ThreadPoolExecutor(1)   # getaddrinfo has no timeout of its own
        try:
            infos = ex.submit(socket.getaddrinfo, host, None).result(timeout=_DNS_TIMEOUT_S)
            break
        except FuturesTimeout as e:
            raise IngestError(f"cannot resolve {host}: timed out after {_DNS_TIMEOUT_S:.0f}s") from e
        except socket.gaierror as e:
            if attempt:
                raise IngestError(f"cannot resolve {host}: {e}") from e
            time.sleep(1.5)
        finally:
            ex.shutdown(wait=False)
    for info in infos:
        _check_ip(info[4][0], host)


def _check_ip(addr: str, host: str) -> None:
    ip = ipaddress.ip_address(addr.split("%", 1)[0])   # strip an IPv6 zone id
    if not ip.is_global or ip.is_multicast:
        raise IngestError(f"refusing to fetch {host}: resolves to non-public address {ip}")


def _proxied(url: str) -> bool:
    """httpx honours *_PROXY env vars; the TCP peer is then the proxy, not the report host."""
    p, host = getproxies(), urlparse(url).hostname or ""
    return bool(p.get(urlparse(url).scheme) or p.get("all")) and not proxy_bypass(host)


def fetch_url(url: str, cfg: FetchConfig) -> tuple[bytes, str, str]:
    if not cfg.allow_urls:
        raise IngestError("URL ingestion disabled by configuration")
    headers = {"User-Agent": "ti2dac/0.1 (+threat-intel-to-detection; research use)"}
    deadline = time.monotonic() + cfg.timeout_s * _FETCH_TOTAL_FACTOR

    def overdue() -> None:
        if time.monotonic() > deadline:
            raise IngestError(f"download of {url} took longer than {cfg.timeout_s * _FETCH_TOTAL_FACTOR:.0f}s")

    with httpx.Client(follow_redirects=False, timeout=cfg.timeout_s, headers=headers) as client:
        for _ in range(6):
            overdue()
            p = urlparse(url)
            if p.scheme not in ("http", "https") or not p.hostname:
                raise IngestError(f"unsupported URL: {url}")
            _check_host(p.hostname, cfg)

            def trace(event: str, info: dict, host: str = p.hostname, direct: bool = not _proxied(url)) -> None:
                # DNS rebinding: httpx resolves again, so check the address actually connected to before sending
                if direct and event == "connection.connect_tcp.complete":
                    _check_ip(info["return_value"].get_extra_info("server_addr")[0], host)

            with client.stream("GET", url, extensions={"trace": trace}) as r:
                if r.is_redirect:
                    url = urljoin(url, r.headers.get("location", ""))
                    continue
                if r.status_code != 200:
                    raise IngestError(f"HTTP {r.status_code} fetching {url}")
                buf = bytearray()
                for chunk in r.iter_bytes():
                    buf.extend(chunk)
                    if len(buf) > cfg.max_bytes:
                        raise IngestError(f"report exceeds {cfg.max_bytes} bytes")
                    overdue()
                return bytes(buf), r.headers.get("content-type", ""), url
    raise IngestError("too many redirects")


# --------------------------------------------------------------------------- entry point
def load_report(source: str, cfg: FetchConfig, *, raw: bytes | None = None, filename: str | None = None) -> LoadedReport:
    """Load from a path, a URL, or already-uploaded bytes (web UI)."""
    content_type = ""
    if raw is not None:
        name = filename or source
    elif re.match(r"^https?://", source, re.I):
        raw, content_type, source = fetch_url(source, cfg)
        name = Path(urlparse(source).path).name or "report.html"
        if "." not in name:
            name += ".pdf" if "pdf" in content_type else ".html"
    else:
        path = Path(source)
        if not path.is_file():
            raise IngestError(f"no such file: {source}")
        if path.stat().st_size > cfg.max_bytes:
            raise IngestError(f"report exceeds {cfg.max_bytes} bytes")
        raw, name = path.read_bytes(), path.name

    if not raw or not raw.strip():
        raise IngestError("report is empty")
    text, meta, kind = _convert(raw, name, content_type)
    if len(text) < 200:
        hint = ""
        if kind == "text/html":
            hint = (" The file looks like a page shell whose article is loaded by JavaScript (common for saved "
                    "Google Cloud/Mandiant, Microsoft and CrowdStrike blog pages) or a captcha page. Use the "
                    "public URL, or open the page in a browser and 'Print -> Save as PDF', or paste the text into a .md file.")
        elif kind == "application/pdf":
            hint = " The PDF appears to be scanned images; run OCR first (e.g. ocrmypdf) or use the HTML version."
        raise IngestError(f"extracted only {len(text)} characters of text.{hint}")

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    banner = re.compile(r"(?i)^(tlp\s*:|classification|confidential|internal use|\[page \d+\]$)")
    first_heading = next((ln.lstrip("# ").strip() for ln in lines if ln.startswith("#")), "") or \
        next((ln for ln in lines if not banner.match(ln)), "")
    return LoadedReport(
        meta=ReportMeta(
            source=source,
            title=(meta.get("title") or first_heading)[:200],
            sha256=hashlib.sha256(raw).hexdigest(),
            retrieved_at=_now(),
            content_type=kind,
            chars=len(text),
            authors=meta.get("authors", ""),
            published=meta.get("published", ""),
            url=source if re.match(r"^https?://", source, re.I) else meta.get("url", ""),
        ),
        raw=raw,
        filename=re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120],
        text=text,
    )
