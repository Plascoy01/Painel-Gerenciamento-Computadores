#!/usr/bin/env python3
"""plascoy modules.crawler

Advanced web crawler with endpoint discovery.

This module is used by the framework flag:
  --crawl [--depth N] [--max-pages M]

It must be syntactically valid because plascoy imports/loads it.
"""

from __future__ import annotations

import hashlib
import logging
import time
import re
import json
import queue
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urljoin, urlparse
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class CrawlResult:
    url: str
    status_code: int
    content_type: str
    content_length: int
    title: str
    links: List[str]
    forms: List[Dict[str, Any]]
    scripts: List[str]
    images: List[str]
    response_time: float
    timestamp: float
    hash: str
    depth: int


@dataclass
class CrawlStats:
    total_urls: int = 0
    crawled_urls: int = 0
    failed_urls: int = 0
    max_depth_reached: int = 0
    start_time: float = 0.0
    end_time: float = 0.0


class AdvancedWebCrawler:
    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        self.target = self._normalize_url(target)
        self.config = {**self._default_config(), **(config or {})}
        self.domain = urlparse(self.target).netloc

        self.visited: Set[str] = set()
        self.queued: Set[str] = set()
        self.failed: Set[str] = set()

        self.results: List[CrawlResult] = []
        self.url_queue: queue.Queue[Tuple[str, int]] = queue.Queue()

        self.endpoints: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self.scripts: Set[str] = set()
        self.images: Set[str] = set()
        self.emails: Set[str] = set()
        self.phones: Set[str] = set()

        self.content_hashes: Set[str] = set()
        self.response_codes: Dict[int, int] = {}
        self.content_types: Dict[str, int] = {}

        self.stats = CrawlStats()

        self.session = self._create_session()
        self.robots_parser = self._setup_robots_parser()

    @staticmethod
    def _default_config() -> Dict[str, Any]:
        return {
            'max_depth': 3,
            'max_pages': 500,
            'timeout': 10,
            'user_agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36'
            ),
            'verify_ssl': False,
            'respect_robots': True,
            'follow_redirects': True,
            'extract_emails': True,
            'extract_phones': True,
            'include_subdomains': False,
            'exclude_extensions': [
                '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar', '.7z', '.tar.gz'
            ],
            'include_query_params': True,
            'delay_between_requests': 0.0,
            'max_content_length': 10 * 1024 * 1024,
        }

    @staticmethod
    def _normalize_url(url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def _create_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            'User-Agent': self.config['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        s.verify = self.config['verify_ssl']
        s.max_redirects = 5 if self.config['follow_redirects'] else 0
        return s

    def _setup_robots_parser(self) -> Optional[RobotFileParser]:
        if not self.config['respect_robots']:
            return None
        try:
            robots_url = urljoin(self.target, '/robots.txt')
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            return rp
        except Exception as e:
            logger.debug("Could not read robots.txt: %s", e)
            return None

    def crawl(self) -> Dict[str, Any]:
        self.stats.start_time = time.time()
        self._initialize_crawl()

        while len(self.visited) < self.config['max_pages'] and not self.url_queue.empty():
            url, depth = self.url_queue.get()
            if url in self.visited or depth > self.config['max_depth']:
                continue

            self.visited.add(url)
            self.stats.crawled_urls += 1
            self.stats.max_depth_reached = max(self.stats.max_depth_reached, depth)

            res = self._crawl_url(url, depth)
            if res is not None:
                self.results.append(res)

            if self.config['delay_between_requests']:
                time.sleep(self.config['delay_between_requests'])

        self.stats.end_time = time.time()
        analysis = self._analyze_crawl_results()

        return {
            'target': self.target,
            'config': self.config,
            'stats': asdict(self.stats),
            'results': [asdict(r) for r in self.results],
            'endpoints': sorted(self.endpoints),
            'forms': self.forms,
            'scripts': sorted(self.scripts),
            'images': sorted(self.images),
            'emails': sorted(self.emails),
            'phones': sorted(self.phones),
            'analysis': analysis,
        }

    def _initialize_crawl(self) -> None:
        self.url_queue.put((self.target, 0))
        self.queued.add(self.target)

    def _crawl_url(self, url: str, depth: int) -> Optional[CrawlResult]:
        start = time.time()
        try:
            if self.robots_parser and not self.robots_parser.can_fetch(self.config['user_agent'], url):
                return None

            r = self.session.get(
                url,
                timeout=self.config['timeout'],
                allow_redirects=self.config['follow_redirects'],
            )

            response_time = time.time() - start
            self.response_codes[r.status_code] = self.response_codes.get(r.status_code, 0) + 1

            content_length = len(r.content) if r.content else 0
            if content_length > self.config['max_content_length']:
                return None

            content_type = (r.headers.get('content-type', '') or '').split(';')[0].strip().lower()
            if content_type:
                self.content_types[content_type] = self.content_types.get(content_type, 0) + 1

            # Non-HTML: return minimal result
            if 'text/html' not in content_type:
                return CrawlResult(
                    url=url,
                    status_code=r.status_code,
                    content_type=content_type,
                    content_length=content_length,
                    title='',
                    links=[],
                    forms=[],
                    scripts=[],
                    images=[],
                    response_time=response_time,
                    timestamp=time.time(),
                    hash='',
                    depth=depth,
                )

            soup = BeautifulSoup(r.content, 'html.parser')
            title = (soup.title.string.strip() if soup.title and soup.title.string else '')
            links = self._extract_links(soup, url)
            forms = self._extract_forms(soup, url)
            scripts = self._extract_scripts(soup, url)
            images = self._extract_images(soup, url)

            if self.config['extract_emails']:
                self._extract_emails(r.text)
            if self.config['extract_phones']:
                self._extract_phones(r.text)

            content_hash = hashlib.md5(r.content).hexdigest()
            if content_hash not in self.content_hashes:
                self.content_hashes.add(content_hash)

            self._queue_new_urls(links, depth)

            return CrawlResult(
                url=url,
                status_code=r.status_code,
                content_type=content_type,
                content_length=content_length,
                title=title,
                links=links,
                forms=forms,
                scripts=scripts,
                images=images,
                response_time=response_time,
                timestamp=time.time(),
                hash=content_hash,
                depth=depth,
            )

        except requests.RequestException:
            self.failed.add(url)
            self.stats.failed_urls += 1
            return None
        except Exception as e:
            logger.debug("crawl error for %s: %s", url, e)
            self.failed.add(url)
            self.stats.failed_urls += 1
            return None

    def _should_crawl_url(self, url: str) -> bool:
        try:
            p = urlparse(url)
            if p.scheme not in ('http', 'https'):
                return False

            if not self.config['include_subdomains'] and p.netloc != self.domain:
                return False

            path = (p.path or '').lower()
            if any(path.endswith(ext) for ext in self.config['exclude_extensions']):
                return False

            if not self.config['include_query_params'] and p.query:
                return False

            return True
        except Exception:
            return False

    def _queue_new_urls(self, urls: List[str], current_depth: int) -> None:
        for u in urls:
            if u not in self.visited and u not in self.queued and len(self.queued) < self.config['max_pages']:
                self.url_queue.put((u, current_depth + 1))
                self.queued.add(u)

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        out: List[str] = []
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag.get('href')
            if not href:
                continue
            full = unquote(urljoin(base_url, href))
            if self._should_crawl_url(full):
                out.append(full)
                self.endpoints.add(full)
        return out

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
        forms_data: List[Dict[str, Any]] = []
        for form in soup.find_all('form'):
            action = urljoin(base_url, form.get('action', '') or '')
            method = (form.get('method', 'GET') or 'GET').upper()

            inputs: List[Dict[str, Any]] = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                inputs.append({
                    'name': inp.get('name', '') or '',
                    'type': inp.get('type', 'text') or 'text',
                    'value': inp.get('value', '') or '',
                })

            data = {'action': action, 'method': method, 'inputs': inputs}
            forms_data.append(data)
            self.forms.append(data)
        return forms_data

    def _extract_scripts(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        scripts: List[str] = []
        for s in soup.find_all('script', src=True):
            src = s.get('src')
            if not src:
                continue
            full = urljoin(base_url, src)
            scripts.append(full)
            self.scripts.add(full)
        return scripts

    def _extract_images(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        images: List[str] = []
        for img in soup.find_all('img', src=True):
            src = img.get('src')
            if not src:
                continue
            full = urljoin(base_url, src)
            images.append(full)
            self.images.add(full)
        return images

    def _extract_emails(self, text: str) -> None:
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
        self.emails.update(re.findall(email_pattern, text or ''))

    def _extract_phones(self, text: str) -> None:
        phone_pattern = r'\b(?:\+?\d{1,3}[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b'
        for p in re.findall(phone_pattern, text or ''):
            self.phones.add(f"({p[0]}) {p[1]}-{p[2]}")

    def _analyze_crawl_results(self) -> Dict[str, Any]:
        duration = max(0.000001, self.stats.end_time - self.stats.start_time)
        avg_resp = (
            sum(r.response_time for r in self.results) / max(1, len(self.results))
            if self.results
            else 0.0
        )

        return {
            'response_code_distribution': dict(self.response_codes),
            'content_type_distribution': dict(self.content_types),
            'crawl_duration': duration,
            'crawl_speed': len(self.results) / duration,
            'unique_domains': len({urlparse(u).netloc for u in self.endpoints if urlparse(u).netloc}),
            'average_response_time': avg_resp,
            'duplicate_content_ratio': 0.0 if not self.results else 1 - (len(self.content_hashes) / len(self.results)),
        }


def crawl_website(
    target: str,
    max_depth: int = 3,
    max_pages: int = 500,
    verbose: bool = False,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Entry point for plascoy."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    base_config: Dict[str, Any] = {
        'max_depth': max_depth,
        'max_pages': max_pages,
    }
    if config:
        base_config.update(config)

    crawler = AdvancedWebCrawler(target, base_config)
    results = crawler.crawl()

    # Compact console summary
    stats = results['stats']
    analysis = results['analysis']
    print(f"\n{'='*60}")
    print(f"CRAWL RESULTS FOR: {target}")
    print(f"Duration: {analysis['crawl_duration']:.2f} seconds")
    print(f"Pages crawled: {stats['crawled_urls']}")
    print(f"Failed requests: {stats['failed_urls']}")
    print(f"Unique endpoints: {len(results['endpoints'])}")
    print(f"Forms found: {len(results['forms'])}")
    print(f"Scripts found: {len(results['scripts'])}")
    print(f"Images found: {len(results['images'])}")
    print(f"Emails found: {len(results['emails'])}")
    print(f"Phones found: {len(results['phones'])}")
    print(f"Average response time: {analysis['average_response_time']:.3f}s")
    print(f"Crawl speed: {analysis['crawl_speed']:.2f} pages/sec")
    print(f"{'='*60}\n")

    return results


__all__ = ['crawl_website']

