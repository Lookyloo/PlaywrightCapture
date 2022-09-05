#!/usr/bin/env python3

from collections import defaultdict
from typing import TypedDict, Dict, Optional, Set, List
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from w3lib.html import strip_html5_whitespace
from w3lib.url import canonicalize_url, safe_url_string

from .exceptions import UnknownPlaywrightDeviceType


class PlaywrightDevice(TypedDict):

    user_agent: str
    viewport: Dict[str, int]
    device_scale_factor: int
    is_mobile: bool
    has_touch: bool
    default_browser_type: str


def get_devices(in_testsuite: bool=False) -> Dict[str, Dict[str, Dict[str, PlaywrightDevice]]]:
    to_return: Dict[str, Dict[str, Dict[str, PlaywrightDevice]]] = {'desktop': defaultdict(dict), 'mobile': defaultdict(dict)}
    playwright = sync_playwright().start()
    devices: Dict[str, PlaywrightDevice] = playwright.devices
    playwright.stop()
    for device_name, settings in devices.items():
        splitted_name = device_name.split(' ')
        if splitted_name[0] == 'Desktop':
            # Desktop device
            if len(splitted_name) == 3:
                if splitted_name[2] != 'HiDPI':
                    if in_testsuite:
                        raise UnknownPlaywrightDeviceType(f'Unexpected device name: {device_name}')
                to_return['desktop']['HiDPI'][device_name] = settings
            elif len(splitted_name) == 2:
                to_return['desktop']['default'][device_name] = settings
            else:
                if in_testsuite:
                    raise UnknownPlaywrightDeviceType(f'Unexpected device name: {device_name}')
        else:
            # Mobile device
            if splitted_name[-1] == 'landscape':
                to_return['mobile']['landscape'][device_name] = settings
            else:
                to_return['mobile']['default'][device_name] = settings

    return to_return


def get_links_from_rendered_page(rendered_url: str, rendered_html: str, rendered_hostname_only: bool) -> List[str]:
    def _sanitize(maybe_url: str) -> Optional[str]:
        href = strip_html5_whitespace(maybe_url)
        href = safe_url_string(href)

        href = urljoin(rendered_url, href)

        href = canonicalize_url(href, keep_fragments=True)
        parsed = urlparse(href)
        if not parsed.netloc:
            return None
        return href

    urls: Set[str] = set()
    soup = BeautifulSoup(rendered_html, "lxml")

    rendered_hostname = urlparse(rendered_url).hostname
    # The simple ones: the links.
    for a_tag in soup.find_all(["a", "area"]):
        href = a_tag.attrs.get("href")
        if not href:
            continue
        if href := _sanitize(href):
            if not rendered_hostname_only:
                urls.add(href)
            elif rendered_hostname and urlparse(href).hostname == rendered_hostname:
                urls.add(href)

    return sorted(urls)
