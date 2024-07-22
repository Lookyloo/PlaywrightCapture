#!/usr/bin/env python3

from __future__ import annotations

import asyncio
import binascii
import json
import logging
import os
import random
import re
import sys
import time

from base64 import b64decode
from dataclasses import dataclass
from io import BytesIO
from logging import LoggerAdapter, Logger
from tempfile import NamedTemporaryFile
from typing import Any, TypedDict, Literal, TYPE_CHECKING, MutableMapping, Generator
from urllib.parse import urlparse, unquote, urljoin
from zipfile import ZipFile

import aiohttp
import dateparser
import urllib3

from aiohttp_socks import ProxyConnector  # type: ignore[import-untyped]
from bs4 import BeautifulSoup
from charset_normalizer import from_bytes
from playwright._impl._errors import TargetClosedError
from playwright.async_api import async_playwright, Frame, Error, Page, Download, Request
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright_stealth import stealth_async, StealthConfig  # type: ignore[import-untyped]
from puremagic import PureError, from_string
from w3lib.html import strip_html5_whitespace
from w3lib.url import canonicalize_url, safe_url_string

from .exceptions import UnknownPlaywrightBrowser, UnknownPlaywrightDevice, InvalidPlaywrightParameter

if sys.version_info < (3, 9):
    from pytz import all_timezones_set
else:
    from zoneinfo import available_timezones
    all_timezones_set = available_timezones()

if sys.version_info < (3, 11):
    from async_timeout import timeout
else:
    from asyncio import timeout

if TYPE_CHECKING:
    from playwright._impl._api_structures import (SetCookieParam, Geolocation,
                                                  HttpCredentials, Headers,
                                                  ViewportSize, Cookie,
                                                  ProxySettings)
    BROWSER = Literal['chromium', 'firefox', 'webkit']

try:
    import pydub  # type: ignore[import-untyped]
    from speech_recognition import Recognizer, AudioFile  # type: ignore[import-untyped]
    CAN_SOLVE_CAPTCHA = True
except ImportError:
    CAN_SOLVE_CAPTCHA = False

# Do not show TLS warnings from urllib3 when fetching a favicon
urllib3.disable_warnings()


class CaptureResponse(TypedDict, total=False):

    last_redirected_url: str
    har: dict[str, Any] | None
    cookies: list[Cookie] | None
    error: str | None
    error_name: str | None
    html: str | None
    png: bytes | None
    downloaded_filename: str | None
    downloaded_file: bytes | None
    children: list[CaptureResponse] | None

    # One day, playwright will support getting the favicon from the capture itself
    # favicon: Optional[bytes]
    # in the meantime, we need a workaround: https://github.com/Lookyloo/PlaywrightCapture/issues/45
    potential_favicons: set[bytes] | None


class PlaywrightCaptureLogAdapter(LoggerAdapter):  # type: ignore[type-arg]
    """
    Prepend log entry with the UUID of the capture
    """
    def process(self, msg: str, kwargs: MutableMapping[str, Any]) -> tuple[str, MutableMapping[str, Any]]:
        if self.extra:
            return '[{}] {}'.format(self.extra['uuid'], msg), kwargs
        return msg, kwargs


@dataclass
class PCStealthConfig(StealthConfig):  # type: ignore[misc]

    @property
    def enabled_scripts(self) -> Generator[str, None, None]:
        self.webdriver = True
        self.webgl_vendor = True
        self.chrome_app = True
        self.chrome_csi = True
        self.chrome_load_times = True
        self.chrome_runtime = True
        self.iframe_content_window = True
        self.media_codecs = True
        self.navigator_hardware_concurrency = 4
        self.navigator_languages = False  # Causes issue
        self.navigator_permissions = True
        self.navigator_platform = True
        self.navigator_plugins = True
        self.navigator_user_agent = False  # Causes issues
        self.navigator_vendor = False  # Causes issues
        self.outerdimensions = True
        self.hairline = True
        yield from super().enabled_scripts


class Capture():

    _browsers: list[BROWSER] = ['chromium', 'firefox', 'webkit']
    _default_viewport: ViewportSize = {'width': 1920, 'height': 1080}
    _default_timeout: int = 90  # set to 90s by default
    _minimal_timeout: int = 15  # set to 15s - It makes little sense to attempt a capture below that limit.

    _requests: dict[str, bytes] = {}

    def __init__(self, browser: BROWSER | None=None, device_name: str | None=None,
                 proxy: str | dict[str, str] | None=None,
                 general_timeout_in_sec: int | None = None, loglevel: str | int='INFO',
                 uuid: str | None=None):
        """Captures a page with Playwright.

        :param browser: The browser to use for the capture.
        :param device_name: The pre-defined device to use for the capture (from playwright).)
        :param proxy: The external proxy to use for the capture.
        :param general_timeout_in_sec: The general timeout for the capture, including children.
        :param loglevel: Python loglevel
        :param uuid: The UUID of the capture.
        """
        master_logger = logging.getLogger('playwrightcapture')
        master_logger.setLevel(loglevel)
        self.logger: Logger | PlaywrightCaptureLogAdapter
        if uuid is not None:
            self.logger = PlaywrightCaptureLogAdapter(master_logger, {'uuid': uuid})
        else:
            self.logger = master_logger
        self.browser_name: BROWSER = browser if browser else 'chromium'

        if general_timeout_in_sec is None:
            self._capture_timeout = self._default_timeout
        else:
            self._capture_timeout = general_timeout_in_sec
            if self._capture_timeout < self._minimal_timeout:
                self.logger.warning(f'Timeout given: {general_timeout_in_sec}s. Ignoring that as it makes little sense to attempt to capture a page in less than {self._minimal_timeout}s.')
                self._capture_timeout = self._minimal_timeout

        self.device_name: str | None = device_name
        self.proxy: ProxySettings = {}
        if proxy:
            if isinstance(proxy, str):
                self.proxy = {'server': proxy}
            elif isinstance(proxy, dict):
                self.proxy = {'server': proxy['server'], 'bypass': proxy.get('bypass', ''),
                              'username': proxy.get('username', ''),
                              'password': proxy.get('password', '')}
            elif isinstance(proxy, int):
                # This is clearly a mistake, just ignoring it
                self.logger.warning('Proxy is an integer, this is a mistake, ignoring it.')
            else:
                raise InvalidPlaywrightParameter(f'Invalid proxy parameter: "{proxy}" ({type(proxy)})')

        self.should_retry: bool = False
        self.__network_not_idle: int = 2  # makes sure we do not wait for network idle the max amount of time the capture is allowed to take
        self._cookies: list[SetCookieParam] = []
        self._http_credentials: HttpCredentials = {}
        self._geolocation: Geolocation = {}
        self._headers: Headers = {}
        self._viewport: ViewportSize | None = None
        self._user_agent: str = ''
        self._timezone_id: str = ''
        self._locale: str = ''
        self._color_scheme: Literal['dark', 'light', 'no-preference', 'null'] | None = None

    async def __aenter__(self) -> Capture:
        '''Launch the browser'''
        self._temp_harfile = NamedTemporaryFile(delete=False)

        self.playwright = await async_playwright().start()

        if self.device_name:
            if self.device_name in self.playwright.devices:
                self.browser_name = self.playwright.devices[self.device_name]['default_browser_type']
            else:
                raise UnknownPlaywrightDevice(f'Unknown device name {self.device_name}, must be in {", ".join(self.playwright.devices.keys())}')
        elif self.browser_name not in self._browsers:
            raise UnknownPlaywrightBrowser(f'Incorrect browser name {self.browser_name}, must be in {", ".join(self._browsers)}')

        self.browser = await self.playwright[self.browser_name].launch(
            proxy=self.proxy if self.proxy else None,
            # headless=False
        )

        # Set of URLs that were captured in that context
        self._already_captured: set[str] = set()

        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if hasattr(self, '_temp_harfile'):
            os.unlink(self._temp_harfile.name)

        try:
            await self.browser.close()
        except Exception as e:
            # We may land in a situation where the capture was forcefully closed and the browser is already closed
            self.logger.info(f'Unable to close browser: {e}')
        try:
            await self.playwright.stop()
        except Exception as e:
            # this should't happen, but just in case it does...
            self.logger.info(f'Unable to stop playwright: {e}')

    @property
    def locale(self) -> str:
        return self._locale

    @locale.setter
    def locale(self, locale: str | None) -> None:
        if locale:
            self._locale = locale

    @property
    def timezone_id(self) -> str:
        return self._timezone_id

    @timezone_id.setter
    def timezone_id(self, timezone_id: str | None) -> None:
        if not timezone_id:
            return
        if timezone_id in all_timezones_set:
            self._timezone_id = timezone_id
        else:
            raise InvalidPlaywrightParameter(f'The Timezone ID provided ({timezone_id}) is invalid.')

    @property
    def http_credentials(self) -> HttpCredentials:
        return self._http_credentials

    @http_credentials.setter
    def http_credentials(self, credentials: dict[str, str] | None) -> None:
        if not credentials:
            return
        if 'username' in credentials and 'password' in credentials:
            self._http_credentials = {'username': credentials['username'],
                                      'password': credentials['password']}
            if 'origin' in credentials:
                self._http_credentials['origin'] = credentials['origin']
        else:
            raise InvalidPlaywrightParameter(f'At least a username and a password are required in the credentials: {credentials}')

    def set_http_credentials(self, username: str, password: str, origin: str | None=None) -> None:
        self._http_credentials = {'username': username, 'password': password, 'origin': origin}

    @property
    def geolocation(self) -> Geolocation:
        return self._geolocation

    @geolocation.setter
    def geolocation(self, geolocation: dict[str, str | int | float] | None) -> None:
        if not geolocation:
            return
        if 'latitude' in geolocation and 'longitude' in geolocation:
            self._geolocation = {'latitude': float(geolocation['latitude']),
                                 'longitude': float(geolocation['longitude'])}
            if 'accuracy' in geolocation:
                self._geolocation['accuracy'] = float(geolocation['accuracy'])
        else:
            raise InvalidPlaywrightParameter(f'At least a latitude and a longitude are required in the geolocation: {geolocation}')

    @property
    def cookies(self) -> list[SetCookieParam]:
        return self._cookies

    @cookies.setter
    def cookies(self, cookies: list[dict[str, Any]] | None) -> None:
        '''Cookies to send along to the initial request.
        :param cookies: The cookies, in this format: https://playwright.dev/python/docs/api/class-browsercontext#browser-context-add-cookies
        '''
        if not cookies:
            return
        for cookie in cookies:
            c: SetCookieParam = {
                'name': cookie['name'],
                'value': cookie['value'],
            }
            # self.context.add_cookies doesn't accept None, we cannot just use get
            if 'url' in cookie:
                c['url'] = cookie['url']
            if 'domain' in cookie:
                c['domain'] = cookie['domain']
            if 'path' in cookie:
                c['path'] = cookie['path']
            if 'expires' in cookie:
                if isinstance(cookie['expires'], str):
                    try:
                        _expire = dateparser.parse(cookie['expires'])
                        if _expire:
                            c['expires'] = _expire.timestamp()
                    except Exception as e:
                        self.logger.warning(f'Invalid expiring value: {cookie["expires"]} - {e}')
                        pass
                elif isinstance(cookie['expires'], (float, int)):
                    c['expires'] = cookie['expires']
                else:
                    self.logger.warning(f'Invalid type for the expiring value: {cookie["expires"]} - {type(cookie["expires"])}')
            if 'httpOnly' in cookie:
                c['httpOnly'] = bool(cookie['httpOnly'])
            if 'secure' in cookie:
                c['secure'] = bool(cookie['secure'])
            if 'sameSite' in cookie and cookie['sameSite'] in ["Lax", "None", "Strict"]:
                c['sameSite'] = cookie['sameSite']

            if 'url' in c or ('domain' in c and 'path' in c):
                self._cookies.append(c)
            else:
                url = cookie.get("url")
                domain = cookie.get("domain")
                path = cookie.get("path")
                self.logger.warning(f'The cookie must have a URL ({url}) or a domain ({domain}) and a path ({path})')

    @property
    def headers(self) -> Headers:
        return self._headers

    @headers.setter
    def headers(self, headers: dict[str, str] | None) -> None:
        if not headers:
            return
        if isinstance(headers, dict):
            # Check if they are valid
            new_headers = {name.strip(): value.strip() for name, value in headers.items() if isinstance(name, str) and isinstance(value, str) and name.strip() and value.strip()}
            if new_headers != headers:
                self.logger.warning(f'Headers contains invalid values:\n{json.dumps(headers, indent=2)}')
        else:
            # This shouldn't happen, but we also cannot ensure the calls leading to this are following the specs,
            # and playwright dislikes invalid HTTP headers so we rather drop them.
            self.logger.info(f'Wrong type of headers ({type(headers)}): {headers}')
            return

        # Validate the new headers, only a subset of characters are accepted
        # https://developers.cloudflare.com/rules/transform/request-header-modification/reference/header-format
        for name, value in new_headers.items():
            if re.match(r'^[\w-]+$', name) is None:
                self.logger.warning(f'Invalid HTTP Header name: {name}')
                continue
            if not value.isprintable():
                self.logger.warning(f'Invalid HTTP Header value: {value}')
                continue
            self._headers[name] = value

    @property
    def viewport(self) -> ViewportSize | None:
        return self._viewport

    @viewport.setter
    def viewport(self, viewport: dict[str, str | int] | None) -> None:
        if not viewport:
            return
        if 'width' in viewport and 'height' in viewport:
            self._viewport = {'width': int(viewport['width']), 'height': int(viewport['height'])}
        else:
            raise InvalidPlaywrightParameter(f'A viewport must have a height and a width - {viewport}')

    @property
    def user_agent(self) -> str:
        return self._user_agent

    @user_agent.setter
    def user_agent(self, user_agent: str | None) -> None:
        if user_agent is not None:
            self._user_agent = user_agent

    @property
    def color_scheme(self) -> Literal['dark', 'light', 'no-preference', 'null'] | None:
        return self._color_scheme

    @color_scheme.setter
    def color_scheme(self, color_scheme: Literal['dark', 'light', 'no-preference', 'null'] | None) -> None:
        if not color_scheme:
            return
        schemes = ['light', 'dark', 'no-preference', 'null']
        if color_scheme in schemes:
            self._color_scheme = color_scheme
        else:
            raise InvalidPlaywrightParameter(f'Invalid color scheme ({color_scheme}), must be in {", ".join(schemes)}.')

    async def initialize_context(self) -> None:
        device_context_settings = {}
        if self.device_name:
            device_context_settings = self.playwright.devices[self.device_name]
            # We need to make sure the device_context_settings dict doesn't contains
            # keys that are set by default in the context creation
            if context_ua := device_context_settings.pop('user_agent', None):
                ua = self.user_agent if self.user_agent else context_ua
            if context_vp := device_context_settings.pop('viewport', self._default_viewport):
                # Always true, but we also always want to pop it.
                vp = self.viewport if self.viewport else context_vp
        else:
            ua = self.user_agent
            vp = self.viewport

        self.context = await self.browser.new_context(
            record_har_path=self._temp_harfile.name,
            ignore_https_errors=True,
            bypass_csp=True,
            http_credentials=self.http_credentials if self.http_credentials else None,
            user_agent=ua,
            locale=self.locale if self.locale else None,
            timezone_id=self.timezone_id if self.timezone_id else None,
            color_scheme=self.color_scheme if self.color_scheme else None,
            viewport=vp,
            # For debug only
            # record_video_dir='./videos/',
            **device_context_settings
        )
        self.context.set_default_timeout(self._capture_timeout * 1000)

        if self.cookies:
            try:
                await self.context.add_cookies(self.cookies)
            except Exception:
                self.logger.exception(f'Unable to set cookies: {self.cookies}')

        if self.headers:
            try:
                await self.context.set_extra_http_headers(self.headers)
            except Exception:
                self.logger.exception(f'Unable to set HTTP Headers: {self.headers}')

        if self.geolocation:
            await self.context.set_geolocation(self.geolocation)

        # NOTE: Which perms are supported by which browsers varies
        # See https://github.com/microsoft/playwright/issues/16577
        chromium_permissions = [
            'geolocation',
            'midi',
            'midi-sysex',
            'notifications',
            'camera',
            'microphone',
            'background-sync',
            'ambient-light-sensor',
            'accelerometer',
            'gyroscope',
            'magnetometer',
            'accessibility-events',
            'clipboard-read',
            'clipboard-write',
            'payment-handler'
        ]

        firefox_permissions = ['geolocation', 'notifications']
        webkit_permissions = ['geolocation']

        if self.browser_name == 'webkit':
            await self.context.grant_permissions(webkit_permissions)
        elif self.browser_name == 'firefox':
            await self.context.grant_permissions(firefox_permissions)
        elif self.browser_name == 'chromium':
            await self.context.grant_permissions(chromium_permissions)

    async def __cloudflare_bypass_attempt(self, page: Page) -> None:
        # This method aims to bypass cloudflare checks, but it mostly doesn't work.
        max_tries = 5
        try:
            while max_tries > 0:
                # cf_locator = page.frame_locator("iframe[title=\"Widget containing a Cloudflare security challenge\"]").get_by_label("Verify you are human")
                cf_locator = page.frame_locator("iframe[title=\"Widget containing a Cloudflare security challenge\"]").get_by_role("checkbox")
                await self._safe_wait(page, 5)
                await cf_locator.click(force=True, position={"x": random.uniform(1, 32), "y": random.uniform(1, 32)})
                self.logger.info('Cloudflare widget visible.')
                await self._safe_wait(page, 5)
                await self._wait_for_random_timeout(page, 2)
                spinner = page.locator('#challenge-spinner')
                while True:
                    if await spinner.is_visible():
                        self.logger.info('Cloudflare spinner visible.')
                        await self._wait_for_random_timeout(page, 2)
                    else:
                        self.logger.info('Cloudflare spinner not visible.')
                        break
                max_tries -= 1
                await self._wait_for_random_timeout(page, 5)
        except Exception as e:
            self.logger.info(f'Unable to find Cloudflare locator: {e}')

    async def __dialog_didomi_clickthrough(self, page: Page) -> None:
        # Setup the handler.
        async def handler() -> None:
            self.logger.debug('Didomi dialog found, clicking through.')
            if await page.locator("#didomi-notice-agree-button").is_visible():
                await page.locator("#didomi-notice-agree-button").click(timeout=30000)

        await page.add_locator_handler(page.locator(".didomi-popup-view").last, handler, times=1, no_wait_after=True)
        self.logger.info('Didomi handler added')

    async def __dialog_onetrust_clickthrough(self, page: Page) -> None:
        async def handler() -> None:
            if await page.locator("#onetrust-accept-btn-handler").is_visible():
                await page.locator("#onetrust-accept-btn-handler").click(timeout=2000)

        await page.add_locator_handler(
            page.locator('#onetrust-banner-sdk').last,
            handler,
            times=1, no_wait_after=True
        )
        self.logger.info('OT handler added')

    async def __dialog_hubspot_clickthrough(self, page: Page) -> None:
        async def handler() -> None:
            if await page.locator("#hs-eu-confirmation-button").is_visible():
                await page.locator("#hs-eu-confirmation-button").click(timeout=2000)

        await page.add_locator_handler(
            page.locator('#hs-eu-cookie-confirmation').last,
            handler,
            times=1, no_wait_after=True
        )
        self.logger.info('HS handler added')

    async def __dialog_cookiebot_clickthrough(self, page: Page) -> None:
        async def handler() -> None:
            if await page.locator("#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll").is_visible():
                await page.locator("#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll").click(timeout=2000)

        await page.add_locator_handler(
            page.locator('#CybotCookiebotDialogBody'),
            handler,
            times=1, no_wait_after=True
        )
        self.logger.info('Cookiebot handler added')

    async def __dialog_alert_dialog_clickthrough(self, page: Page) -> None:
        async def handler() -> None:
            if await page.frame_locator("iframe[title=\"Consent window\"]").locator("button.button__acceptAll").is_visible():
                self.logger.info('Consent window found, clicking through.')
                await page.frame_locator("iframe[title=\"Consent window\"]").locator("button.button__acceptAll").click(timeout=2000)
            elif await page.locator('#onetrust-button-group').locator("#onetrust-accept-btn-handler").is_visible():
                await page.locator('#onetrust-button-group').locator("#onetrust-accept-btn-handler").click(timeout=1000)
            else:
                self.logger.info('Consent window found (alert dialog), but no button to click through.')

        await page.add_locator_handler(
            page.get_by_role("alertdialog").last,
            handler,
            times=1, no_wait_after=True
        )
        self.logger.info('alert dialog handler added')

    async def __dialog_clickthrough(self, page: Page) -> None:
        async def handler() -> None:
            if await page.locator(".qc-cmp2-summary-buttons").locator("button").first.is_visible():
                self.logger.info('Consent window found, clicking through.')
                await page.locator(".qc-cmp2-summary-buttons").locator("button").locator("nth=-1").click(timeout=2000)
            elif await page.locator("#popin_tc_privacy").locator("#popin_tc_privacy_button_2").is_visible():
                self.logger.info('Consent window found, clicking through.')
                await page.locator("#popin_tc_privacy").locator("#popin_tc_privacy_button_2").click(timeout=2000)
            elif await page.get_by_test_id("uc-accept-all-button").is_visible():
                self.logger.info('Consent window found, clicking through.')
                await page.get_by_test_id("uc-accept-all-button").click(timeout=2000)
            else:
                self.logger.info('Consent window found (dialog), but no button to click through.')
        await page.add_locator_handler(
            page.get_by_role("dialog").last,
            handler,
            times=1, no_wait_after=True
        )
        self.logger.info('dialog handler added')

    async def __dialog_complianz_clickthrough(self, page: Page) -> None:
        async def handler() -> None:
            if await page.locator('.cmplz-show').first.locator("button.cmplz-accept").is_visible():
                await page.locator('.cmplz-show').first.locator("button.cmplz-accept").click(timeout=2000)

        await page.add_locator_handler(
            page.locator('.cmplz-show').first,
            handler,
            times=1, no_wait_after=True
        )
        self.logger.info('Complianz handler added')

    async def __dialog_yahoo_clickthrough(self, page: Page) -> None:
        async def handler() -> None:
            if await page.locator('.con-wizard').locator("button.accept-all").is_visible():
                await page.locator('.con-wizard').locator("button.accept-all").click(timeout=2000)

        await page.add_locator_handler(
            page.locator('.con-wizard'),
            handler,
            times=1, no_wait_after=True
        )
        self.logger.info('Yahoo handler added')

    async def __dialog_ppms_clickthrough(self, page: Page) -> None:
        async def handler() -> None:
            if await page.locator('.ppms_cm_popup_overlay').locator("button.ppms_cm_agree-to-all").is_visible():
                await page.locator('.ppms_cm_popup_overlay').locator("button.ppms_cm_agree-to-all").click(timeout=2000)

        await page.add_locator_handler(
            page.locator('#ppms_cm_popup_overlay'),
            handler,
            times=1, no_wait_after=True
        )
        self.logger.info('Piwik handler added')

    async def capture_page(self, url: str, *, max_depth_capture_time: int,
                           referer: str | None=None,
                           page: Page | None=None, depth: int=0,
                           rendered_hostname_only: bool=True,
                           with_favicon: bool=False,
                           allow_tracking: bool=False
                           ) -> CaptureResponse:

        to_return: CaptureResponse = {}
        got_favicons = False

        # We don't need to be super strict on the lock, as it simply triggers a wait for network idle before stoping the capture
        # but we still need it to be an integer in case we have more than one download triggered and one finished when the others haven't
        self.wait_for_download = 0

        # We may have multiple download triggered via JS
        multiple_downloads: list[tuple[str, bytes]] = []

        async def handle_download(download: Download) -> None:
            # This method is called when a download event is triggered from JS in a page that also renders
            try:
                self.wait_for_download += 1
                with NamedTemporaryFile() as tmp_f:
                    self.logger.info('Got a download triggered from JS.')
                    await download.save_as(tmp_f.name)
                    filename = download.suggested_filename
                    with open(tmp_f.name, "rb") as f:
                        file_content = f.read()
                    multiple_downloads.append((filename, file_content))
                    self.logger.info('Done with download.')
            except Exception as e:
                if download.page.is_closed():
                    # Page is closed, skip logging.
                    pass
                else:
                    self.logger.warning(f'Unable to finish download triggered from JS: {e}')
            finally:
                self.wait_for_download -= 1

        async def store_request(request: Request) -> None:
            # This method is called on each request, to store the body (if it is an image) in a dict indexed by URL
            if got_favicons or request.resource_type != 'image':
                return
            try:
                if response := await request.response():
                    if got_favicons:
                        return
                    if request.resource_type == 'image' and response.ok:
                        try:
                            if body := await response.body():
                                try:
                                    mimetype = from_string(body, mime=True)
                                    if mimetype.startswith('image'):
                                        self._requests[request.url] = body
                                except PureError:
                                    # unable to identify the mimetype
                                    pass
                        except Exception:
                            pass
            except Exception as e:
                self.logger.info(f'Unable to store request: {e}')

        if page is not None:
            capturing_sub = True
        else:
            capturing_sub = False
            try:
                page = await self.context.new_page()
                # await page.clock.install()
            except Error as e:
                self.logger.warning(f'The context is in a broken state: {e}')
                self.should_retry = True
                return to_return

            if allow_tracking:
                # Add authorization clickthroughs
                await self.__dialog_didomi_clickthrough(page)
                await self.__dialog_onetrust_clickthrough(page)
                await self.__dialog_hubspot_clickthrough(page)
                await self.__dialog_cookiebot_clickthrough(page)
                await self.__dialog_complianz_clickthrough(page)
                await self.__dialog_yahoo_clickthrough(page)
                await self.__dialog_ppms_clickthrough(page)
                await self.__dialog_alert_dialog_clickthrough(page)
                await self.__dialog_clickthrough(page)

            await stealth_async(page, PCStealthConfig())
            # await stealth_async(page)

            page.set_default_timeout((self._capture_timeout - 2) * 1000)
            # trigger a callback on each request to store it in a dict indexed by URL to get it back from the favicon fetcher
            page.on("requestfinished", store_request)
            page.on("dialog", lambda dialog: dialog.accept())

        try:
            # Parse the URL. If there is a fragment, we need to scroll to it manually
            parsed_url = urlparse(url, allow_fragments=True)

            try:
                await page.goto(url, wait_until='domcontentloaded', referer=referer if referer else '')
                page.on("download", handle_download)
            except Error as initial_error:
                self._update_exceptions(initial_error)
                # So this one is really annoying: chromium raises a net::ERR_ABORTED when it hits a download
                if initial_error.name in ['Download is starting', 'net::ERR_ABORTED']:
                    # page.goto failed, but it triggered a download event.
                    # Let's re-trigger it.
                    try:
                        async with page.expect_download() as download_info:
                            try:
                                await page.goto(url, referer=referer if referer else '')
                            except Exception:
                                pass
                            with NamedTemporaryFile() as tmp_f:
                                download = await download_info.value
                                await download.save_as(tmp_f.name)
                                filename = download.suggested_filename
                                with open(tmp_f.name, "rb") as f:
                                    file_content = f.read()
                                multiple_downloads.append((filename, file_content))
                    except PlaywrightTimeoutError:
                        self.logger.debug('No download has been triggered.')
                        raise initial_error
                    except Error as e:
                        try:
                            error_msg = download.failure()
                            if not error_msg:
                                raise e
                            to_return['error'] = f"Error while downloading: {error_msg}"
                            self.logger.info(to_return['error'])
                            self.should_retry = True
                        except Exception:
                            raise e
                else:
                    raise initial_error
            else:
                await self._wait_for_random_timeout(page, 5)  # Wait 5 sec after document loaded
                try:
                    await page.bring_to_front()
                    self.logger.debug('Page moved to front.')
                except Error as e:
                    self.logger.warning('Page in a broken state.')
                    raise e

                # page instrumentation
                await self._wait_for_random_timeout(page, 5)  # Wait 5 sec after document loaded
                self.logger.debug('Start instrumentation.')

                # check if we have anything on the page. If we don't, the page is not working properly.
                if await self._failsafe_get_content(page):
                    self.logger.debug('Got rendered content')

                    # ==== recaptcha
                    # Same technique as: https://github.com/NikolaiT/uncaptcha3
                    if CAN_SOLVE_CAPTCHA:
                        try:
                            if (await page.locator("//iframe[@title='reCAPTCHA']").first.is_visible(timeout=3000)
                                    and await page.locator("//iframe[@title='reCAPTCHA']").first.is_enabled(timeout=2000)):
                                self.logger.info('Found a captcha')
                                await self._recaptcha_solver(page)
                        except PlaywrightTimeoutError as e:
                            self.logger.info(f'Captcha on {url} is not ready: {e}')
                        except TargetClosedError as e:
                            self.logger.warning(f'Target closed while resolving captcha on {url}: {e}')
                        except Error as e:
                            self.logger.warning(f'Error while resolving captcha on {url}: {e}')
                        except Exception as e:
                            self.logger.exception(f'General error with captcha solving on {url}: {e}')
                    # ======
                    # NOTE: testing
                    # await self.__cloudflare_bypass_attempt(page)
                    self.logger.debug('Done with captcha.')

                    # move mouse
                    await page.mouse.move(x=random.uniform(300, 800), y=random.uniform(200, 500))
                    self.logger.debug('Moved mouse.')
                    await self._wait_for_random_timeout(page, 5)
                    self.logger.debug('Keep going after moving mouse.')

                    if allow_tracking:
                        await self._wait_for_random_timeout(page, 5)
                        # This event is required trigger the add_locator_handler
                        try:
                            if await page.locator("body").first.is_visible():
                                self.logger.debug('Got body.')
                                await page.locator("body").first.click(button="right",
                                                                       timeout=5000,
                                                                       delay=50)
                                self.logger.debug('Clicked on body.')
                        except Exception as e:
                            self.logger.warning(f'Could not find body: {e}')

                    if parsed_url.fragment:
                        # We got a fragment, make sure we go to it and scroll only a little bit.
                        fragment = unquote(parsed_url.fragment)
                        try:
                            await page.locator(f'id={fragment}').first.scroll_into_view_if_needed(timeout=3000)
                            await self._wait_for_random_timeout(page, 2)
                            async with timeout(5):
                                await page.mouse.wheel(delta_y=random.uniform(150, 300), delta_x=0)
                            self.logger.debug('Jumped to fragment.')
                        except PlaywrightTimeoutError as e:
                            self.logger.info(f'Unable to go to fragment "{fragment}" (timeout): {e}')
                        except TargetClosedError as e:
                            self.logger.warning(f'Target closed, unable to go to fragment "{fragment}": {e}')
                        except Error as e:
                            self.logger.exception(f'Unable to go to fragment "{fragment}": {e}')
                        except (asyncio.TimeoutError, TimeoutError):
                            self.logger.debug('Unable to scroll due to timeout')
                        except (asyncio.CancelledError):
                            self.logger.debug('Unable to scroll due to timeout, call canceled')
                    else:
                        # scroll more
                        try:
                            # NOTE using page.mouse.wheel causes the instrumentation to fail, sometimes.
                            #   2024-07-08: Also, it sometimes get stuck.
                            async with timeout(5):
                                await page.mouse.wheel(delta_y=random.uniform(1500, 3000), delta_x=0)
                            self.logger.debug('Scrolled down.')
                        except Error as e:
                            self.logger.debug(f'Unable to scroll: {e}')
                        except (TimeoutError, asyncio.TimeoutError):
                            self.logger.debug('Unable to scroll due to timeout')
                        except (asyncio.CancelledError):
                            self.logger.debug('Unable to scroll due to timeout, call canceled')

                    await self._wait_for_random_timeout(page, 3)
                    self.logger.debug('Keep going after moving on page.')

                    try:
                        await page.keyboard.press('PageUp')
                        self.logger.debug('PageUp on keyboard')
                        await self._wait_for_random_timeout(page, 3)
                        await page.keyboard.press('PageDown')
                        self.logger.debug('PageDown on keyboard')
                    except Error as e:
                        self.logger.debug(f'Unable to use keyboard: {e}')
                if self.wait_for_download > 0:
                    self.logger.info('Waiting for download to finish...')
                    await self._safe_wait(page, 20)

                if multiple_downloads:
                    if len(multiple_downloads) == 1:
                        to_return["downloaded_filename"] = multiple_downloads[0][0]
                        to_return["downloaded_file"] = multiple_downloads[0][1]
                    else:
                        # we have multiple downloads, making it a zip
                        mem_zip = BytesIO()
                        to_return["downloaded_filename"] = 'multiple_downloads.zip'
                        with ZipFile(mem_zip, 'w') as z:
                            for i, f_details in enumerate(multiple_downloads):
                                filename, file_content = f_details
                                z.writestr(f'{i}_{filename}', file_content)
                        to_return["downloaded_file"] = mem_zip.getvalue()

                # fast forward 30s
                # try:
                #    async with timeout(3):
                #        await page.clock.run_for("47")
                #        self.logger.debug('Moved time forward.')
                # except (TimeoutError, asyncio.TimeoutError):
                #    self.logger.warning('Unable to move time forward.')

                self.logger.debug('Done with instrumentation, waiting for network idle.')
                await self._wait_for_random_timeout(page, 5)  # Wait 5 sec after instrumentation
                await self._safe_wait(page)
                self.logger.debug('Done with instrumentation, done with waiting.')

                if content := await self._failsafe_get_content(page):
                    to_return['html'] = content

                if 'html' in to_return and to_return['html'] is not None and with_favicon:
                    to_return['potential_favicons'] = await self.get_favicons(page.url, to_return['html'])
                    got_favicons = True

                to_return['last_redirected_url'] = page.url
                to_return['png'] = await self._failsafe_get_screenshot(page)

                self._already_captured.add(url)
                if depth > 0 and to_return.get('html') and to_return['html']:
                    if child_urls := self._get_links_from_rendered_page(page.url, to_return['html'], rendered_hostname_only):
                        to_return['children'] = []
                        depth -= 1
                        total_urls = len(child_urls)
                        max_capture_time = max(int(max_depth_capture_time / total_urls), self._minimal_timeout)
                        max_captures = int(max_depth_capture_time / max_capture_time)
                        if max_captures < total_urls:
                            self.logger.warning(f'Attempting to capture URLs from {page.url} but there are too many ({total_urls}) to capture in too little time. Only capturing the first {max_captures} URLs in the page.')
                            if max_captures <= 0:
                                # We don't really have time for even one capture, but let's try anyway.
                                child_urls = child_urls[:1]
                            else:
                                child_urls = child_urls[:max_captures]
                        self.logger.info(f'Capturing children, {max_captures} URLs')
                        consecutive_errors = 0
                        for index, url in enumerate(child_urls):
                            self.logger.info(f'Capture child {url} - Timeout: {max_capture_time}s')
                            start_time = time.time()
                            if page.is_closed():
                                self.logger.info('Page is closed, unable to capture children.')
                                break
                            try:
                                async with timeout(max_capture_time + 1):  # just adding a bit of padding so playwright has the chance to raise the exception first
                                    child_capture = await self.capture_page(
                                        url=url, referer=page.url,
                                        page=page, depth=depth,
                                        rendered_hostname_only=rendered_hostname_only,
                                        max_depth_capture_time=max_capture_time)
                                    to_return['children'].append(child_capture)  # type: ignore[union-attr]
                            except (TimeoutError, asyncio.TimeoutError):
                                self.logger.info(f'Timeout error, took more than {max_capture_time}s. Unable to capture {url}.')
                                consecutive_errors += 1
                            except Exception as e:
                                self.logger.warning(f'Error while capturing child "{url}": {e}. {len(child_urls) - index - 1} more to go.')
                                consecutive_errors += 1
                            else:
                                consecutive_errors = 0
                                runtime = int(time.time() - start_time)
                                self.logger.info(f'Successfully captured child URL: {url} in {runtime}s. {len(child_urls) - index - 1} to go.')

                            if consecutive_errors >= 5:
                                # if we have more than 5 consecutive errors, the capture is most probably broken, breaking.
                                self.logger.warning('Got more than 5 consecutive errors while capturing children, breaking.')
                                to_return['error'] = "Got more than 5 consecutive errors while capturing children"
                                self.should_retry = True
                                break

                            try:
                                await page.go_back()
                            except PlaywrightTimeoutError:
                                self.logger.info('Go back timed out, it is probably not a big deal.')
                            except Exception as e:
                                self.logger.info(f'Unable to go back: {e}.')

        except PlaywrightTimeoutError as e:
            to_return['error'] = f"The capture took too long - {e.message}"
            self.should_retry = True
        except (asyncio.TimeoutError, TimeoutError):
            to_return['error'] = "Something in the capture took too long"
            self.should_retry = True
        except TargetClosedError as e:
            to_return['error'] = f"The target was closed - {e}"
            self.should_retry = True
        except Error as e:
            self._update_exceptions(e)
            to_return['error'] = e.message
            to_return['error_name'] = e.name
            # TODO: check e.message and figure out if it is worth retrying or not.
            # NOTE: e.name is generally (always?) "Error"
            if self._exception_is_network_error(e):
                # Expected errors
                self.logger.info(f'Unable to process {url}: {e.name}')
                if e.name == 'net::ERR_CONNECTION_RESET':
                    self.should_retry = True
            elif e.name in ['NS_BINDING_CANCELLED_OLD_LOAD',
                            'NS_BINDING_ABORTED',
                            'NS_ERROR_PARSED_DATA_CACHED',
                            'NS_ERROR_DOCUMENT_NOT_CACHED']:
                # this one sounds like something we can retry...
                self.logger.info(f'Issue with {url} (retrying): {e.message}')
                self.should_retry = True
            elif e.name in ['Download is starting',
                            'Connection closed',
                            'Connection terminated unexpectedly',
                            'Navigation interrupted by another one',
                            'Navigation failed because page was closed!',
                            'Target page, context or browser has been closed',
                            'Peer failed to perform TLS handshake: A packet with illegal or unsupported version was received.',
                            'Peer failed to perform TLS handshake: The TLS connection was non-properly terminated.',
                            'Peer failed to perform TLS handshake: Error sending data: Connection reset by peer',
                            'Peer failed to perform TLS handshake: Error receiving data: Connection reset by peer',
                            'Peer sent fatal TLS alert: Handshake failed',
                            'Peer sent fatal TLS alert: Internal error',
                            'Peer sent fatal TLS alert: The server name sent was not recognized',
                            'Load cannot follow more than 20 redirections',
                            'Page crashed',
                            'Error receiving data: Connection reset by peer',
                            'Internal SOCKSv5 proxy server error.',
                            'Host unreachable through SOCKSv5 server.',
                            'HTTP/2 Error: NO_ERROR',
                            'HTTP/2 Error: PROTOCOL_ERROR']:
                # Other errors, let's give it another shot
                self.logger.info(f'Issue with {url} (retrying): {e.message}')
                self.should_retry = True
            elif e.name in ['Target page, context or browser has been closed']:
                # The browser barfed, let's try again
                self.logger.info(f'Browser barfed on {url} (retrying): {e.message}')
                self.should_retry = True
            elif e.name in ['net::ERR_INVALID_AUTH_CREDENTIALS',
                            'net::ERR_BAD_SSL_CLIENT_AUTH_CERT',
                            'net::ERR_CERT_DATE_INVALID',
                            'net::ERR_UNEXPECTED_PROXY_AUTH',
                            'net::ERR_UNSAFE_PORT']:
                # No need to retry, the credentials/certs are wrong/missing.
                pass
            elif e.name and any([msg in e.name for msg in ['is interrupted by another navigation to', 'Page.bringToFront']]):
                self.should_retry = True
            elif e.name and any([msg in e.name for msg in ['Error resolving', 'Could not connect to']]):
                pass
            else:
                # Unexpected ones
                self.logger.exception(f'Something went poorly with {url}: "{e.name}" - {e.message}')
        except Exception as e:
            # we may get a non-playwright exception to.
            # The ones we try to handle here should be treated as if they were.
            to_return['error'] = str(e)
            if to_return['error'] in ['Connection closed while reading from the driver']:
                self.logger.info(f'Issue with {url} (retrying): {e}')
                self.should_retry = True
            else:
                raise e
        finally:
            self.logger.debug('Finishing up capture.')
            if not capturing_sub:
                try:
                    to_return['cookies'] = await self.context.cookies()
                    self.logger.debug('Done with cookies.')
                except Exception as e:
                    if 'error' not in to_return:
                        to_return['error'] = f'Unable to get the cookies: {e}'
                # frames_tree = self.make_frame_tree(page.main_frame)
                try:
                    page.remove_listener("requestfinished", store_request)
                    await page.close()
                    await self.context.close()  # context needs to be closed to generate the HAR
                    self.logger.debug('Context closed.')
                    with open(self._temp_harfile.name) as _har:
                        to_return['har'] = json.load(_har)
                    self.logger.debug('Got HAR.')
                except Exception as e:
                    if 'error' not in to_return:
                        to_return['error'] = f'Unable to generate HAR file: {e}'
        self.logger.debug('Capture done')
        return to_return

    async def _failsafe_get_screenshot(self, page: Page) -> bytes:
        self.logger.debug("Capturing a screenshot of the full page.")
        try:
            return await page.screenshot(full_page=True, timeout=10000)
        except Error as e:
            self.logger.info(f"Capturing a screenshot of the full page failed, trying to scale it down: {e}")

        try:
            return await page.screenshot(full_page=True, scale="css", timeout=30000)
        except Error as e:
            self.logger.info(f"Capturing a screenshot of the full page failed, trying to get the current viewport only: {e}")

        try:
            return await page.screenshot(scale="css", animations='disabled', caret='initial', timeout=5000)
        except Error as e:
            self.logger.info(f"Unable to get any screenshot: {e}")
            raise e

    async def _safe_wait(self, page: Page, force_max_wait_in_sec: int | None=None) -> None:
        max_wait: float
        try:
            if force_max_wait_in_sec is not None:
                max_wait = force_max_wait_in_sec
            else:
                max_wait = self._capture_timeout / self.__network_not_idle
            self.logger.debug(f'Waiting for network idle, max wait: {max_wait}s')
            max_wait *= 1000
            # If we don't have networkidle relatively quick, it's probably because we're playing a video.
            await page.wait_for_load_state('networkidle', timeout=max_wait)
        except PlaywrightTimeoutError:
            # Network never idle, keep going
            self.__network_not_idle += 1
            self.logger.debug(f'Timed out - Waiting for network idle, max wait: {max_wait}s')

    async def _failsafe_get_content(self, page: Page) -> str | None:
        ''' The page might be changing for all kind of reason (generally a JS timeout).
        In that case, we try a few times to get the HTML.'''
        tries = 3
        while tries:
            try:
                async with timeout(30):
                    return await page.content()
            except (Error, TimeoutError, asyncio.TimeoutError):
                self.logger.debug('Unable to get page content, trying again.')
                tries -= 1
                await self._wait_for_random_timeout(page, 1)
                await self._safe_wait(page, 5)
            except Exception as e:
                self.logger.warning(f'The Playwright Page is in a broken state: {e}.')
                break
        self.logger.warning('Unable to get page content.')
        return None

    def _get_links_from_rendered_page(self, rendered_url: str, rendered_html: str, rendered_hostname_only: bool) -> list[str]:
        def _sanitize(maybe_url: str) -> str | None:
            href = strip_html5_whitespace(maybe_url)
            href = safe_url_string(href)

            href = urljoin(rendered_url, href)

            href = canonicalize_url(href, keep_fragments=True)
            parsed = urlparse(href)
            if not parsed.netloc:
                return None
            return href

        urls: set[str] = set()
        soup = BeautifulSoup(rendered_html, "lxml")

        rendered_hostname = urlparse(rendered_url).hostname
        # The simple ones: the links.
        for a_tag in soup.find_all(["a", "area"]):
            href = a_tag.attrs.get("href")
            if not href:
                continue
            try:
                if href := _sanitize(href):
                    if not rendered_hostname_only:
                        urls.add(href)
                    elif rendered_hostname and urlparse(href).hostname == rendered_hostname:
                        urls.add(href)
            except ValueError as e:
                # unable to sanitize
                self.logger.warning(f'Unable to sanitize link: "{href}" - {e}')
        return sorted(urls - self._already_captured)

    async def _recaptcha_solver(self, page: Page) -> bool:
        try:
            framename = await page.locator("//iframe[@title='reCAPTCHA']").first.get_attribute("name")
            if not framename:
                return False
        except PlaywrightTimeoutError as e:
            self.logger.info(f'Captcha not ready: {e}')
            return False

        recaptcha_init_frame = page.frame(name=framename)

        if not recaptcha_init_frame:
            return False
        try:
            if await recaptcha_init_frame.get_by_role("checkbox", name="I'm not a robot").is_visible(timeout=5000):
                await recaptcha_init_frame.get_by_role("checkbox", name="I'm not a robot").click()
            else:
                self.logger.info('Checkbox not visible.')
                return False
        except PlaywrightTimeoutError as e:
            self.logger.info(f'Checkbox never ready: {e}')
            return False

        await self._wait_for_random_timeout(page, random.randint(3, 6))
        try:
            if await recaptcha_init_frame.locator("//span[@id='recaptcha-anchor']").first.is_checked(timeout=5000):  # solved already
                return True
        except PlaywrightTimeoutError:
            self.logger.info('Need to solve the captcha.')

        possible_urls = ['https://google.com/recaptcha/api2/bframe?', 'https://google.com/recaptcha/enterprise/bframe?']
        for url in possible_urls:
            try:
                recaptcha_testframename = await page.locator(f"//iframe[contains(@src,'{url}')]").first.get_attribute("name")
                if recaptcha_testframename:
                    self.logger.debug(f'Got iframe with {url}')
                    break
            except PlaywrightTimeoutError:
                self.logger.debug(f'Unable to get iframe with {url}')
                continue
        else:
            self.logger.info('Unable to find iframe')
            return False

        main_frame = page.frame(name=recaptcha_testframename)
        if not main_frame:
            return False

        # click on audio challenge button
        await main_frame.get_by_role("button", name="Get an audio challenge").click()

        connector = None
        if self.proxy and self.proxy.get('server'):
            connector = ProxyConnector.from_url(self.proxy['server'])

        async with aiohttp.ClientSession(connector=connector) as session:
            while True:
                try:
                    href = await main_frame.get_by_role("link", name="Alternatively, download audio as MP3").get_attribute("href")
                except Exception as e:
                    self.logger.warning(f'Google caught the browser as a robot, sorry: {e}')
                    return False
                if not href:
                    self.logger.warning('Unable to find download link for captcha.')
                    return False
                async with session.get(href, timeout=10, ssl=False) as response:
                    response.raise_for_status()
                    mp3_content = await response.read()
                with NamedTemporaryFile() as mp3_file, NamedTemporaryFile() as wav_file:
                    mp3_file.write(mp3_content)
                    pydub.AudioSegment.from_mp3(mp3_file.name).export(wav_file.name, format="wav")
                    recognizer = Recognizer()
                    recaptcha_audio = AudioFile(wav_file.name)
                    with recaptcha_audio as source:
                        audio = recognizer.record(source)
                    text = recognizer.recognize_google(audio)
                await main_frame.get_by_role("textbox", name="Enter what you hear").fill(text)
                await main_frame.get_by_role("button", name="Verify").click()
                await self._safe_wait(page, 5)
                await self._wait_for_random_timeout(page, random.randint(3, 6))
                try:
                    if await recaptcha_init_frame.locator("//span[@id='recaptcha-anchor']").first.is_checked(timeout=5000):
                        self.logger.info('Captcha solved successfully')
                        return True
                    elif await main_frame.get_by_role("textbox", name="Enter what you hear").is_editable(timeout=5000):
                        self.logger.info('Unable to find checkbox, needs to solve more captchas')
                except PlaywrightTimeoutError as e:
                    self.logger.info(f'Unexpected timeout: {e}')

    def _update_exceptions(self, exception: Error) -> None:
        if '\n' in exception.message:
            name, _ = exception.message.split('\n', maxsplit=1)
            if ' at ' in name:
                name, _ = name.split(' at ', maxsplit=1)
            elif '; ' in name:
                name, _ = name.split('; ', maxsplit=1)
            # This is kinda dirty.

            # The format changed in Playwright 1.43.0, the name of the method that failed is set before the exception itself.
            if ': ' in name:
                _, name = name.split(': ', maxsplit=1)
            exception._name = name.strip()
        else:
            # The format changed in Playwright 1.43.0, the name of the method that failed is set before the exception itself.
            if ': ' in exception.message:
                _, name = exception.message.split(': ', maxsplit=1)
            exception._name = name.strip()

    def _exception_is_network_error(self, exception: Error) -> bool:
        if exception.name in [
                'NS_ERROR_ABORT',
                'NS_ERROR_CONNECTION_REFUSED',
                'NS_ERROR_NET_INTERRUPT',
                'NS_ERROR_NET_PARTIAL_TRANSFER',
                'NS_ERROR_NET_RESET',
                'NS_ERROR_NET_TIMEOUT',
                'NS_ERROR_REDIRECT_LOOP',
                'NS_ERROR_UNEXPECTED',
                'NS_ERROR_UNKNOWN_HOST',
                'NS_ERROR_UNKNOWN_PROTOCOL',
                'net::ERR_ABORTED',
                'net::ERR_ADDRESS_UNREACHABLE',
                'net::ERR_CONNECTION_CLOSED',
                'net::ERR_CONNECTION_REFUSED',
                'net::ERR_CONNECTION_RESET',
                'net::ERR_CONNECTION_TIMED_OUT',
                'net::ERR_EMPTY_RESPONSE',
                'net::ERR_HTTP_RESPONSE_CODE_FAILURE',
                'net::ERR_HTTP2_PROTOCOL_ERROR',
                'net::ERR_INVALID_REDIRECT',
                'net::ERR_INVALID_RESPONSE',
                'net::ERR_NAME_NOT_RESOLVED',
                'net::ERR_NETWORK_ACCESS_DENIED',
                'net::ERR_QUIC_PROTOCOL_ERROR',
                'net::ERR_RESPONSE_HEADERS_TRUNCATED',
                'net::ERR_SOCKET_NOT_CONNECTED',
                'net::ERR_SOCKS_CONNECTION_FAILED',
                'net::ERR_SSL_KEY_USAGE_INCOMPATIBLE',
                'net::ERR_SSL_PROTOCOL_ERROR',
                'net::ERR_SSL_UNRECOGNIZED_NAME_ALERT',
                'net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH',
                'net::ERR_TIMED_OUT',
                'net::ERR_TOO_MANY_REDIRECTS',
                'SSL_ERROR_UNKNOWN',
        ]:
            return True
        return False

    async def _wait_for_random_timeout(self, page: Page, timeout: int) -> None:
        '''Instead of waiting for the exact same time, we wait +-500ms around the given time. The time is fiven in seconds for simplicity's sake.'''
        if timeout > 1000:
            self.logger.warning(f'The waiting time is too long {timeout}, we expect seconds, not miliseconds.')
            timeout = int(timeout / 1000)
        _wait_time = random.randrange(max(timeout * 1000 - 500, 500), max(timeout * 1000 + 500, 1000))
        await page.wait_for_timeout(_wait_time)

    def make_frame_tree(self, frame: Frame) -> dict[str, list[dict[str, Any]]]:
        # TODO: not used at this time, need to figure out how do use that.
        to_return: dict[str, list[dict[str, Any]]] = {frame._impl_obj._guid: []}
        for child in frame.child_frames:
            to_return[frame._impl_obj._guid].append(self.make_frame_tree(child))
        return to_return

    # #### Manual favicon extractor, will be removed if/when Playwright supports getting the favicon.

    # Method copied from HAR2Tree
    def __parse_data_uri(self, uri: str) -> tuple[str, str, bytes] | None:
        if not uri.startswith('data:'):
            return None
        uri = uri[5:]
        if ';base64' in uri:
            mime, b64data = uri.split(';base64', 1)
            if not b64data or b64data[0] != ',':
                self.logger.warning(f'Unable to decode {b64data}: empty or missing leading ",".')
                return None
            b64data = b64data[1:].strip()
            if not re.fullmatch('[A-Za-z0-9+/]*={0,2}', b64data):
                self.logger.warning(f'Unable to decode {b64data}: invalid characters.')
                return None
            if len(b64data) % 4:
                # Note: Too many = isn't a problem.
                b64data += "==="
            try:
                data = b64decode(b64data)
            except binascii.Error as e:
                # Incorrect padding
                self.logger.warning(f'Unable to decode {uri}: {e}')
                return None
        else:
            if ',' not in uri:
                self.logger.warning(f'Unable to decode {uri}, missing ","')
                return None
            mime, d = uri.split(',', 1)
            data = d.encode()

        if mime:
            if ';' in mime:
                mime, mimeparams = mime.split(';', 1)
            else:
                mimeparams = ''
        else:
            mime = '[No mimetype given]'
            mimeparams = ''
        return mime, mimeparams, data

    def __extract_favicons(self, rendered_content: str | bytes) -> tuple[set[str], set[bytes]] | None:
        if isinstance(rendered_content, bytes):
            rendered_content = str(from_bytes(rendered_content).best())
            if not rendered_content:
                return None
        soup = BeautifulSoup(rendered_content, 'lxml')
        all_icons = set()
        favicons_urls = set()
        favicons = set()
        # shortcut
        for shortcut in soup.find_all('link', rel='shortcut icon'):
            all_icons.add(shortcut)
        # icons
        for icon in soup.find_all('link', rel='icon'):
            all_icons.add(icon)

        for mask_icon in soup.find_all('link', rel='mask-icon'):
            all_icons.add(mask_icon)
        for apple_touche_icon in soup.find_all('link', rel='apple-touch-icon'):
            all_icons.add(apple_touche_icon)
        for msapplication in soup.find_all('meta', attrs={'name': 'msapplication-TileImage'}):  # msapplication-TileColor
            all_icons.add(msapplication)

        for tag in all_icons:
            if icon_url := tag.get('href'):
                if parsed_uri := self.__parse_data_uri(icon_url):
                    mime, mimeparams, favicon = parsed_uri
                    favicons.add(favicon)
                else:
                    # NOTE: This urn can be a path without the domain part. We need to urljoin
                    favicons_urls.add(icon_url)
            elif tag.get('name') == 'msapplication-TileImage':
                if icon_url := tag.get('content'):
                    if parsed_uri := self.__parse_data_uri(icon_url):
                        mime, mimeparams, favicon = parsed_uri
                        favicons.add(favicon)
                    else:
                        # NOTE: This urn can be a path without the domain part. We need to urljoin
                        favicons_urls.add(icon_url)
            else:
                self.logger.info(f'Not processing {tag}')
        return favicons_urls, favicons

    async def get_favicons(self, rendered_url: str, rendered_content: str) -> set[bytes]:
        """This method will be deprecated as soon as Playwright will be able to fetch favicons (https://github.com/microsoft/playwright/issues/7493).
        In the meantime, we try to get all the potential ones in this method.
        Method inspired by https://github.com/ail-project/ail-framework/blob/master/bin/lib/crawlers.py
        """
        connector = None
        if self.proxy and self.proxy.get('server'):
            # NOTE 2024-05-17: switch to async to fetch, the lib uses socks5h by default
            connector = ProxyConnector.from_url(self.proxy['server'])

        extracted_favicons = self.__extract_favicons(rendered_content)
        if not extracted_favicons:
            return set()
        to_fetch, to_return = extracted_favicons
        to_fetch.add('/favicon.ico')
        async with aiohttp.ClientSession(connector=connector) as session:
            session.headers['user-agent'] = self.user_agent
            for u in to_fetch:
                try:
                    self.logger.debug(f'Attempting to fetch favicon from {u}.')
                    url_to_fetch = urljoin(rendered_url, u)
                    favicon = b''
                    if url_to_fetch in self._requests:
                        favicon = self._requests[url_to_fetch]
                    if not favicon:
                        async with session.get(url_to_fetch, timeout=5, ssl=False) as favicon_response:
                            favicon_response.raise_for_status()
                            favicon = await favicon_response.read()
                    if favicon:
                        try:
                            mimetype = from_string(favicon, mime=True)
                        except PureError:
                            # unable to identify the mimetype
                            self.logger.debug(f'Unable to identify the mimetype for favicon from {u}')
                        else:
                            if not mimetype:
                                # empty, ignore
                                pass
                            elif mimetype.startswith('image'):
                                to_return.add(favicon)
                            elif mimetype.startswith('text'):
                                # Just ignore, it's probably a 404 page
                                pass
                            else:
                                self.logger.warning(f'Unexpected mimetype for favicon from {u}: {mimetype}')
                    self.logger.debug(f'Done with favicon from {u}.')
                except aiohttp.ClientError as e:
                    self.logger.debug(f'Unable to fetch favicon from {u}: {e}')
                except Exception as e:
                    self.logger.info(f'Unexpectedly unable to fetch favicon from {u}: {e}')
        return to_return

    # END FAVICON EXTRACTOR
