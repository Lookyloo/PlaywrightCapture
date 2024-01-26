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
from io import BytesIO
from tempfile import NamedTemporaryFile
from typing import Any, TypedDict, Literal, TYPE_CHECKING
from urllib.parse import urlparse, unquote, urljoin
from zipfile import ZipFile

import dateparser
import requests

from bs4 import BeautifulSoup
from charset_normalizer import from_bytes
from playwright.async_api import async_playwright, Frame, Error, Page, Download
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright_stealth import stealth_async  # type: ignore[import-untyped]
from w3lib.html import strip_html5_whitespace
from w3lib.url import canonicalize_url, safe_url_string

from .exceptions import UnknownPlaywrightBrowser, UnknownPlaywrightDevice, InvalidPlaywrightParameter

if sys.version_info < (3, 9):
    from pytz import all_timezones_set
else:
    from zoneinfo import available_timezones
    all_timezones_set = available_timezones()

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


class Capture():

    _browsers: list[BROWSER] = ['chromium', 'firefox', 'webkit']
    _default_viewport: ViewportSize = {'width': 1920, 'height': 1080}
    _default_timeout: int = 90  # set to 90s by default
    _minimal_timeout: int = 15  # set to 15s - It makes little sense to attempt a capture below that limit.

    def __init__(self, browser: BROWSER | None=None, device_name: str | None=None,
                 proxy: str | dict[str, str] | None=None,
                 general_timeout_in_sec: int | None = None, loglevel: str='INFO'):
        """Captures a page with Playwright.

        :param browser: The browser to use for the capture.
        :param device_name: The pre-defined device to use for the capture (from playwright).)
        :param proxy: The external proxy to use for the capture.
        :param general_timeout_in_sec: The general timeout for the capture, including children.
        :param loglevel: Python loglevel
        """
        self.logger = logging.getLogger('playwrightcapture')
        self.logger.setLevel(loglevel)
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
            else:
                self.proxy = {'server': proxy['server'], 'bypass': proxy.get('bypass', ''),
                              'username': proxy.get('username', ''),
                              'password': proxy.get('password', '')}

        self.should_retry: bool = False
        self.__network_not_idle: int = 1
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
            proxy=self.proxy if self.proxy else None
        )
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
    def headers(self, headers: str | dict[str, str] | None) -> None:
        if not headers:
            return
        if isinstance(headers, str):
            new_headers: dict[str, str] = {}
            for header_line in headers.splitlines():
                if header_line and ':' in header_line:
                    splitted = header_line.split(':', 1)
                    if splitted and len(splitted) == 2:
                        header, h_value = splitted
                        if header.strip() and h_value.strip():
                            new_headers[header.strip()] = h_value.strip()
        elif isinstance(headers, dict):
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

        self.context = await self.browser.new_context(
            record_har_path=self._temp_harfile.name,
            ignore_https_errors=True,
            http_credentials=self.http_credentials if self.http_credentials else None,
            user_agent=self.user_agent if self.user_agent else device_context_settings.pop('user_agent', None),
            locale=self.locale if self.locale else None,
            timezone_id=self.timezone_id if self.timezone_id else None,
            color_scheme=self.color_scheme if self.color_scheme else None,
            viewport=self.viewport if self.viewport else device_context_settings.pop('viewport', self._default_viewport),
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
                await self._safe_wait(page)
                await cf_locator.click(force=True, position={"x": random.uniform(1, 32), "y": random.uniform(1, 32)})
                self.logger.info('Cloudflare widget visible.')
                await self._safe_wait(page)
                await page.wait_for_timeout(2000)  # Wait 30 sec after network idle
                spinner = page.locator('#challenge-spinner')
                while True:
                    if await spinner.is_visible():
                        self.logger.info('Cloudflare spinner visible.')
                        await page.wait_for_timeout(2000)
                    else:
                        self.logger.info('Cloudflare spinner not visible.')
                        break
                max_tries -= 1
                await page.wait_for_timeout(5000)
        except Exception as e:
            self.logger.info(f'Unable to find Cloudflare locator: {e}')

    async def capture_page(self, url: str, *, max_depth_capture_time: int,
                           referer: str | None=None,
                           page: Page | None=None, depth: int=0,
                           rendered_hostname_only: bool=True,
                           with_favicon: bool=False
                           ) -> CaptureResponse:

        to_return: CaptureResponse = {}

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
                self.logger.warning(f'Unable to finish download triggered from JS: {e}')
            finally:
                self.wait_for_download -= 1

        if page is not None:
            capturing_sub = True
        else:
            capturing_sub = False
            page = await self.context.new_page()
            await stealth_async(page)
            page.set_default_timeout(self._capture_timeout * 1000)
        try:
            # Parse the URL. If there is a fragment, we need to scroll to it manually
            parsed_url = urlparse(url, allow_fragments=True)

            try:
                # NOTE 2022-12-02: allow 15s less than the general timeout to get a DOM
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
                elif self._exception_is_network_error(initial_error):
                    raise initial_error
            else:
                await page.bring_to_front()

                # page instrumentation
                await page.wait_for_timeout(5000)  # Wait 5 sec after document loaded

                # ==== recaptcha
                # Same technique as: https://github.com/NikolaiT/uncaptcha3
                if CAN_SOLVE_CAPTCHA:
                    try:
                        if (await page.locator("//iframe[@title='reCAPTCHA']").first.is_visible(timeout=5000)
                                and await page.locator("//iframe[@title='reCAPTCHA']").first.is_enabled(timeout=5000)):
                            self.logger.info('Found a captcha')
                            await self._recaptcha_solver(page)
                    except PlaywrightTimeoutError as e:
                        self.logger.info(f'Captcha on {url} is not ready: {e}')
                    except Error as e:
                        self.logger.warning(f'Error while resolving captcha on {url}: {e}')
                    except Exception as e:
                        self.logger.exception(f'General error with captcha solving on {url}: {e}')
                # ======
                # NOTE: testing
                # await self.__cloudflare_bypass_attempt(page)

                # check if we have anything on the page. If we don't, the page is not working properly.
                if await self._failsafe_get_content(page):
                    # move mouse
                    await page.mouse.move(x=random.uniform(300, 800), y=random.uniform(200, 500))
                    await self._safe_wait(page)

                    if parsed_url.fragment:
                        # We got a fragment, make sure we go to it and scroll only a little bit.
                        fragment = unquote(parsed_url.fragment)
                        try:
                            await page.locator(f'id={fragment}').first.scroll_into_view_if_needed(timeout=5000)
                            await self._safe_wait(page)
                            await page.mouse.wheel(delta_y=random.uniform(150, 300), delta_x=0)
                        except PlaywrightTimeoutError as e:
                            self.logger.info(f'Unable to go to fragment "{fragment}" (timeout): {e}')
                        except Error as e:
                            self.logger.exception(f'Unable to go to fragment "{fragment}": {e}')
                    else:
                        # scroll more
                        try:
                            # NOTE using page.mouse.wheel causes the instrumentation to fail, sometimes
                            await page.mouse.wheel(delta_y=random.uniform(1500, 3000), delta_x=0)
                        except Error as e:
                            self.logger.debug(f'Unable to scroll: {e}')

                    await self._safe_wait(page)
                    try:
                        await page.keyboard.press('PageUp')
                        await self._safe_wait(page)
                        await page.keyboard.press('PageDown')
                    except Error as e:
                        self.logger.debug(f'Unable to use keyboard: {e}')

                await self._safe_wait(page)
                await page.wait_for_timeout(5000)  # Wait 5 sec after network idle
                await self._safe_wait(page)

                if content := await self._failsafe_get_content(page):
                    to_return['html'] = content

                to_return['last_redirected_url'] = page.url

                to_return['png'] = await self._failsafe_get_screenshot(page)

                if 'html' in to_return and to_return['html'] is not None and with_favicon:
                    to_return['potential_favicons'] = self.get_favicons(page.url, to_return['html'])

                if self.wait_for_download > 0:
                    self.logger.info('Waiting for download to finish...')
                    await self._safe_wait(page)

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
                        for index, url in enumerate(child_urls):
                            self.logger.info(f'Capture child {url} - Timeout: {max_capture_time}s')
                            start_time = time.time()
                            try:
                                child_capture = await asyncio.wait_for(
                                    self.capture_page(url=url, referer=page.url,
                                                      page=page, depth=depth,
                                                      rendered_hostname_only=rendered_hostname_only,
                                                      max_depth_capture_time=max_capture_time),
                                    timeout=max_capture_time + 1)  # just adding a bit of padding so playwright has the chance to raise the exception first
                                to_return['children'].append(child_capture)  # type: ignore[union-attr]
                            except (TimeoutError, asyncio.exceptions.TimeoutError):
                                self.logger.info(f'Timeout error, took more than {max_capture_time}s. Unable to capture {url}.')
                            except Exception as e:
                                self.logger.warning(f'Error while capturing child "{url}": {e}. {len(child_urls) - index - 1} more to go.')
                            else:
                                runtime = int(time.time() - start_time)
                                self.logger.info(f'Successfully captured child URL: {url} in {runtime}s. {len(child_urls) - index - 1} to go.')
                            try:
                                await page.go_back()
                            except PlaywrightTimeoutError:
                                self.logger.info('Go back timed out, it is probably not a big deal.')
                            except Exception as e:
                                self.logger.warning(f'Unable to go back: {e}.')

        except PlaywrightTimeoutError as e:
            to_return['error'] = f"The capture took too long - {e.message}"
            self.should_retry = True
        except Error as e:
            self._update_exceptions(e)
            to_return['error'] = e.message
            to_return['error_name'] = e.name
            # TODO: check e.message and figure out if it is worth retrying or not.
            # NOTE: e.name is generally (always?) "Error"
            if self._exception_is_network_error(e):
                # Expected errors
                self.logger.info(f'Unable to process {url}: {e.message}')
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
                            'Navigation interrupted by another one',
                            'Navigation failed because page was closed!',
                            'Protocol error (Page.bringToFront): Not attached to an active page']:
                # Other errors, let's give it another shot
                self.logger.info(f'Issue with {url} (retrying): {e.message}')
                self.should_retry = True
            else:
                # Unexpected ones
                self.logger.exception(f'Something went poorly with {url}: {e.message}')
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
        try:
            return await page.screenshot(full_page=True)
        except Error as e:
            self.logger.info(f"Capturing a screenshot of the full page failed, trying to scale it down: {e}")

        try:
            return await page.screenshot(full_page=True, scale="css")
        except Error as e:
            self.logger.info(f"Capturing a screenshot of the full page failed, trying to get the current viewport only: {e}")

        try:
            return await page.screenshot()
        except Error as e:
            self.logger.warning(f"Unable to get any screenshot: {e}")
            raise e

    async def _safe_wait(self, page: Page) -> None:
        try:
            # If we don't have networkidle relatively quick, it's probably because we're playing a video.
            await page.wait_for_load_state('networkidle', timeout=10000 / self.__network_not_idle)
        except PlaywrightTimeoutError:
            # Network never idle, keep going
            self.__network_not_idle += 1

    async def _failsafe_get_content(self, page: Page) -> str | None:
        ''' The page might be changing for all kind of reason (generally a JS timeout).
        In that case, we try a few times to get the HTML.'''
        tries = 3
        while tries:
            try:
                return await page.content()
            except Error:
                self.logger.debug('Unable to get page content, trying again.')
                tries -= 1
                await page.wait_for_timeout(1000)
                await self._safe_wait(page)
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

        return sorted(urls)

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

        await page.wait_for_timeout(random.randint(3, 6) * 1000)
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
        while True:
            try:
                href = await main_frame.get_by_role("link", name="Alternatively, download audio as MP3").get_attribute("href")
            except Exception as e:
                self.logger.warning(f'Google caught the browser as a robot, sorry: {e}')
                return False
            if not href:
                self.logger.warning('Unable to find download link for captcha.')
                return False
            r = requests.get(href, allow_redirects=True)
            with NamedTemporaryFile() as mp3_file, NamedTemporaryFile() as wav_file:
                mp3_file.write(r.content)
                pydub.AudioSegment.from_mp3(mp3_file.name).export(wav_file.name, format="wav")
                recognizer = Recognizer()
                recaptcha_audio = AudioFile(wav_file.name)
                with recaptcha_audio as source:
                    audio = recognizer.record(source)
                text = recognizer.recognize_google(audio)
            await main_frame.get_by_role("textbox", name="Enter what you hear").fill(text)
            await main_frame.get_by_role("button", name="Verify").click()
            await self._safe_wait(page)
            await page.wait_for_timeout(random.randint(3, 6) * 1000)
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
            exception._name = name.strip()

    def _exception_is_network_error(self, exception: Error) -> bool:
        if exception.name in [
                'NS_ERROR_ABORT',
                'NS_ERROR_CONNECTION_REFUSED',
                'NS_ERROR_NET_INTERRUPT',
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
                'net::ERR_EMPTY_RESPONSE',
                'net::ERR_HTTP2_PROTOCOL_ERROR',
                'net::ERR_NAME_NOT_RESOLVED',
                'net::ERR_SOCKS_CONNECTION_FAILED',
                'net::ERR_SSL_UNRECOGNIZED_NAME_ALERT',
                'net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH',
                'net::ERR_SSL_PROTOCOL_ERROR',
                'net::ERR_TIMED_OUT',
                'net::ERR_TOO_MANY_REDIRECTS',
        ]:
            return True
        return False

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

        # print(favicons_urls)
        return favicons_urls, favicons

    def get_favicons(self, rendered_url: str, rendered_content: str) -> set[bytes]:
        """This method will be deprecated as soon as Playwright will be able to fetch favicons (https://github.com/microsoft/playwright/issues/7493).
        In the meantime, we try to get all the potential ones in this method.
        Method inspired by https://github.com/ail-project/ail-framework/blob/master/bin/lib/crawlers.py
        """
        extracted_favicons = self.__extract_favicons(rendered_content)
        if not extracted_favicons:
            return set()
        to_fetch, to_return = extracted_favicons
        to_fetch.add('/favicon.ico')
        session = requests.session()
        session.headers['user-agent'] = self.user_agent
        if self.proxy and self.proxy.get('server'):
            proxies = {'http': self.proxy['server'],
                       'https': self.proxy['server']}
            session.proxies.update(proxies)
        for u in to_fetch:
            try:
                self.logger.debug(f'Attempting to fetch favicon from {u}.')
                favicon_response = session.get(urljoin(rendered_url, u), timeout=5)
                favicon_response.raise_for_status()
                to_return.add(favicon_response.content)
                self.logger.debug(f'Done with favicon from {u}.')
            except Exception as e:
                self.logger.info(f'Unable to fetch favicon from {u}: {e}')

        return to_return

    # END FAVICON EXTRACTOR
