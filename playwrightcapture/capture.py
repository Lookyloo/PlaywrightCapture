#!/usr/bin/env python3

import json
import os
import random
import logging

from tempfile import NamedTemporaryFile
from typing import Optional, Dict, List, Union, Any, TypedDict, Literal

import dateparser

from playwright.async_api import async_playwright, ProxySettings, Frame, ViewportSize, Cookie, Error, Page
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from playwright._impl._api_structures import SetCookieParam

from .exceptions import UnknownPlaywrightBrowser, UnknownPlaywrightDevice, InvalidPlaywrightParameter
from .helpers import get_links_from_rendered_page

try:
    import pydub  # type: ignore
    import requests
    from speech_recognition import Recognizer, AudioFile  # type: ignore
    CAN_SOLVE_CAPTCHA = True
except ImportError:
    CAN_SOLVE_CAPTCHA = False


class CaptureResponse(TypedDict, total=False):

    last_redirected_url: str
    har: Optional[Dict[str, Any]]
    cookies: Optional[List[Cookie]]
    error: Optional[str]
    html: Optional[str]
    png: Optional[bytes]
    downloaded_filename: Optional[str]
    downloaded_file: Optional[bytes]
    children: Optional[List[Any]]


BROWSER = Literal['chromium', 'firefox', 'webkit']


class Capture():

    _user_agent: str = ''
    _browsers: List[BROWSER] = ['chromium', 'firefox', 'webkit']
    _default_viewport: ViewportSize = {'width': 1920, 'height': 1080}
    _viewport: Optional[ViewportSize] = None
    _general_timeout: int = 60 * 1000   # in miliseconds, set to 60s by default
    _cookies: List[SetCookieParam] = []
    _http_credentials: Dict[str, str] = {}
    _headers: Dict[str, str] = {}

    def __init__(self, browser: Optional[BROWSER]=None, device_name: Optional[str]=None,
                 proxy: Optional[Union[str, Dict[str, str]]]=None,
                 general_timeout_in_sec: Optional[int] = None, loglevel: str='INFO'):
        """Captures a page with Playwright.

        :param browser: The browser to use for the capture.
        :param device_name: The pre-defined device to use for the capture (from playwright).)
        :param proxy: The external proxy to use for the capture.
        :param general_timeout_in_sec: The general timeout for the capture.
        :param loglevel: Python loglevel
        """
        self.logger = logging.getLogger('playwrightcapture')
        self.logger.setLevel(loglevel)
        self.browser_name: BROWSER = browser if browser else 'chromium'
        self.general_timeout = general_timeout_in_sec * 1000 if general_timeout_in_sec is not None else self._general_timeout
        self.device_name = device_name
        self.proxy: Optional[ProxySettings] = None
        if proxy:
            if isinstance(proxy, str):
                self.proxy = {'server': proxy}
            else:
                self.proxy = {'server': proxy['server'], 'bypass': proxy.get('bypass', ''),
                              'username': proxy.get('username', ''),
                              'password': proxy.get('password', '')}

        self.should_retry: bool = False
        self.__network_not_idle: int = 1

    async def __aenter__(self) -> 'Capture':
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

        if self.proxy:
            self.browser = await self.playwright[self.browser_name].launch(
                proxy=self.proxy,
            )
        else:
            self.browser = await self.playwright[self.browser_name].launch()
        return self

    @property
    def http_credentials(self) -> Dict[str, str]:
        return self._http_credentials

    @property
    def cookies(self) -> List[SetCookieParam]:
        return self._cookies

    @cookies.setter
    def cookies(self, cookies: Optional[List[Dict[str, Any]]]) -> None:
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
                    except Exception:
                        pass
                elif isinstance(cookie['expires'], (float, int)):
                    c['expires'] = cookie['expires']
            if 'httpOnly' in cookie:
                c['httpOnly'] = bool(cookie['httpOnly'])
            if 'secure' in cookie:
                c['secure'] = bool(cookie['secure'])
            if 'sameSite' in cookie and cookie['sameSite'] in ["Lax", "None", "Strict"]:
                c['sameSite'] = cookie['sameSite']
            self._cookies.append(c)

    @property
    def headers(self) -> Dict[str, str]:
        return self._headers

    @headers.setter
    def headers(self, headers: Optional[Union[str, Dict[str, str]]]) -> None:
        if not headers:
            return
        if isinstance(headers, str):
            for header_line in headers.splitlines():
                if header_line and ':' in header_line:
                    splitted = header_line.split(':', 1)
                    if splitted and len(splitted) == 2:
                        header, h_value = splitted
                        if header and h_value:
                            self._headers[header.strip()] = h_value.strip()
        else:
            self._headers = headers

    @property
    def viewport(self) -> Optional[ViewportSize]:
        return self._viewport

    @viewport.setter
    def viewport(self, viewport: Optional[Dict[str, int]]) -> None:
        if not viewport:
            return
        if 'width' in viewport and 'height' in viewport:
            self._viewport = {'width': viewport['width'], 'height': viewport['height']}
        else:
            raise InvalidPlaywrightParameter(f'A viewport must have a height and a width - {viewport}')

    @property
    def user_agent(self) -> str:
        return self._user_agent

    @user_agent.setter
    def user_agent(self, user_agent: Optional[str]) -> None:
        if user_agent is not None:
            self._user_agent = user_agent

    async def initialize_context(self) -> None:
        default_context_settings = {
            'record_har_path': self._temp_harfile.name,
            'ignore_https_errors': True
        }

        if self.device_name:
            default_context_settings.update(self.playwright.devices[self.device_name])

        if self.http_credentials:
            default_context_settings['http_credentials'] = self.http_credentials

        if self.user_agent:
            # User defined UA, can overwrite device UA
            default_context_settings['user_agent'] = self.user_agent

        if self.viewport:
            # User defined viewport, can overwrite device viewport
            default_context_settings['viewport'] = self.viewport
        elif 'viewport' not in default_context_settings:
            # No viewport given, fallback to default
            default_context_settings['viewport'] = self._default_viewport

        if self.browser_name == 'firefox' and default_context_settings.get('is_mobile'):
            # NOTE: Not supported, see https://github.com/microsoft/playwright-python/issues/1509
            default_context_settings.pop('is_mobile')

        self.context = await self.browser.new_context(**default_context_settings)  # type: ignore

        self.context.set_default_navigation_timeout(self.general_timeout)
        if self.cookies:
            await self.context.add_cookies(self.cookies)
        if self.headers:
            await self.context.set_extra_http_headers(self.headers)

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

    def set_http_credentials(self, username: str, password: str) -> None:
        self._http_credentials = {'username': username, 'password': password}

    def make_frame_tree(self, frame: Frame) -> Dict[str, List[Dict[str, Any]]]:
        # TODO: not used at this time, need to figure out how do use that.
        to_return: Dict[str, List[Dict[str, Any]]] = {frame._impl_obj._guid: []}
        for child in frame.child_frames:
            to_return[frame._impl_obj._guid].append(self.make_frame_tree(child))
        return to_return

    async def _safe_wait(self, page: Page) -> None:
        try:
            # If we don't have networkidle relatively quick, it's probably because we're playing a video.
            await page.wait_for_load_state('networkidle', timeout=10000 / self.__network_not_idle)
        except PlaywrightTimeoutError:
            # Network never idle, keep going
            self.__network_not_idle += 1

    async def recaptcha_solver(self, page: Page) -> bool:
        framename = await page.locator("//iframe[@title='reCAPTCHA']").get_attribute("name")
        if not framename:
            return False
        recaptcha_init_frame = page.frame(name=framename)

        if not recaptcha_init_frame:
            return False
        await recaptcha_init_frame.get_by_role("checkbox", name="I'm not a robot").click()
        await page.wait_for_timeout(random.randint(3, 6) * 1000)
        try:
            if await recaptcha_init_frame.locator("//span[@id='recaptcha-anchor']").is_checked(timeout=5000):  # solved already
                return True
        except PlaywrightTimeoutError:
            self.logger.debug('Need to solve the captcha.')

        recaptcha_testframename = await page.locator("//iframe[contains(@src,'https://google.com/recaptcha/api2/bframe?')]").get_attribute("name")
        if not recaptcha_testframename:
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
                if await recaptcha_init_frame.locator("//span[@id='recaptcha-anchor']").is_checked(timeout=5000):
                    self.logger.info('Captcha solved successfully')
                    return True
                elif await main_frame.get_by_role("textbox", name="Enter what you hear").is_editable(timeout=5000):
                    self.logger.info('Unable to find checkbox, needs to solve more captchas')
            except PlaywrightTimeoutError as e:
                self.logger.info(f'Unexpected timeout: {e}')

    async def _failsafe_get_content(self, page: Page) -> Optional[str]:
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
        self.logger.warning('Unable to get page content.')
        return None

    async def _failsafe_get_screenshot(self, page: Page) -> bytes:
        try:
            return await page.screenshot(full_page=True)
        except Error as e:
            self.logger.info(f"Capturing a screenshot of the full page failed, trying to scale it down: {e}")

        try:
            return await page.screenshot(full_page=True, scale="css")
        except Error as e:
            self.logger.warning(f"Capturing a screenshot of the full page failed, trying to get the current viewport only: {e}")

        try:
            return await page.screenshot()
        except Error as e:
            self.logger.warning(f"Unable to get any screenshot: {e}")
            raise e

    async def capture_page(self, url: str, referer: Optional[str]=None, page: Optional[Page]=None,
                           depth: int=0, rendered_hostname_only: bool=True) -> CaptureResponse:
        to_return: CaptureResponse = {}
        try:
            if page:
                capturing_sub = True
            else:
                capturing_sub = False
                page = await self.context.new_page()
            try:
                # NOTE 2022-12-02: allow 15s less than the general timeout to get a DOM
                await page.goto(url, wait_until='domcontentloaded', timeout=self.general_timeout - 15000, referer=referer if referer else '')
            except Error as initial_error:
                # page.goto failed, but it (might have) triggered a download event.
                # If it is the case, let's try to save it.
                try:
                    async with page.expect_download(timeout=5000) as download_info:
                        tmp_f = NamedTemporaryFile(delete=False)
                        download = await download_info.value
                        await download.save_as(tmp_f.name)
                        to_return["downloaded_filename"] = download.suggested_filename
                        with open(tmp_f.name, "rb") as f:
                            to_return["downloaded_file"] = f.read()
                        os.unlink(tmp_f.name)
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
                        self.retry = True
                    except Exception:
                        raise e
            else:
                await page.bring_to_front()

                # page instrumentation
                await page.wait_for_timeout(5000)  # Wait 5 sec after document loaded

                # ==== recaptcha
                # Same technique as: https://github.com/NikolaiT/uncaptcha3
                if CAN_SOLVE_CAPTCHA:
                    try:
                        if await page.is_visible("//iframe[@title='reCAPTCHA']", timeout=5000):
                            self.logger.info('Found a captcha')
                            await self.recaptcha_solver(page)
                    except Error as e:
                        self.logger.warning(f'Error while resolving captcha: {e}')
                    except Exception as e:
                        self.logger.exception(f'General error with captcha solving: {e}')
                # ======

                # check if we have anything on the page. If we don't, the page is not working properly.
                if await self._failsafe_get_content(page):
                    # move mouse
                    await page.mouse.move(x=500, y=400)
                    await self._safe_wait(page)
                    self.logger.debug('Moved mouse')

                    # scroll
                    try:
                        # NOTE using page.mouse.wheel causes the instrumentation to fail, sometimes
                        await page.mouse.wheel(delta_y=2000, delta_x=0)
                        await self._safe_wait(page)
                    except Error as e:
                        self.logger.debug(f'Unable to scroll: {e}')
                    await page.keyboard.press('PageUp')
                    self.logger.debug('Scrolled')

                await self._safe_wait(page)
                await page.wait_for_timeout(5000)  # Wait 5 sec after network idle
                await self._safe_wait(page)

                if content := await self._failsafe_get_content(page):
                    to_return['html'] = content

                to_return['last_redirected_url'] = page.url

                to_return['png'] = await self._failsafe_get_screenshot(page)

                if depth > 0 and to_return.get('html') and to_return['html']:
                    to_return['children'] = []
                    depth -= 1
                    child_urls = get_links_from_rendered_page(page.url, to_return['html'], rendered_hostname_only)
                    self.logger.info(f'Capturing children, {len(child_urls)} URLs')
                    for url in child_urls:
                        self.logger.info(f'Capture child {url}')
                        to_return['children'].append(await self.capture_page(url, page.url, page, depth))  # type: ignore
                        try:
                            await page.go_back()
                        except PlaywrightTimeoutError as e:
                            self.logger.warning(f'Go back timed out, it is probably not a big deal: {e}')

        except PlaywrightTimeoutError as e:
            to_return['error'] = f"The capture took too long - {e.message}"
            self.retry = True
        except Error as e:
            to_return['error'] = e.message
            # TODO: check e.name and figure out if it is worth retrying or not.
            self.logger.critical(f'Something went poorly with {url}: {e.message}')
        finally:
            if not capturing_sub:
                to_return['cookies'] = await self.context.cookies()
                await self.context.close()  # context needs to be closed to generate the HAR
                # frames_tree = self.make_frame_tree(page.main_frame)
                try:
                    with open(self._temp_harfile.name) as _har:
                        to_return['har'] = json.load(_har)
                except Exception as e:
                    to_return['error'] = f'Unable to generate HAR file: {e}'
        self.logger.debug('Capture done')
        return to_return

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if hasattr(self, '_temp_harfile'):
            os.unlink(self._temp_harfile.name)

        await self.browser.close()
        # This method *must* be awaited but for some reason, MyPy complains.
        await self.playwright.stop()  # type: ignore
