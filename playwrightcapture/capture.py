#!/usr/bin/env python3

import json
import os
import random
import logging

from tempfile import NamedTemporaryFile
from typing import Optional, Dict, List, Union, Any, TypedDict

import dateparser

from playwright.async_api import async_playwright, ProxySettings, Frame, ViewportSize, Cookie, Error, Page
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from playwright._impl._api_structures import SetCookieParam

from .exceptions import UnknownPlaywrightBrowser, UnknownPlaywrightDevice, InvalidPlaywrightParameter

try:
    import pydub  # type: ignore
    import requests
    from speech_recognition import Recognizer, AudioFile  # type: ignore
    CAN_SOLVE_CAPTCHA = True
except ImportError:
    CAN_SOLVE_CAPTCHA = False


class CaptureResponse(TypedDict, total=False):

    har: Dict[str, Any]
    last_redirected_url: str
    cookies: List[Cookie]
    error: Optional[str]
    html: Optional[str]
    png: Optional[bytes]
    downloaded_filename: Optional[str]
    downloaded_file: Optional[bytes]


class Capture():

    _user_agent: str = ''
    _browsers: List[str] = ['chromium', 'firefox', 'webkit']
    _default_viewport: ViewportSize = {'width': 1920, 'height': 1080}
    _viewport: Optional[ViewportSize] = None
    _general_timeout: int = 45 * 1000   # in miliseconds, set to 45s by default
    _cookies: List[SetCookieParam] = []
    _http_credentials: Dict[str, str] = {}
    _headers: Dict[str, str] = {}

    def __init__(self, browser: Optional[str]=None, device_name: Optional[str]=None, proxy: Optional[Union[str, Dict[str, str]]]=None, loglevel: str='WARNING'):
        self.logger = logging.getLogger('playwrightcapture')
        self.logger.setLevel(loglevel)
        self.browser_name = browser if browser else 'chromium'
        self.device_name = device_name
        self.proxy = proxy

    async def __aenter__(self) -> 'Capture':
        '''Launch the browser, with or without a proxy.
        :param proxy: The proxy, as a dictionary with the following format:
            ```
               {'server': 'proxy.server',
                'username': 'user',
                'password': 'pwd'}
            ```
        '''
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
            p: ProxySettings
            if isinstance(self.proxy, str):
                p = {'server': self.proxy}
            else:
                p = {'server': self.proxy['server'], 'bypass': self.proxy.get('bypass', ''),
                     'username': self.proxy.get('username', ''),
                     'password': self.proxy.get('password', '')}
            self.browser = await self.playwright[self.browser_name].launch(
                proxy=p,
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
    def cookies(self, cookies: List[Dict[str, Any]]) -> None:
        '''Cookies to send along to the initial request.
        :param cookies: The cookies, in this format: https://playwright.dev/python/docs/api/class-browsercontext#browser-context-add-cookies
        '''
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
    def headers(self, headers: Dict[str, str]) -> None:
        self._headers = headers

    @property
    def viewport(self) -> Optional[ViewportSize]:
        return self._viewport

    @viewport.setter
    def viewport(self, viewport: Dict[str, int]) -> None:
        if 'width' in viewport and 'height' in viewport:
            self._viewport = {'width': viewport['width'], 'height': viewport['height']}
        else:
            raise InvalidPlaywrightParameter(f'A viewport must have a height and a width - {viewport}')

    @property
    def user_agent(self) -> str:
        return self._user_agent

    @user_agent.setter
    def user_agent(self, user_agent: str) -> None:
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

        self.context.set_default_navigation_timeout(self._general_timeout)
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
            await page.wait_for_load_state('networkidle', timeout=10)
        except PlaywrightTimeoutError:
            # Network never idle, keep going
            pass

    async def recaptcha_solver(self, page: Page) -> bool:
        framename = await page.locator("//iframe[@title='reCAPTCHA']").get_attribute("name")
        if not framename:
            return False
        recaptcha_init_frame = page.frame(name=framename)

        if not recaptcha_init_frame:
            return False
        await recaptcha_init_frame.click("//div[@class='recaptcha-checkbox-border']")
        await page.wait_for_timeout(random.randint(1, 3) * 1000)
        s = recaptcha_init_frame.locator("//span[@id='recaptcha-anchor']")
        if await s.get_attribute("aria-checked") != "false":  # solved already
            return True

        recaptcha_testframename = await page.locator("//iframe[contains(@src,'https://google.com/recaptcha/api2/bframe?')]").get_attribute("name")
        if not recaptcha_testframename:
            return False
        main_frame = page.frame(name=recaptcha_testframename)
        if not main_frame:
            return False

        # click on audio challenge button
        await main_frame.click("id=recaptcha-reload-button", timeout=2 * 1000,
                               delay=100, position={'x': 3, 'y': 4})
        await page.wait_for_timeout(random.randint(1, 3) * 1000)
        await main_frame.locator("#recaptcha-audio-button").click(timeout=2 * 1000)

        # get audio file
        await page.wait_for_timeout(random.randint(1, 3) * 1000)
        await main_frame.click("//button[@aria-labelledby='audio-instructions rc-response-label']", timeout=5 * 1000)
        href = await main_frame.locator("//a[@class='rc-audiochallenge-tdownload-link']").get_attribute("href")
        if not href:
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
        await main_frame.fill("id=audio-response", text)
        await main_frame.click("id=recaptcha-verify-button")
        await self._safe_wait(page)
        return True

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

    async def capture_page(self, url: str, referer: Optional[str]=None) -> CaptureResponse:
        to_return: CaptureResponse = {}
        try:
            page = await self.context.new_page()
            try:
                await page.goto(url, wait_until='load', referer=referer if referer else '')
            except Error as initial_error:
                # page.goto failed, but it (might have) triggered a download event.
                # If it is the case, let's try to save it.
                try:
                    async with page.expect_download(timeout=5) as download_info:
                        tmp_f = NamedTemporaryFile(delete=False)
                        download = await download_info.value
                        await download.save_as(tmp_f.name)
                        to_return["downloaded_filename"] = download.suggested_filename
                        with open(tmp_f.name, "rb") as f:
                            to_return["downloaded_file"] = f.read()
                        os.unlink(f.name)
                except PlaywrightTimeoutError:
                    self.logger.info('No download has been triggered.')
                    raise initial_error
            else:
                await page.bring_to_front()

                # page instrumentation
                await page.wait_for_timeout(5000)  # Wait 5 sec after document loaded

                # ==== recaptcha
                # Same technique as: https://github.com/NikolaiT/uncaptcha3
                if CAN_SOLVE_CAPTCHA:
                    try:
                        if await page.is_visible("//iframe[@title='reCAPTCHA']", timeout=5 * 1000):
                            self.logger.info('Found a captcha')
                            await self.recaptcha_solver(page)
                    except Error:
                        self.logger.exception('Error while resolving captcha.')
                    except Exception:
                        self.logger.exception('General error with captcha solving.')
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
                        self.logger.warning(f'Unable to scroll: {e}')
                    await page.keyboard.press('PageUp')
                    self.logger.debug('Scrolled')

                await self._safe_wait(page)
                await page.wait_for_timeout(5000)  # Wait 5 sec after network idle
                await self._safe_wait(page)

                if content := await self._failsafe_get_content(page):
                    to_return['html'] = content
                to_return['png'] = await page.screenshot(full_page=True)
        except PlaywrightTimeoutError as e:
            to_return['error'] = f"The capture took too long - {e.message}"
        except Error as e:
            to_return['error'] = e.message
            self.logger.exception('Something went poorly.')
        finally:
            to_return['last_redirected_url'] = page.url
            to_return['cookies'] = await self.context.cookies()
            await self.context.close()  # context needs to be closed to generate the HAR
            # frames_tree = self.make_frame_tree(page.main_frame)
            with open(self._temp_harfile.name) as _har:
                to_return['har'] = json.load(_har)
        self.logger.debug('Capture done')
        return to_return

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if hasattr(self, '_temp_harfile'):
            os.unlink(self._temp_harfile.name)

        await self.browser.close()
        # This method *must* be awaited but for some reason, MyPy complains.
        await self.playwright.stop()  # type: ignore
