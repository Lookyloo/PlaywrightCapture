#!/usr/bin/env python3

from __future__ import annotations

import sys

from collections import defaultdict

from playwright.sync_api import sync_playwright

from .exceptions import UnknownPlaywrightDeviceType

if sys.version_info < (3, 12):
    from typing_extensions import TypedDict
else:
    from typing import TypedDict


class PlaywrightDevice(TypedDict):

    user_agent: str
    viewport: dict[str, int]
    device_scale_factor: int
    is_mobile: bool
    has_touch: bool
    default_browser_type: str


def get_devices(in_testsuite: bool=False) -> dict[str, dict[str, dict[str, PlaywrightDevice]]]:
    to_return: dict[str, dict[str, dict[str, PlaywrightDevice]]] = {'desktop': defaultdict(dict), 'mobile': defaultdict(dict)}
    with sync_playwright() as playwright:
        devices: dict[str, PlaywrightDevice] = playwright.devices
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
