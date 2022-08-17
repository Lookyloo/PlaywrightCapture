#!/usr/bin/env python3

class PlaywrightCaptureException(Exception):
    pass


class UnknownPlaywrightDeviceType(PlaywrightCaptureException):
    pass


class UnknownPlaywrightBrowser(PlaywrightCaptureException):
    pass


class UnknownPlaywrightDevice(PlaywrightCaptureException):
    pass


class InvalidPlaywrightParameter(PlaywrightCaptureException):
    pass
