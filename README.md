# Playwright Capture

Simple replacement for [splash](https://github.com/scrapinghub/splash) using [playwright](https://github.com/microsoft/playwright-python).

# Install

```bash
pip install playwrightcapture
```

# Usage

A very basic example:

```python
from playwrightcapture import Capture

async with Capture() as capture:
    await capture.prepare_context()
    entries = await capture.capture_page(url)
```

Entries is a dictionaries that contains (if all goes well) the HAR, the screenshot, all the cookies of the session, the URL as it is in the browser at the end of the capture, and the full HTML page as rendered.


# reCAPTCHA bypass

No blackmagic, it is just a reimplementation of a [well known technique](https://github.com/NikolaiT/uncaptcha3)
as implemented [there](https://github.com/Binit-Dhakal/Google-reCAPTCHA-v3-solver-using-playwright-python),
and [there](https://github.com/embium/solverecaptchas).

This modules will try to bypass reCAPTCHA protected websites if you install it this way:

```bash
pip install playwrightcapture[recaptcha]
```

This will install `requests`, `pydub` and `SpeechRecognition`. In order to work, `pydub`
requires `ffmpeg` or `libav`, look at the [install guide ](https://github.com/jiaaro/pydub#installation)
for more details.
`SpeechRecognition` uses the Google Speech Recognition API to turn the audio file into text (I hope you appreciate the irony).
