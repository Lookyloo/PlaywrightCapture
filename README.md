# Playwright Capture

Simple replacement for [splash](https://github.com/scrapinghub/splash) using [playwright](https://github.com/microsoft/playwright-python).

# reCAPTCHA bypass

No blackmagic, it is just a reimplementation of a [well known technique](https://github.com/NikolaiT/uncaptcha3)
as implemented [there](https://github.com/Binit-Dhakal/Google-reCAPTCHA-v3-solver-using-playwright-python),
and [there](https://github.com/embium/solverecaptchas).

This modules will try to bypass reCAPTCHA protected websites if you install it this way:

```
    pip install playwrightcapture[recaptcha]
```

This will install `requests`, `pydub` and `SpeechRecognition`. In order to work, `pydub`
requires `ffmpeg` or `libav`, look at the [install guide ](https://github.com/jiaaro/pydub#installation)
for more details.
`SpeechRecognition` uses the Google Speech Recognition API to turn the audio file into text (I hope you appreciate the irony).
