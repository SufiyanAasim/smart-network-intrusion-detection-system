"""Client-side critical-threat notification: a beep sound + browser notice.

The beep WAV is synthesized at runtime with the standard library (no audio
asset to ship, no external dependency). `alert_html` returns a small
self-contained HTML/JS snippet suitable for `st.components.v1.html`, which
plays the sound and raises a browser Notification when the user has enabled
those options.

Kept free of Streamlit imports so it can be unit tested directly.
"""

import base64
import io
import json
import math
import struct
import wave

_SAMPLE_RATE = 44100


def beep_wav_bytes(frequency=880.0, duration_seconds=0.25, volume=0.5):
    """Synthesize a short sine-wave beep and return it as WAV file bytes."""
    n_samples = int(_SAMPLE_RATE * duration_seconds)
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)  # 16-bit
        wav.setframerate(_SAMPLE_RATE)
        frames = bytearray()
        for i in range(n_samples):
            sample = volume * math.sin(2 * math.pi * frequency * (i / _SAMPLE_RATE))
            frames += struct.pack("<h", int(sample * 32767))
        wav.writeframes(bytes(frames))
    return buffer.getvalue()


def beep_data_uri():
    """Return the beep as a base64 `data:audio/wav` URI."""
    encoded = base64.b64encode(beep_wav_bytes()).decode("ascii")
    return f"data:audio/wav;base64,{encoded}"


def alert_html(message, play_sound=True, browser_notification=True, nonce=""):
    """Return an HTML/JS snippet that fires the enabled notifications.

    `nonce` should change per alert so Streamlit re-renders the component and
    the JS runs again (identical HTML would be deduplicated). No-op branches
    are omitted so a disabled channel produces no code.
    """
    safe_message = json.dumps(str(message).replace("\n", " ")).replace("<", "\\u003c")
    parts = [f'<!-- nonce:{nonce} -->']

    if play_sound:
        parts.append(f'<audio autoplay src="{beep_data_uri()}"></audio>')

    if browser_notification:
        parts.append(
            "<script>"
            "(function(){"
            "if(!('Notification' in window))return;"
            "function show(){new Notification('NIDS: Critical threat',"
            f'{{body:{safe_message}}});}}'
            "if(Notification.permission==='granted'){show();}"
            "else if(Notification.permission!=='denied'){"
            "Notification.requestPermission().then(function(p){"
            "if(p==='granted')show();});}"
            "})();"
            "</script>"
        )

    return "".join(parts)
