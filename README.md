# Source Studio

Source Studio is a local media discovery app with a separate TeraBox resolver. It can observe media requests, list streams and subtitle tracks, play HLS streams through a local relay, and export captured TeraBox video to MP4.

## Run locally

Install Python, then run these commands from the repository directory:

```sh
python -m pip install -r requirements.txt
python -m playwright install chromium
python app.py
```

Open [Source Studio](http://127.0.0.1:5050/) or the [TeraBox resolver](http://127.0.0.1:5050/terabox). The app listens on loopback.

Install FFmpeg and add it to `PATH` to use **Download MP4** on HLS video. Optionally install `requirements-addons.txt` to enable the Lexbor parser accelerator.

## TeraBox

1. Open **Saved session settings** and select a domain-scoped TeraBox cookie export from a browser session that can access the share. JSON, Netscape `cookies.txt`, and TSV are supported. The app encrypts and stores the cookies for the current Windows user.
2. Paste a share and click **Resolve full video**. The field converts `terabox.com` links to `terabox.app`. The resolver tries the official download, then looks for playback sources. If TeraBox prompts you to save a preview for full access, the app may save a copy to your My TeraBox account.
3. Use **Play video** or **Download MP4** beside a captured HLS stream. An original download, when available, starts automatically. Relay links are temporary. Full-video access depends on what TeraBox offers to your saved session.

Keep cookie exports, saved sessions, and signed media URLs out of Git. Use the app only for media you have permission to access and download.

## Development

`app.py` is the bundled entry point. Run `python bundle_video_addons.py` to regenerate it from `build_support/app_base.py`, the add-on sources, and the vendored player. It can run on its own with the Python dependencies installed.

Run the core regression checks from the repository directory:

```sh
python -m unittest test_terabox_addon test_bundle test_proxy_routing -q
```

The browser fixture scripts and `test_video_addons` require an installed Playwright Chromium. Optional upstream proxy routing is configured through `RIPPER_PROXY_URL`. External AI integrations are disabled by default.

The bundled HLS.js player is distributed with its license in `vendor/`.
