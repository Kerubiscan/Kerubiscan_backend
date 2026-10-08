"""PDF reports rendered from the HTML report, so both formats are identical.

The HTML report is printed by headless Chromium (Playwright), i.e. exactly what a browser prints.
The report contains data coming from the scanned targets (page titles, evidences...), so the
rendering is locked down: JavaScript disabled and no network access (only inline data: URLs,
such as the embedded logo, are loaded).
"""
import logging
from typing import Callable, Optional, Union

logger = logging.getLogger(__name__)

RENDER_TIMEOUT_MS = 120_000


class PdfRenderingError(RuntimeError):
    pass


def html_to_pdf(html: Union[bytes, str]) -> bytes:
    """Renders an HTML document to an A4 PDF with the page settings of its @page/print CSS."""
    if isinstance(html, bytes):
        html = html.decode("utf-8")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        raise PdfRenderingError("Playwright is not installed") from e

    try:
        with sync_playwright() as p:
            # --no-sandbox: the API runs as root in its container; JS is disabled and the page is offline
            browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                context = browser.new_context(java_script_enabled=False, offline=True)
                page = context.new_page()
                page.route("**/*", lambda route: route.abort())
                page.set_default_timeout(RENDER_TIMEOUT_MS)
                page.set_content(html, wait_until="load")
                page.emulate_media(media="print")
                return page.pdf(format="A4", print_background=True, prefer_css_page_size=True)
            finally:
                browser.close()
    except PdfRenderingError:
        raise
    except Exception as e:
        raise PdfRenderingError(f"Chromium could not render the report: {e}") from e


def render_pdf(html: Union[bytes, str], fallback: Optional[Callable[[], bytes]] = None) -> bytes:
    """HTML -> PDF; if Chromium is unavailable, falls back to the legacy ReportLab layout (logged)."""
    try:
        return html_to_pdf(html)
    except PdfRenderingError as e:
        if fallback is None:
            raise
        logger.error(f"{e} — falling back to the legacy PDF layout (different from the HTML report). "
                     f"Check that Chromium is installed in the image: playwright install --with-deps chromium")
        return fallback()
