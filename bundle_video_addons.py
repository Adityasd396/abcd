"""Append-only runtime extension bundler; preserves original app code verbatim."""
from pathlib import Path
from base64 import b64encode
from gzip import compress

root=Path(__file__).parent
path=root/'app.py'
text=(root/'build_support'/'app_base.py').read_text(encoding='utf-8')
begin='# BEGIN OPTIONAL VIDEO ADDONS\n'
end='# END OPTIONAL VIDEO ADDONS\n'
source=(root/'video_addons.py').read_text(encoding='utf-8')
source+='\n'+(root/'terabox_addon.py').read_text(encoding='utf-8')
source+='\n'+(root/'terabox_media.py').read_text(encoding='utf-8')
vendor=root/'vendor'
hls=(vendor/'hls-1.7.4.min.js').read_bytes()
license_text=(vendor/'hls-1.7.4.LICENSE').read_bytes()
hls=b'/*! HLS.js v1.7.4\n'+license_text+b'\n*/\n'+hls
source+='\n_TB_HLS_BUNDLE = '+repr(b64encode(compress(hls,mtime=0)))+'\n'
source+='\nTERABOX_PAGE = '+repr((root/'terabox_page.html').read_text(encoding='utf-8'))+'\n'
ui=(root/'video_addons_ui.html').read_text(encoding='utf-8')
block=begin+source+'\nVIDEO_ADDON_UI = '+repr(ui)+'\nHTML_PAGE = HTML_PAGE.replace("</body>", VIDEO_ADDON_UI + "</body>")\n'+end
position=text.index('if __name__ == "__main__":')
path.write_text(text[:position]+block+text[position:],encoding='utf-8')
print('Built the standalone app.py from the included sources.')
