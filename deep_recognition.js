() => {
    // Optional read-only pass. Does not execute script strings, click controls,
    // change player state or issue additional network requests.
    if (!window.__sourceStudioDeep) {
        const records = new Map(), parsed = new WeakMap();
        const mediaExtension = /\.(?:mp4|webm|mkv|mov|m4v|m3u8|mpd|m4s|ts|mp3|aac|ogg)(?:[?#]|$)/i;
        let parseCount = 0, remainingText = 1000000;
        function add(value, base, source, mime='', explicit=false) {
            if (typeof value!=='string' || !value.trim() || value.length>8192 || records.size>=600) return;
            try {
                const url=new URL(value,base);
                if (!/^https?:$/.test(url.protocol) || /\.(?:drmkey)(?:[?#]|$)/i.test(url.href)) return;
                if (!explicit && !mediaExtension.test(url.href)) return;
                url.hash='';
                records.set(url.href,{url:url.href,source,mime});
            } catch (_) {}
        }
        function json(value,base,source) {
            if (typeof value!=='string' || value.length>150000) return;
            const text=value.trim();
            try {
                const queue=[{value:JSON.parse(text),key:'',depth:0,mime:''}];
                let count=0;
                while(queue.length && count++<3000) {
                    const item=queue.pop(),node=item.value;
                    if(item.depth>15)continue;
                    if(typeof node==='string') {
                        const explicit=/^(contenturl|videourl|audiourl|playbackurl|streamurl|hls|dash|manifesturl)$/i.test(item.key) ||
                            (/^(src|file|url)$/i.test(item.key) && /^(video|audio)\//i.test(item.mime));
                        add(node,base,source,item.mime,explicit);
                    } else if(Array.isArray(node)) {
                        for(const child of node.slice(0,100))queue.push({...item,value:child,depth:item.depth+1});
                    } else if(node && typeof node==='object') {
                        const mime=typeof (node.mimeType||node.type)==='string'?(node.mimeType||node.type):item.mime;
                        for(const [key,child] of Object.entries(node).slice(0,100)) {
                            if(/token|secret|password|license|drm|key|image|poster|thumbnail/i.test(key))continue;
                            queue.push({value:child,key:key.replaceAll('_',''),depth:item.depth+1,mime});
                        }
                    }
                }
            } catch (_) {}
        }
        function inspect(el,base) {
            const config=['data-config','data-setup','data-player','data-sources','data-options'];
            const texts=[];
            for(const attr of config) {
                const value=el.getAttribute(attr);
                if(value && value.length<=150000)texts.push([attr,value]);
            }
            if(el.tagName==='SCRIPT' && el.textContent.length<=150000)texts.push(['script',el.textContent]);
            const signature=texts.map(([name,value])=>name+':'+value).join('\n');
            if(signature && parsed.get(el)!==signature && signature.length<=remainingText && parseCount<300) {
                remainingText-=signature.length;
                parsed.set(el,signature); parseCount++;
                for(const [name,text]of texts) {
                    json(text,base,'deep_config');
                    if(name!=='script' && /^[A-Za-z0-9+/=\s]+$/.test(text) && text.length<50000) {
                        try {json(atob(text),base,'deep_encoded_config')}catch(_){}
                    }
                    // Decode JSON/JS escaped URL syntax without evaluating code.
                    const normalized=text.replace(/\\u002[fF]/g,'/').replace(/\\\//g,'/').replace(/\\u0026/gi,'&');
                    const urls=normalized.match(/https?:\/\/[^\s"'<>\\]{1,2048}/g)||[];
                    for(const url of urls.slice(0,100))add(url,base,'deep_script');
                }
            }
            for(const attr of ['data-hls','data-dash','data-stream','data-video-src','data-mp4']) {
                const value=el.getAttribute(attr);
                const mime=attr==='data-hls'?'application/vnd.apple.mpegurl':attr==='data-dash'?'application/dash+xml':'';
                add(value,base,'deep_attribute',mime,true);
            }
            if(el.tagName==='LINK' && /^(preload|prefetch)$/i.test(el.rel))add(el.href,base,'resource_hint');
            if(el.tagName==='META' && /^(og:video(?::url|:secure_url)?|twitter:player:stream)$/i.test(el.getAttribute('property')||el.name||''))
                add(el.content,base,'media_metadata','',true);
        }
        window.__sourceStudioDeep={snapshot(){
            remainingText=1000000;
            const roots=[document],seen=new Set();let nodes=0;
            while(roots.length && nodes<12000) {
                const root=roots.pop();if(seen.has(root))continue;seen.add(root);
                const walker=document.createTreeWalker(root,NodeFilter.SHOW_ELEMENT);let el;
                while((el=walker.nextNode()) && nodes++<12000) {
                    inspect(el,el.baseURI?.startsWith('http')?el.baseURI:document.baseURI);
                    if(el.shadowRoot)roots.push(el.shadowRoot);
                    if(el.tagName==='TEMPLATE' && el.content)roots.push(el.content);
                }
            }
            for(const entry of performance.getEntriesByType('resource').slice(-1000))add(entry.name,document.baseURI,'deep_resource');
            return {sources:[...records.values()],nodes_scanned:nodes,configs_parsed:parseCount,capped:nodes>=12000||records.size>=600};
        }};
    }
    return window.__sourceStudioDeep.snapshot();
}
