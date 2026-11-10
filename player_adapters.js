(() => {
    if (window.__playerDiscovery) return;
    const sources = new Map(), players = new Set(), events = [];
    const observed = new WeakSet(), initiated = new Map();
    function add(value, mime = '', adapter = 'HTML media') {
        if (typeof value !== 'string' || !value.trim() || sources.size >= 500) return;
        try {
            const url = new URL(value, document.baseURI);
            if (!/^https?:$/.test(url.protocol)) return;
            url.hash = '';
            const aliases={hls:'application/vnd.apple.mpegurl',dash:'application/dash+xml',mp4:'video/mp4',webm:'video/webm'};
            mime=typeof mime==='string'?(aliases[mime.toLowerCase()] || mime):'';
            sources.set(url.href, {url:url.href, mime, adapter});
        } catch (_) {}
    }
    function walk(value, adapter, depth = 0, key = '', mime = '', budget = {n:0}) {
        if (++budget.n > 3000 || depth > 12 || !value) return;
        if (typeof value === 'string') {
            if (/^(file|src|url|contentUrl|manifest|hls|dash)$/i.test(key) || /\.(m3u8|mpd|mp4|webm)(?:[?#]|$)/i.test(value)) add(value,mime,adapter);
        } else if (Array.isArray(value)) {
            for (const item of value.slice(0,100)) walk(item,adapter,depth+1,key,mime,budget);
        } else if (typeof value === 'object') {
            const type=typeof value.type==='string'?value.type:mime;
            for (const [name,item] of Object.entries(value).slice(0,100)) {
                if (/drm|license|token|key|thumbnail|image|poster|track/i.test(name)) continue;
                walk(item,adapter,depth+1,name,type,budget);
            }
        }
    }
    function record(kind, video) {
        if (events.length < 150) events.push({event:kind, source:video.currentSrc || video.src || '',
            readyState:video.readyState, networkState:video.networkState,
            errorCode:video.error?.code || 0});
    }
    function sample(attemptPlayback=false) {
        try {
            if (window.videojs?.getPlayers) for (const player of Object.values(window.videojs.getPlayers()).slice(0,30)) {
                if (!player) continue;
                try {
                    players.add('Video.js');
                    if (typeof player.currentSources==='function') walk(player.currentSources(),'Video.js');
                    if (typeof player.currentSrc==='function') add(player.currentSrc(),player.currentType?.() || '', 'Video.js');
                } catch (_) {}
            }
        } catch (_) {}
        if (typeof window.jwplayer === 'function') {
            const ids=[undefined,...Array.from(document.querySelectorAll('.jwplayer[id]')).slice(0,20).map(el=>el.id)];
            for (const id of ids) try {
                const player = window.jwplayer(id);
                if (player && typeof player.getPlaylist==='function') { players.add('JW Player'); walk(player.getPlaylist(),'JW Player'); }
            } catch (_) {}
        }
        for (const name of ['player','shakaPlayer','hls','hlsPlayer','dashPlayer','videoPlayer']) try {
            const player=Object.getOwnPropertyDescriptor(window,name)?.value;
            if (!player || typeof player!=='object') continue;
            if (typeof player.getAssetUri==='function' && typeof player.getVariantTracks==='function') {
                players.add('Shaka'); add(player.getAssetUri(),'','Shaka');
            }
            if (typeof player.getSource==='function' && typeof player.getActiveStream==='function') {
                players.add('dash.js'); add(player.getSource(),'application/dash+xml','dash.js');
            }
            if (typeof player.loadSource==='function' && typeof player.attachMedia==='function') {
                players.add('HLS.js'); add(player.url,'application/vnd.apple.mpegurl','HLS.js');
                for (const level of (player.levels || []).slice(0,50)) walk(level.url,'HLS.js',0,'url','application/vnd.apple.mpegurl');
            }
        } catch (_) {}
        const roots=[document], seen=new Set(); let count=0;
        while(roots.length && count<10000) {
            const root=roots.pop(); if(seen.has(root))continue; seen.add(root);
            const walker=document.createTreeWalker(root,NodeFilter.SHOW_ELEMENT);let el;
            while((el=walker.nextNode()) && count++<10000) {
                if(el.shadowRoot) roots.push(el.shadowRoot);
                if(!/^(VIDEO|AUDIO)$/.test(el.tagName))continue;
                const video=el;
                add(el.currentSrc || el.src,'','HTML media');
                if(!observed.has(el)) {
                    observed.add(el);
                    for(const event of ['loadstart','loadedmetadata','playing','waiting','stalled','error','ended'])
                        el.addEventListener(event,()=>record(event,video));
                    record('observed',el);
                }
                if(attemptPlayback && el.paused && !initiated.has(el) && initiated.size<3) {
                    initiated.set(el,{muted:el.muted}); el.muted=true;
                    try { const promise=el.play(); if(promise?.catch)promise.catch(()=>record('playback-unavailable',video)); }
                    catch(_){record('playback-unavailable',el)}
                }
            }
        }
        return {sources:[...sources.values()],players:[...players],playback:events.slice()};
    }
    Object.defineProperty(window,'__playerDiscovery',{value:{sample, finish(){
        for(const [video,state] of initiated) try{video.pause();video.muted=state.muted}catch(_){}
        initiated.clear();
    }}});
})();
