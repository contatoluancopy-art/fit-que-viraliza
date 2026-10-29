/* Área de membros Fit que Viraliza: fileiras, senha, busca, receitas com vídeo e leitor de PDF (sem framework).
   Base: a área de membros Sabonetes de Sucesso (mesmo cofre AES-GCM, mesmas camadas, mesmo leitor). */
(() => {
  'use strict';
  const D = window.DADOS;
  if (!D) return;

  const html = document.documentElement;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const ico = (nome, extra = '') => `<svg class="ico ${extra}" aria-hidden="true"><use href="#i-${nome}"></use></svg>`;
  const normal = (s) => String(s).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const palavrasBusca = (s) => String(s).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const deB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const paraB64 = (buf) => { const b = new Uint8Array(buf); let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); };
  const quieto = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
  const espera = (ms) => new Promise((r) => setTimeout(r, ms));

  // ---------- guardado no aparelho ----------
  const guarda = {
    ler(k, padrao) { try { const v = localStorage.getItem('fqv.' + k); return v == null ? padrao : JSON.parse(v); } catch (e) { return padrao; } },
    gravar(k, v) { try { localStorage.setItem('fqv.' + k, JSON.stringify(v)); } catch (e) { /* bloqueado */ } },
    apagar(k) { try { localStorage.removeItem('fqv.' + k); } catch (e) { /* idem */ } },
  };
  const favs = new Set(guarda.ler('favs', []));
  const salvarFavs = () => guarda.gravar('favs', [...favs]);

  // ---------- idioma: português (padrão, a venda começa no Brasil) ou espanhol ----------
  let idioma = guarda.ler('idioma', 'pt') === 'es' ? 'es' : 'pt';
  const ES = () => idioma === 'es';
  const t = (pt, es) => (ES() ? es : pt);
  const nomeRec = (it) => (ES() && it.t_es) || it.t;
  const nomeLivro = (l) => (ES() && l.titulo_es) || l.titulo;
  const subLivro = (l) => (ES() && l.sub_es) || l.sub;
  const nomeFileira = (f) => (f.tipo === 'livro' ? nomeLivro(f.livro) : (ES() && f.video.titulo_es) || f.video.titulo);
  const nReceitas = (n) => `${n} ${n === 1 ? t('receita', 'receta') : t('receitas', 'recetas')}`;
  const lidas = guarda.ler('paginas', {});
  let tLidas = 0;
  const salvarLidas = () => { clearTimeout(tLidas); tLidas = setTimeout(() => guarda.gravar('paginas', lidas), 400); };

  const estado = { liberado: html.hasAttribute('data-liberado'), chave: null, segredo: null, cofre: null };

  // ---------- cripto: PBKDF2-SHA256 -> AES-GCM, arquivo = iv(12) + cifra ----------
  async function derivarChave(senhaNormal) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(senhaNormal), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: deB64(D.kdf.salt), iterations: D.kdf.iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }
  const decifrar = (buf, chave) => { const b = new Uint8Array(buf); return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, 12) }, chave, b.slice(12)); };
  async function baixar(url, aoAvancar) {
    const r = await fetch(url);
    if (!r.ok) throw new Error('http ' + r.status);
    const total = Number(r.headers.get('content-length')) || 0;
    if (!aoAvancar || !total || !r.body || !r.body.getReader) return r.arrayBuffer();
    const leitor = r.body.getReader();
    const partes = []; let recebido = 0;
    for (;;) {
      const { done, value } = await leitor.read();
      if (done) break;
      partes.push(value); recebido += value.length;
      aoAvancar(Math.min(1, recebido / total));
    }
    const tudo = new Uint8Array(recebido); let pos = 0;
    for (const p of partes) { tudo.set(p, pos); pos += p.length; }
    return tudo.buffer;
  }
  async function abrirCofre(chave) {
    if (!estado.cofre) estado.cofre = await baixar(D.cofre);
    return JSON.parse(new TextDecoder().decode(await decifrar(estado.cofre, chave)));
  }
  async function guardarChave(chave) {
    guarda.gravar('chave', { k: paraB64(await crypto.subtle.exportKey('raw', chave)), s: D.kdf.salt });
  }
  // o GitHub Pages deixa o navegador guardar o js/dados.js por até 10 min: confere a versão atual antes de abrir o cofre
  async function dadosAtuais() {
    try {
      const r = await fetch('js/dados.json', { cache: 'no-store' });
      if (!r.ok) return;
      const novo = await r.json();
      if (novo.versao && novo.versao !== D.versao) { D.versao = novo.versao; D.kdf = novo.kdf; D.cofre = novo.cofre; estado.cofre = null; }
    } catch (e) { /* sem internet */ }
  }
  async function chaveGuardada() {
    const g = guarda.ler('chave', null);
    if (!g || g.s !== D.kdf.salt) return null;
    try { return await crypto.subtle.importKey('raw', deB64(g.k), 'AES-GCM', false, ['decrypt']); } catch (e) { return null; }
  }
  async function garantirSegredo() {
    if (estado.segredo) return estado.segredo;
    await dadosAtuais();
    if (!estado.chave) estado.chave = await chaveGuardada();
    if (!estado.chave) throw new Error('sem chave');
    estado.segredo = await abrirCofre(estado.chave);
    return estado.segredo;
  }

  // ---------- as receitas ----------
  // cor de cada fileira de vídeo (as dos livros vêm do próprio livro)
  const COR_VIDEO = { cafe: '#C99A06', almoco: '#C2552F', jantar: '#7B5BC4', lanches: '#E2462C', doces: '#D9467E', saladas: '#2E9A5B', bebidas: '#1F86C9', molhos: '#0F7F7A' };
  const fileiras = [
    ...D.livros.map((l) => ({ id: l.id, tipo: 'livro', titulo: l.titulo, cor: l.cor, livro: l, itens: l.itens })),
    ...D.videos.map((v) => ({ id: v.id, tipo: 'video', titulo: v.titulo, cor: COR_VIDEO[v.id] || '#d9472b', video: v, itens: v.itens })),
  ];
  const porId = Object.fromEntries(fileiras.map((f) => [f.id, f]));
  const todas = fileiras.flatMap((f) => f.itens.map((it, i) => ({ f, i, it, chave: `${f.id}:${i}`, busca: palavrasBusca(`${it.t} ${it.t_es || ''} ${f.titulo} ${f.livro?.titulo_es || f.video?.titulo_es || ''}`).join(' ') })));
  const porChave = Object.fromEntries(todas.map((e) => [e.chave, e]));
  const detalhe = (e) => (e.f.tipo === 'livro' ? estado.segredo?.livros?.[e.f.id]?.[e.i] : estado.segredo?.videos?.[e.f.id]?.[e.i]);

  // ---------- cartões ----------
  const cadeado = (extra = '') => `<span class="cadeado ${extra}" aria-hidden="true">${ico('lock-simple-fill', 'fechado')}${ico('lock-simple-open', 'aberto')}</span>`;
  const linhaMeta = (partes) => partes.filter(Boolean).map((p) => esc(p).replace(/ /g, '&nbsp;')).join('&nbsp;<span class="ponto" aria-hidden="true">·</span> ');

  function cartaoRec(e, k = 0) {
    const bloq = !estado.liberado;
    const { f, it } = e;
    const fav = favs.has(e.chave);
    const video = f.tipo === 'video';
    const nome = nomeRec(it);
    const rotulo = `${nome}${it.k ? `, ${it.k} kcal` : ''}${video ? t(', receita em vídeo', ', receta en video') : `${t(', do livro ', ', del libro ')}${nomeFileira(f)}`}${bloq ? t(', liberada com a senha', ', se desbloquea con la contraseña') : ''}`;
    return `<button class="cartao cartao-rec${video ? ' cartao-video' : ''}" type="button" data-chave="${e.chave}" id="c-${e.chave.replace(':', '-')}"${bloq ? ' data-bloqueado' : ''} style="--cor:${f.cor};--i:${k}" aria-label="${esc(rotulo)}">
      <span class="cartao-arte rec-arte">
        ${it.foto ? `<img src="${esc(it.foto)}" alt="" width="480" height="600" loading="lazy" decoding="async">` : '<span class="rec-fundo" aria-hidden="true"></span>'}
        ${!it.foto && it.th ? `<img class="rec-thumb" src="${esc(it.th)}" alt="" width="360" height="450" loading="lazy" decoding="async" onerror="this.remove()">` : ''}
        <span class="rec-nome">${esc(nome)}</span>
        ${it.k ? `<span class="rec-kcal">${it.k} kcal</span>` : ''}
        ${video ? `<span class="rec-play" aria-hidden="true">${ico('play-fill')}</span>` : ''}
        ${fav ? `<span class="rec-fav" aria-hidden="true">${ico('heart-fill')}</span>` : ''}
        ${cadeado('cadeado-mini')}
      </span>
    </button>`;
  }
  function capaLivro(l, extra = '') {
    return l.capa
      ? `<img src="${esc(l.capa)}" alt="" width="420" height="560" loading="lazy" decoding="async">`
      : `<span class="capa-texto ${extra}" style="--cor:${l.cor};--cor2:${l.cor2 || '#fff'}"><small>Fit que Viraliza</small><b>${esc(nomeLivro(l))}</b><i>${t('30 receitas', '30 recetas')}</i></span>`;
  }
  function cartaoLivro(l) {
    const bloq = !estado.liberado;
    const n = lidas[l.id];
    return `<button class="cartao cartao-livro" type="button" data-pdf="${l.id}" id="c-livro-${l.id}"${bloq ? ' data-bloqueado' : ''} aria-label="${esc(`${t('Livro', 'Libro')} ${Number(l.num)}: ${nomeLivro(l)}, PDF${bloq ? t(', liberado com a senha', ', se desbloquea con la contraseña') : ''}`)}">
      <span class="cartao-arte">${capaLivro(l)}<span class="livro-num" aria-hidden="true">${t('Livro', 'Libro')} ${Number(l.num)}</span>${cadeado()}
      ${!bloq && n > 1 ? `<span class="progresso"><i style="--p:${Math.max(3, Math.round((n / 64) * 100))}%"></i></span>` : ''}</span>
    </button>`;
  }
  function posterPdf(p) {
    const l = D.livros.find((x) => x.id === p.id);
    const bloq = !estado.liberado;
    const n = lidas[p.id];
    const meta = !bloq && n > 1 ? t(`Página ${n} de ${p.paginas}`, `Página ${n} de ${p.paginas}`) : t(`${p.paginas} páginas`, `${p.paginas} páginas`);
    const nome = nomeLivro(l);
    return `<button class="cartao cartao-poster" type="button" data-pdf="${p.id}" id="c-pdf-${p.id}"${bloq ? ' data-bloqueado' : ''} aria-label="${esc(`${t('Ler o livro', 'Leer el libro')} ${nome}, ${meta}${bloq ? t(', liberado com a senha', ', se desbloquea con la contraseña') : ''}`)}">
      <span class="cartao-arte">${capaLivro(l)}${bloq ? `<span class="rotulo-bloqueio" aria-hidden="true">${ico('lock-simple-fill')}<span>${t('Liberado com a&nbsp;senha', 'Se desbloquea con la&nbsp;contraseña')}</span></span>` : ''}
      ${!bloq && n > 1 ? `<span class="progresso"><i style="--p:${Math.max(3, Math.round((n / p.paginas) * 100))}%"></i></span>` : ''}</span>
      <span class="cartao-titulo">${esc(nome)}</span>
      <span class="cartao-meta">${esc(meta)}</span>
    </button>`;
  }

  // ---------- fileiras ----------
  function montarFileiras() {
    $('#livros').innerHTML = D.livros.map((l) => `<section class="fileira fileira-livro" id="f-${l.id}" aria-labelledby="t-${l.id}" style="--cor:${l.cor}">
        <div class="fileira-topo"><h2 id="t-${l.id}"><span class="fileira-num">${t('Livro', 'Libro')} ${Number(l.num)}</span> ${esc(nomeLivro(l))}</h2><p class="fileira-info">${esc(subLivro(l))}</p></div>
        <div class="trilho-caixa"><div class="trilho trilho-livro" id="trilho-${l.id}"></div></div>
      </section>`).join('');
    $('#videos').innerHTML = D.videos.map((v) => `<section class="fileira" id="f-${v.id}" aria-labelledby="t-${v.id}">
        <div class="fileira-topo"><h2 id="t-${v.id}">${esc((ES() && v.titulo_es) || v.titulo)}</h2><p class="fileira-info">${v.itens.length} ${t('receitas em vídeo', 'recetas en video')}</p></div>
        <div class="trilho-caixa"><div class="trilho trilho-rec" id="trilho-${v.id}"></div></div>
      </section>`).join('');
  }
  function renderFileiras() {
    $('#trilho-pdfs').innerHTML = D.pdfs.map(posterPdf).join('');
    for (const l of D.livros) {
      const f = porId[l.id];
      $(`#trilho-${l.id}`).innerHTML = cartaoLivro(l) + f.itens.map((_, i) => cartaoRec(porChave[`${l.id}:${i}`], i)).join('');
    }
    for (const v of D.videos) $(`#trilho-${v.id}`).innerHTML = porId[v.id].itens.map((_, i) => cartaoRec(porChave[`${v.id}:${i}`], i)).join('');
    const lista = [...favs].map((c) => porChave[c]).filter(Boolean);
    $('#fileira-favoritas').hidden = !lista.length;
    $('#info-fav').textContent = lista.length ? nReceitas(lista.length) : '';
    $('#trilho-favoritas').innerHTML = lista.map((e, k) => cartaoRec(e, k)).join('');
    $$('.trilho-caixa').forEach((c) => c._setas?.());
  }
  const botao = (tipo, icone, texto, acao) => `<button class="botao botao-${tipo}" type="button" data-acao="${acao}">${ico(icone)}<span>${esc(texto)}</span></button>`;
  function renderDestaque(animar) {
    const total = todas.length;
    $('#destaque-meta').innerHTML = linhaMeta([`${total} ${t('receitas', 'recetas')}`, t('10 livros em PDF', '10 libros en PDF'), t('modo Shorts', 'modo Shorts')]);
    $('#selo').setAttribute('aria-label', estado.liberado ? t('Tudo liberado. Ir para as receitas', 'Todo desbloqueado. Ir a las recetas') : t('Liberar as receitas', 'Desbloquear las recetas'));
    const acoes = $('#destaque-acoes');
    if (estado.liberado) {
      $('#destaque-texto').textContent = t('Comece por um livro ou busque pelo que você tem na geladeira. Toque no coração pra guardar as favoritas.',
        'Empieza por un libro o busca por lo que tienes en el refrigerador. Toca el corazón para guardar tus favoritas.');
      acoes.innerHTML = botao('principal', 'shuffle', t('Explorar receitas', 'Explorar recetas'), 'explorar') + botao('secundario', 'book-open-text', t('Abrir o primeiro livro', 'Abrir el primer libro'), 'livro1');
    } else {
      $('#destaque-texto').textContent = t('Digite a senha que chegou no seu WhatsApp pra abrir as receitas, os vídeos e os 10 livros.',
        'Escribe la contraseña que llegó a tu WhatsApp para abrir las recetas, los videos y los 10 libros.');
      acoes.innerHTML = botao('principal', 'lock-simple-open', t('Digitar a senha', 'Escribir la contraseña'), 'liberar') + botao('secundario', 'list-bullets', t('Ver as receitas', 'Ver las recetas'), 'ver');
    }
    if (animar && !quieto()) { acoes.classList.remove('trocando'); void acoes.offsetWidth; acoes.classList.add('trocando'); }
  }
  function renderTudo() { renderDestaque(); renderFileiras(); if (buscaAtiva()) renderBusca(); }

  // a senha certa: os cartões na tela acendem um por um, o resto acende junto
  function liberar(animar) {
    estado.liberado = true;
    html.setAttribute('data-liberado', '');
    if (!animar || quieto()) { renderTudo(); aviso(t('Tudo liberado. Bom proveito!', 'Todo desbloqueado. ¡Buen provecho!')); return; }
    const selo = $('#selo');
    selo.classList.remove('estalo'); void selo.offsetWidth; selo.classList.add('estalo');
    renderDestaque(true);
    const acender = (c) => { c.removeAttribute('data-bloqueado'); const r = c.getAttribute('aria-label'); if (r) c.setAttribute('aria-label', r.replace(/, (liberad[oa] com a senha|se desbloquea con la contraseña)/, '')); };
    const cartoes = $$('.cartao[data-bloqueado]');
    const naTela = cartoes.filter((c) => { const r = c.getBoundingClientRect(); return r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth; });
    const passo = Math.min(90, 1200 / Math.max(1, naTela.length));
    naTela.forEach((c, k) => setTimeout(() => acender(c), 200 + k * passo));
    const depois = 200 + naTela.length * passo + 200;
    setTimeout(() => { renderFileiras(); if (buscaAtiva()) renderBusca(); aviso(t('Tudo liberado. Bom proveito!', 'Todo desbloqueado. ¡Buen provecho!')); }, depois);
  }

  // ---------- busca ----------
  const filtro = { kcal: 0, fav: false };
  const buscaAtiva = () => Boolean($('#busca-texto').value.trim() || filtro.kcal || filtro.fav);
  function renderBusca() {
    const q = palavrasBusca($('#busca-texto').value);
    const ativa = buscaAtiva();
    $('#busca-limpar').hidden = !$('#busca-texto').value;
    $('#grupo-fileiras').hidden = ativa;
    $('#busca-grade').hidden = !ativa;
    if (!ativa) { $('#busca-info').textContent = ''; $('#busca-grade').innerHTML = ''; return; }
    const achou = todas.filter((e) => q.every((w) => e.busca.includes(w))
      && (!filtro.kcal || (e.it.k && e.it.k <= filtro.kcal)) && (!filtro.fav || favs.has(e.chave)));
    $('#busca-info').textContent = achou.length ? nReceitas(achou.length) : t('Nenhuma receita com esse nome. Tente outra palavra, como frango, bolo ou ovo.', 'Ninguna receta con ese nombre. Prueba otra palabra, como pollo, pastel o huevo.');
    $('#busca-grade').innerHTML = achou.map((e, k) => cartaoRec(e, Math.min(k, 12))).join('');
  }
  let tBusca = 0;
  $('#busca-texto').addEventListener('input', () => { clearTimeout(tBusca); tBusca = setTimeout(renderBusca, 120); });
  $('#busca-limpar').addEventListener('click', () => { $('#busca-texto').value = ''; renderBusca(); $('#busca-texto').focus(); });
  $('#filtros').addEventListener('click', (e) => {
    const b = e.target.closest('.filtro');
    if (!b) return;
    if (b.dataset.fav) { filtro.fav = !filtro.fav; b.setAttribute('aria-pressed', String(filtro.fav)); }
    else {
      const v = Number(b.dataset.kcal);
      filtro.kcal = filtro.kcal === v ? 0 : v;
      $$('.filtro[data-kcal]').forEach((x) => x.setAttribute('aria-pressed', String(Number(x.dataset.kcal) === filtro.kcal)));
    }
    renderBusca();
  });
  function irPraBusca() {
    $('#busca').scrollIntoView({ behavior: quieto() ? 'auto' : 'smooth', block: 'start' });
    setTimeout(() => $('#busca-texto').focus({ preventScroll: true }), quieto() ? 0 : 350);
  }

  // ---------- camadas com o botão voltar do celular ----------
  const camadas = { liberar: $('#camada-liberar'), receita: $('#camada-receita'), leitor: $('#camada-leitor'), explorar: $('#camada-explorar') };
  Object.values(camadas).forEach((c) => { const d = $('[role="dialog"]', c); if (d) d.tabIndex = -1; });
  const pilha = [];
  const aberta = (nome) => pilha.some((p) => p.nome === nome);
  function atualizarInert() {
    const topo = pilha[pilha.length - 1];
    [$('#topo'), $('#conteudo'), $('.rodape'), $('.pular')].forEach((x) => { if (x) x.inert = Boolean(topo); });
    Object.values(camadas).forEach((c) => { c.inert = Boolean(topo) && c !== topo.el; });
  }
  function abrirCamada(nome, { aoFechar, foco } = {}) {
    const el = camadas[nome];
    const ativo = document.activeElement;
    const item = { nome, el, aoFechar, anterior: ativo, idAnterior: (ativo && ativo.id) || '' };
    el.hidden = false;
    el.style.zIndex = String(60 + pilha.length);
    void el.offsetWidth;
    el.classList.add('aberta');
    pilha.push(item);
    document.body.classList.add('travado');
    atualizarInert();
    history.pushState({ camada: nome }, '');
    const alvo = (foco && $(foco, el)) || $('[role="dialog"]', el);
    alvo?.focus({ preventScroll: true });
  }
  function fecharTopo() { if (pilha.length) history.back(); }
  function fecharItem(item) {
    item.el.classList.remove('aberta');
    item.aoFechar?.();
    setTimeout(() => { if (!item.el.classList.contains('aberta')) { item.el.hidden = true; item.el.style.zIndex = ''; } }, 360);
    if (!pilha.length) document.body.classList.remove('travado');
    atualizarInert();
    const volta = (item.anterior && document.contains(item.anterior) && item.anterior) || (item.idAnterior && document.getElementById(item.idAnterior));
    if (volta) volta.focus({ preventScroll: true });
  }
  window.addEventListener('popstate', () => { const item = pilha.pop(); if (item) fecharItem(item); });
  document.addEventListener('keydown', (e) => {
    if (!pilha.length) return;
    if (e.key === 'Escape') { e.preventDefault(); fecharTopo(); return; }
    if (e.key !== 'Tab') return;
    const caixa = pilha[pilha.length - 1].el;
    const foc = $$('button:not([disabled]), a[href], input, [tabindex]:not([tabindex="-1"])', caixa).filter((x) => x.offsetParent !== null && !x.closest('[inert]'));
    if (!foc.length) return;
    const pri = foc[0], ult = foc[foc.length - 1];
    const i = foc.indexOf(document.activeElement);
    if (i === -1) { e.preventDefault(); (e.shiftKey ? ult : pri).focus(); return; }
    if (e.shiftKey && i === 0) { e.preventDefault(); ult.focus(); }
    else if (!e.shiftKey && i === foc.length - 1) { e.preventDefault(); pri.focus(); }
  });
  document.addEventListener('click', (e) => { if (e.target.closest('[data-fechar]')) fecharTopo(); });

  // ---------- senha ----------
  let depoisDaSenha = null;
  function abrirLiberar(depois) {
    depoisDaSenha = depois || null;
    if (aberta('liberar')) return;
    $('#senha-form').removeAttribute('data-erro');
    $('#senha-erro').textContent = '';
    abrirCamada('liberar', { foco: matchMedia('(hover: hover) and (pointer: fine)').matches ? '#senha' : null });
  }
  function erroSenha(txt) {
    const form = $('#senha-form');
    form.setAttribute('data-erro', '');
    $('#senha-erro').textContent = txt;
    if (!quieto()) { form.classList.remove('tremendo'); void form.offsetWidth; form.classList.add('tremendo'); }
  }
  $('#senha-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const campo = $('#senha');
    const n = normal(campo.value);
    if (!n) { erroSenha(t('Digite a senha que você recebeu no WhatsApp.', 'Escribe la contraseña que recibiste por WhatsApp.')); campo.focus(); return; }
    const enviar = $('#senha-enviar');
    enviar.disabled = true; enviar.classList.add('carregando');
    $('#senha-erro').textContent = '';
    $('#senha-form').removeAttribute('data-erro');
    try {
      await dadosAtuais();
      const chave = await derivarChave(n);
      const segredo = await abrirCofre(chave);
      estado.chave = chave; estado.segredo = segredo;
      await guardarChave(chave);
      campo.value = ''; campo.blur();
      fecharTopo();
      await espera(quieto() ? 0 : 340);
      liberar(true);
      const depois = depoisDaSenha; depoisDaSenha = null;
      if (depois) setTimeout(depois, quieto() ? 0 : 700);
    } catch (err) {
      if (err && err.name === 'OperationError') erroSenha(t('Essa senha não confere. Confira a mensagem do WhatsApp e digite de novo.', 'Esa contraseña no coincide. Revisa el mensaje de WhatsApp y escríbela de nuevo.'));
      else erroSenha(t('Não consegui conferir agora. Veja se a internet está ligada e tente de novo.', 'No pude verificarla ahora. Revisa tu conexión a internet e inténtalo de nuevo.'));
      campo.focus(); campo.select();
    } finally {
      enviar.disabled = false; enviar.classList.remove('carregando');
    }
  });

  // ---------- página da receita ----------
  let igCarga = null;
  function carregarInstagram() {
    if (window.instgrm) return Promise.resolve(window.instgrm);
    if (!igCarga) {
      igCarga = new Promise((res, rej) => {
        const s = document.createElement('script');
        s.async = true; s.src = 'https://www.instagram.com/embed.js';
        s.onload = () => res(window.instgrm);
        s.onerror = () => { igCarga = null; rej(new Error('instagram')); };
        document.head.append(s);
      });
    }
    return igCarga;
  }
  // Só o vídeo. O player do embed oficial (gerado pelo embed.js) fica dentro de uma moldura do tamanho exato do vídeo (4:5, medido em
  // 29/10/2026): o cabeçalho de 54 px e as curtidas, comentários e botões ficam pra fora. O vídeo toca ali mesmo.
  // O crédito do criador vai escrito embaixo, com o link pro post. Se o Instagram mudar o embed, ajustar o top e a altura
  // do iframe em .ig-moldura (css/receitas.css).
  const arroba = (p) => String(p || '').replace(/^dr-riqmonteiro$/, 'dr.riqmonteiro');
  const moldura = (code, perfil, dur) => `<div class="video-caixa" data-dur="${Number(dur) || 0}">
      <div class="ig-moldura"><blockquote class="instagram-media" data-instgrm-permalink="https://www.instagram.com/p/${esc(code)}/?utm_source=ig_embed" data-instgrm-version="14"></blockquote></div>
      <p class="ig-link">${ico('instagram-logo')}<span>${perfil ? `${t('Vídeo de', 'Video de')} @${esc(arroba(perfil))}` : t('Vídeo do Instagram', 'Video de Instagram')}</span></p>
    </div>`;
  // o script oficial do Instagram transforma cada blockquote no player; sem ele, tocar no vídeo abre o Instagram
  function processarIg() { carregarInstagram().then((ig) => ig?.Embeds?.process()).catch(() => {}); }
  // A pessoa nunca sai do site: cada player que o embed.js cria ganha sandbox sem allow-popups e sem
  // allow-top-navigation, e recarrega uma vez pra valer. O vídeo continua tocando ali; o "Assistir no Instagram"
  // deixa de abrir aba (em vídeo que o Instagram não toca fora do app, o toque simplesmente não faz nada).
  const CAIXA = 'allow-scripts allow-same-origin allow-presentation';
  // recarrega o player SEM criar entrada no histórico (senão o botão voltar do celular volta o player em vez de
  // fechar a tela). location.replace numa URL um pouco diferente (o parâmetro r) força o recarregamento.
  function recarregarIframe(f) {
    const [base, hash = ''] = f.src.split('#');
    const url = base.replace(/([?&])r=\d+&?/, '$1').replace(/[?&]$/, '') + (base.includes('?') ? '&' : '?') + 'r=' + Date.now() + (hash ? '#' + hash : '');
    try { f.contentWindow.location.replace(url); } catch (e) { f.src = url; }
  }
  new MutationObserver(() => {
    for (const f of document.querySelectorAll('iframe.instagram-media:not([data-caixa])')) {
      f.dataset.caixa = '1';
      f.setAttribute('sandbox', CAIXA);
      f.setAttribute('allow', 'autoplay; encrypted-media; fullscreen; picture-in-picture');
      recarregarIframe(f);
    }
  }).observe(document.body, { childList: true, subtree: true });
  // ---------- só um vídeo tocando por vez ----------
  // O site não manda no player do Instagram, mas recarregar o iframe para o vídeo e volta pro início.
  // Tocar no vídeo leva o foco pro iframe: a página perde o foco e o iframe vira o elemento ativo. Assim dá pra saber
  // que a pessoa tocou, quando foi, e (com a duração do vídeo) se o toque foi depois do fim, no "Assistir no Instagram".
  function reiniciarVideo(caixa) {
    if (!caixa || !caixa.dataset.tocado) return;
    for (const f of caixa.querySelectorAll('iframe.instagram-media')) recarregarIframe(f);
    delete caixa.dataset.tocado;
    delete caixa.dataset.desde;
  }
  function pararVideosEm(raiz) { $$('.video-caixa[data-tocado], .legenda-caixa[data-tocado]', raiz).forEach(reiniciarVideo); }
  window.addEventListener('blur', () => setTimeout(() => {
    const f = document.activeElement;
    if (!f || f.tagName !== 'IFRAME') return;
    const caixa = f.closest('.video-caixa, .legenda-caixa');
    if (!caixa) return;
    const agora = Date.now();
    const dur = Number(caixa.dataset.dur) || 0;
    if (caixa.dataset.tocado && dur && agora - Number(caixa.dataset.desde || 0) >= (dur - 0.8) * 1000) {
      // o vídeo já tinha acabado: o toque foi no "Assistir no Instagram", que não abre nada aqui. Recomeça.
      reiniciarVideo(caixa);
    } else if (!caixa.dataset.tocado) {
      caixa.dataset.tocado = '1';
      caixa.dataset.desde = String(agora);
      // outro vídeo que estava tocando para (no Explorar e na receita)
      $$('.video-caixa[data-tocado], .legenda-caixa[data-tocado]').forEach((c) => { if (c !== caixa) reiniciarVideo(c); });
    }
    // devolve o foco pra página, pra perceber o próximo toque no vídeo
    f.blur();
  }, 0));

  // vídeo que o Instagram só deixa tocar no app dele (toca = false, conferido por ferramentas/toca_no_site.py):
  // em vez de um play que não responde, a capa parada e um aviso. Nenhum link pra fora.
  function videoOuCapa(e, r) {
    if (r.toca !== false) return moldura(r.ig, r.perfil, r.dur);
    const url = `https://www.instagram.com/p/${esc(r.ig)}/`;
    return `<div class="video-caixa">
      <a class="ig-moldura ig-parado" href="${url}" target="_blank" rel="noopener" aria-label="${t('Assistir este vídeo no Instagram', 'Ver este video en Instagram')}">
        ${e.it.th ? `<img src="${esc(e.it.th)}" alt="" width="360" height="450" decoding="async">` : ''}
        <span class="ig-abrir">${ico('instagram-logo')}<span>${t('Assistir no Instagram', 'Ver en Instagram')}</span></span>
      </a>
      <p class="ig-link">${ico('info')}<span>${t(`O Instagram só deixa este vídeo tocar no app dele. Vídeo de @${esc(arroba(r.perfil))}.`, `Instagram solo permite reproducir este video en su app. Video de @${esc(arroba(r.perfil))}.`)}</span></p>
    </div>`;
  }

  // a legenda completa (onde está a receita das extras) só aparece quando a pessoa pede
  const legendaIg = (code) => `<blockquote class="instagram-media" data-instgrm-permalink="https://www.instagram.com/p/${esc(code)}/?utm_source=ig_embed" data-instgrm-version="14" data-instgrm-captioned>
      <span>${t('Carregando a receita…', 'Cargando la receta…')}</span></blockquote>`;
  const listaIngr = (r) => r.ingredientes.map((g) => `${r.ingredientes.length > 1 || g.grupo ? `<h4 class="ingr-grupo">${esc(g.grupo)}</h4>` : ''}<ul class="ingr">${g.itens.map((i) => `<li><b>${esc(i.qtd)}</b> ${esc(i.item)}${i.peso ? ` <i>(${esc(i.peso)})</i>` : ''}</li>`).join('')}</ul>`).join('');
  const chip = (icone, txt) => `<span class="chip">${ico(icone)}${esc(txt)}</span>`;
  function botaoFav(chave) {
    const on = favs.has(chave);
    return `<button class="botao botao-secundario botao-fav" type="button" data-acao="fav" data-chave="${chave}" aria-pressed="${on}">${ico(on ? 'heart-fill' : 'heart')}<span>${on ? 'Favorita' : t('Favoritar', 'Guardar en favoritas')}</span></button>`;
  }
  function paginaLivro(e, r0) {
    const l = e.f.livro;
    const r = ES() && r0.es ? { ...r0, ...r0.es } : r0;
    const m = r.macros;
    const s = r.armazenamento;
    return `<header class="rec-topo" style="--cor:${l.cor}">
        ${e.it.foto ? `<img class="rec-topo-foto" src="${esc(e.it.foto)}" alt="">` : ''}
        <button class="fechar" type="button" data-fechar aria-label="${t('Fechar', 'Cerrar')}">${ico('x')}</button>
        <p class="rec-de">${t('Livro', 'Libro')} ${Number(l.num)} · ${esc(nomeLivro(l))} · ${t('receita', 'receta')} ${e.i + 1}</p>
        <h2 class="pagina-titulo" id="receita-titulo">${esc(nomeRec(e.it))}</h2>
        <p class="rec-chamada">${esc(r.chamada)}</p>
        <div class="macros">
          <div><b>${m.kcal}</b><span>kcal</span></div><div><b>${m.proteina}g</b><span>${t('proteína', 'proteína')}</span></div><div><b>${m.carbo}g</b><span>${t('carbo', 'carbohidratos')}</span></div><div><b>${m.gordura}g</b><span>${t('gordura', 'grasa')}</span></div>
        </div>
        <p class="rec-porcao">${t('Por porção', 'Por porción')}: ${esc(r.porcao)}</p>
      </header>
      <div class="pagina-corpo rec-corpo">
        <div class="chips">${chip('fork-knife', `${t('Rende', 'Rinde')} ${r.rendimento}`)}${chip('timer', r.tempo)}${chip('chef-hat', r.dificuldade)}</div>
        <div class="pagina-acoes">${r.ig && r.toca !== false ? botao('principal', 'play-fill', t('Ver o vídeo', 'Ver el video'), 'ver-video') : ''}${botaoFav(e.chave)}</div>
        <div class="rec-grade">
          <div class="rec-texto">
            <section class="bloco"><h3>${ico('basket')}${t('Ingredientes', 'Ingredientes')}</h3>${listaIngr(r)}
              ${r.sem_whey ? `<p class="sem-whey"><b>${ico('swap')}${t('Sem whey?', '¿Sin whey?')}</b> ${esc(r.sem_whey)}</p>` : ''}</section>
            <section class="bloco"><h3>${ico('list-numbers')}${t('Modo de preparo', 'Preparación')}</h3>
              <ol class="passos-rec">${r.passos.map((p, k) => `<li><span class="passo-n">${k + 1}</span><div><b>${esc(p.titulo)}</b><p>${esc(p.texto)}</p></div></li>`).join('')}</ol></section>
            <section class="bloco bloco-dica"><h3>${ico('lightbulb-filament')}${t('Dica', 'Consejo')}</h3><p>${esc(r.dica)}</p></section>
            <section class="bloco"><h3>${ico('clock-countdown')}${t('Melhor horário', 'Mejor momento')}</h3><p><b>${esc(r.horario.quando)}</b>, ${esc(r.horario.faixa)}. ${esc(r.horario.porque)}</p></section>
            <section class="bloco"><h3>${ico('snowflake')}${t('Geladeira e freezer', 'Refrigerador y congelador')}</h3><p><b>${t('Geladeira', 'Refrigerador')}:</b> ${esc(s.geladeira)} · <b>${t('Freezer', 'Congelador')}:</b> ${esc(s.freezer)}</p><p>${esc(s.reaquecer)}</p></section>
            <section class="bloco"><h3>${ico('globe-hemisphere-west')}${t('De onde vem', 'De dónde viene')}: ${esc(r.origem.lugar)}</h3><p>${esc(r.origem.texto)}</p></section>
          </div>
          ${r.ig ? `<aside class="rec-video" id="rec-video"><h3>${ico('play-circle')}${t('O vídeo que inspirou a receita', 'El video que inspiró la receta')}</h3><p class="video-nota">${t('A nossa versão pode trocar ingredientes e quantidades. Siga os valores escritos aqui.', 'Nuestra versión puede cambiar ingredientes y cantidades. Sigue los valores escritos aquí. El video puede estar en portugués o en inglés.')}</p>${videoOuCapa(e, r)}</aside>` : ''}
        </div>
      </div>`;
  }
  function paginaVideo(e, r0) {
    // receita escrita por nós a partir da legenda (r.receita); em espanhol, r.receita.es
    const rr = r0.receita ? (ES() && r0.receita.es ? { ...r0.receita, ...r0.receita.es } : r0.receita) : null;
    const meta = rr ? [rr.rendimento && chip('fork-knife', `${t('Rende', 'Rinde')} ${rr.rendimento}`), rr.tempo && chip('timer', rr.tempo)].filter(Boolean).join('') : '';
    const texto = rr ? `<div class="rec-texto">
            <section class="bloco"><h3>${ico('basket')}${t('Ingredientes', 'Ingredientes')}</h3>${listaIngr(rr)}</section>
            <section class="bloco"><h3>${ico('list-numbers')}${t('Modo de preparo', 'Preparación')}</h3>
              <ol class="passos-rec">${rr.passos.map((p, k) => `<li><span class="passo-n">${k + 1}</span><div>${p.titulo ? `<b>${esc(p.titulo)}</b>` : ''}<p>${esc(p.texto)}</p></div></li>`).join('')}</ol></section>
            ${rr.dica ? `<section class="bloco bloco-dica"><h3>${ico('lightbulb-filament')}${t('Dica', 'Consejo')}</h3><p>${esc(rr.dica)}</p></section>` : ''}
            <p class="video-nota">${t(`Receita escrita por nós a partir do vídeo de @${esc(arroba(r0.perfil))}.`, `Receta escrita por nosotros a partir del video de @${esc(arroba(r0.perfil))}.`)}</p>
          </div>` : `<div class="rec-texto">
            <p class="pagina-texto">${t(`Os ingredientes e o modo de preparo estão na legenda do post, escritos por @${esc(arroba(r0.perfil))}.`, `Los ingredientes y la preparación están en la descripción de la publicación, escritos por @${esc(arroba(r0.perfil))}.`)}</p>
            <div class="pagina-acoes"><button class="botao botao-principal" type="button" data-acao="legenda" data-ig="${esc(r0.ig)}">${ico('list-bullets')}<span>${t('Mostrar a receita escrita', 'Mostrar la receta escrita')}</span></button></div>
            <div class="legenda-caixa" id="legenda-caixa" hidden></div>
          </div>`;
    return `<header class="rec-topo rec-topo-video" style="--cor:${e.f.cor}">
        <button class="fechar" type="button" data-fechar aria-label="${t('Fechar', 'Cerrar')}">${ico('x')}</button>
        <p class="rec-de">${t('Receita em vídeo', 'Receta en video')} · ${esc(nomeFileira(e.f))}</p>
        <h2 class="pagina-titulo" id="receita-titulo">${esc(nomeRec(e.it))}</h2>
      </header>
      <div class="pagina-corpo rec-corpo">
        ${meta ? `<div class="chips">${meta}</div>` : ''}
        <div class="pagina-acoes">${rr ? botao('principal', 'play-fill', t('Ver o vídeo', 'Ver el video'), 'ver-video') : ''}${botaoFav(e.chave)}</div>
        <div class="rec-grade">
          ${texto}
          <aside class="rec-video" id="rec-video"><h3>${ico('play-circle')}${t('O vídeo', 'El video')}</h3>${videoOuCapa(e, r0)}</aside>
        </div>
      </div>`;
  }

  let receitaAberta = null;
  async function abrirReceita(chave) {
    const e = porChave[chave];
    if (!e) return;
    if (!estado.liberado) { abrirLiberar(() => abrirReceita(chave)); return; }
    try { await garantirSegredo(); } catch (err) { aviso(t('Não consegui abrir agora. Confira a internet e tente de novo.', 'No pude abrirlo ahora. Revisa tu conexión e inténtalo de nuevo.')); return; }
    const r = detalhe(e);
    if (!r) { aviso(t('Não achei essa receita.', 'No encontré esa receta.')); return; }
    receitaAberta = chave;
    const pag = $('#pagina-receita');
    pararVideosEm(pag);
    pag.innerHTML = e.f.tipo === 'livro' ? paginaLivro(e, r) : paginaVideo(e, r);
    pag.scrollTop = 0;
    if (!aberta('receita')) abrirCamada('receita', { foco: '.fechar', aoFechar: () => { receitaAberta = null; pararVideosEm($('#pagina-receita')); } });
    if (r.ig) processarIg();
  }
  $('#pagina-receita').addEventListener('click', (ev) => {
    const b = ev.target.closest('[data-acao]');
    if (!b) return;
    if (b.dataset.acao === 'legenda') {
      const caixa = $('#legenda-caixa');
      caixa.hidden = false;
      caixa.innerHTML = legendaIg(b.dataset.ig);
      caixa.dataset.dur = $('.video-caixa', $('#pagina-receita'))?.dataset.dur || '0';
      b.remove();
      carregarInstagram().then((ig) => ig?.Embeds?.process()).catch(() => {
        caixa.innerHTML = `<p class="ig-link">${t('A legenda não abriu agora. Confira a internet e tente de novo.', 'La descripción no se abrió ahora. Revisa tu conexión e inténtalo de nuevo.')}</p>`;
      });
      return;
    }
    if (b.dataset.acao === 'ver-video') $('#rec-video')?.scrollIntoView({ behavior: quieto() ? 'auto' : 'smooth', block: 'start' });
    else if (b.dataset.acao === 'fav') {
      const c = b.dataset.chave;
      if (favs.has(c)) favs.delete(c); else favs.add(c);
      salvarFavs();
      b.outerHTML = botaoFav(c);
      aviso(favs.has(c) ? t('Guardada nas favoritas', 'Guardada en favoritas') : t('Tirada das favoritas', 'Quitada de favoritas'));
      renderFileiras();
      if (buscaAtiva()) renderBusca();
    }
  });

  // ---------- explorar: feed vertical tipo Shorts, receitas aleatórias de todas as áreas ----------
  const feed = $('#feed');
  const EX = { fila: [], pos: 0, obs: null, n: 0 };
  const embaralhar = (a) => { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };
  // sem repetir a mesma receita até passar por todas; acabou, embaralha de novo e continua
  // só entra vídeo que o Instagram deixa tocar dentro do site (toca = false: só toca no app dele)
  function novaFila() { EX.fila = embaralhar(todas.filter((e) => detalhe(e)?.ig && detalhe(e).toca !== false)); EX.pos = 0; }
  const esperaVideo = () => `<div class="short-espera">${ico('play-circle')}<span>${t('Carregando o vídeo…', 'Cargando el video…')}</span></div>`;
  function shortHtml(e) {
    const r = detalhe(e);
    const livro = e.f.tipo === 'livro';
    const de = livro ? `${t('Livro', 'Libro')} ${Number(e.f.livro.num)} · ${nomeFileira(e.f)}` : nomeFileira(e.f);
    const fav = favs.has(e.chave);
    const nome = nomeRec(e.it);
    return `<article class="short" data-chave="${e.chave}" data-ig="${esc(r.ig)}" data-perfil="${esc(r.perfil || '')}" data-dur="${Number(r.dur) || 0}" style="--cor:${e.f.cor}" aria-label="${esc(nome)}">
      <div class="short-info">
        <span class="short-de">${esc(de)}</span>
        <h3>${esc(nome)}</h3>
        <p class="short-macros">${livro ? t(`${r.macros.kcal} kcal · ${r.macros.proteina} g de proteína por porção`, `${r.macros.kcal} kcal · ${r.macros.proteina} g de proteína por porción`) : (r.receita ? t(`Receita escrita no site · vídeo de @${esc(arroba(r.perfil))}`, `Receta escrita en el sitio · video de @${esc(arroba(r.perfil))}`) : t(`Vídeo de @${esc(arroba(r.perfil))}`, `Video de @${esc(arroba(r.perfil))}`))}</p>
      </div>
      <div class="short-video">${esperaVideo()}</div>
      <div class="short-acoes">
        <button class="botao botao-principal" type="button" data-acao="abrir">${ico(livro ? 'book-open-text' : 'list-bullets')}<span>${livro ? t('Ver a receita completa', 'Ver la receta completa') : t('Ver a receita', 'Ver la receta')}</span></button>
        <button class="icone-botao short-fav" type="button" data-acao="fav" aria-pressed="${fav}" aria-label="${fav ? t('Tirar das favoritas', 'Quitar de favoritas') : t('Guardar nas favoritas', 'Guardar en favoritas')}">${ico(fav ? 'heart-fill' : 'heart')}</button>
      </div>
      ${EX.n === 0 ? `<p class="short-dica">${ico('caret-up')}${t('Deslize pra cima pra ver a próxima', 'Desliza hacia arriba para ver la siguiente')}</p>` : ''}
    </article>`;
  }
  function maisShorts(qtd = 8) {
    let h = '';
    for (let k = 0; k < qtd; k++) {
      if (EX.pos >= EX.fila.length) novaFila();
      h += shortHtml(EX.fila[EX.pos++]);
      EX.n++;
    }
    feed.insertAdjacentHTML('beforeend', h);
    $$('.short:not([data-obs])', feed).forEach((s) => { s.dataset.obs = '1'; EX.obs.observe(s); EX.vis.observe(s); });
  }
  function carregarShort(s) {
    const caixa = $('.short-video', s);
    if (caixa.dataset.on) return;
    caixa.dataset.on = '1';
    const ig = s.dataset.ig;
    caixa.innerHTML = moldura(ig, s.dataset.perfil, s.dataset.dur);
    processarIg();
  }
  // longe da tela: tira o vídeo, pra o celular não ficar com dezenas de players abertos
  function descarregarShort(s) {
    const caixa = $('.short-video', s);
    if (!caixa.dataset.on) return;
    delete caixa.dataset.on;
    caixa.innerHTML = esperaVideo();
  }
  function montarFeed() {
    if (EX.obs) EX.obs.disconnect();
    feed.innerHTML = '';
    feed.scrollTop = 0;
    EX.n = 0;
    novaFila();
    EX.obs = new IntersectionObserver((ents) => {
      for (const en of ents) { if (en.isIntersecting) carregarShort(en.target); else descarregarShort(en.target); }
    }, { root: feed, rootMargin: '120% 0px' });
    if (EX.vis) EX.vis.disconnect();
    EX.vis = new IntersectionObserver((ents) => {
      for (const en of ents) if (!en.isIntersecting) reiniciarVideo($('.video-caixa', en.target));
    }, { root: feed, threshold: 0.6 });
    maisShorts();
  }
  feed.addEventListener('scroll', () => {
    if (feed.scrollTop + feed.clientHeight * 3 >= feed.scrollHeight) maisShorts();
  }, { passive: true });
  async function abrirExplorar() {
    if (!estado.liberado) { abrirLiberar(abrirExplorar); return; }
    try { await garantirSegredo(); } catch (e) { aviso(t('Não consegui abrir agora. Confira a internet e tente de novo.', 'No pude abrirlo ahora. Revisa tu conexión e inténtalo de nuevo.')); return; }
    montarFeed();
    if (!aberta('explorar')) abrirCamada('explorar', { foco: '#feed', aoFechar: fecharExplorar });
  }
  function fecharExplorar() {
    if (EX.obs) { EX.obs.disconnect(); EX.obs = null; }
    if (EX.vis) { EX.vis.disconnect(); EX.vis = null; }
    pararVideosEm(feed);
    setTimeout(() => { if (!aberta('explorar')) feed.innerHTML = ''; }, 380);
  }
  feed.addEventListener('click', (ev) => {
    const b = ev.target.closest('[data-acao]');
    if (!b) return;
    const s = b.closest('.short');
    const c = s.dataset.chave;
    if (b.dataset.acao === 'abrir') { pararVideosEm(feed); abrirReceita(c); }
    else if (b.dataset.acao === 'fav') {
      if (favs.has(c)) favs.delete(c); else favs.add(c);
      salvarFavs();
      const on = favs.has(c);
      b.setAttribute('aria-pressed', String(on));
      b.setAttribute('aria-label', on ? t('Tirar das favoritas', 'Quitar de favoritas') : t('Guardar nas favoritas', 'Guardar en favoritas'));
      b.innerHTML = ico(on ? 'heart-fill' : 'heart');
      aviso(on ? t('Guardada nas favoritas', 'Guardada en favoritas') : t('Tirada das favoritas', 'Quitada de favoritas'));
      renderFileiras();
    }
  });
  $('#abrir-explorar').addEventListener('click', abrirExplorar);
  $('#explorar-embaralhar').addEventListener('click', () => { montarFeed(); aviso(t('Embaralhado de novo', 'Mezclado de nuevo')); });

  // ---------- leitor de PDF (pdf.js, páginas desenhadas só perto da tela) ----------
  let pdfjsCarga = null;
  function carregarPdfjs() {
    if (window.pdfjsLib) return Promise.resolve(window.pdfjsLib);
    if (!pdfjsCarga) {
      pdfjsCarga = new Promise((res, rej) => {
        const s = document.createElement('script');
        s.src = 'vendor/pdf.min.js';
        s.onload = () => { window.pdfjsLib.GlobalWorkerOptions.workerSrc = 'vendor/pdf.worker.min.js'; res(window.pdfjsLib); };
        s.onerror = () => { pdfjsCarga = null; rej(new Error('pdfjs')); };
        document.head.append(s);
      });
    }
    return pdfjsCarga;
  }
  const L = { id: null, info: null, doc: null, total: 0, atual: 0, ar: 0.7071, w: 0, zoom: false, obs: null, tarefas: new Map(), blob: null, geracao: 0 };
  const areaPdf = $('#leitor-paginas');
  function estadoLeitor(texto, p = null, erro = false) {
    const caixa = $('#leitor-estado');
    if (!texto) { caixa.hidden = true; return; }
    caixa.hidden = false;
    $('#leitor-estado-txt').textContent = texto;
    const barra = $('#leitor-barra');
    barra.hidden = p == null;
    if (p != null) barra.style.setProperty('--p', String(p));
    $('#leitor-tentar').hidden = !erro;
  }
  async function abrirPdf(id) {
    if (!estado.liberado) { abrirLiberar(() => abrirPdf(id)); return; }
    try { await garantirSegredo(); } catch (e) { aviso(t('Não consegui abrir agora. Confira a internet e tente de novo.', 'No pude abrirlo ahora. Revisa tu conexión e inténtalo de nuevo.')); return; }
    const info = estado.segredo.pdfs?.[id];
    if (!info) { aviso(t('Não achei esse livro.', 'No encontré ese libro.')); return; }
    L.id = id; L.info = info;
    $('#leitor-titulo').textContent = nomeLivro(D.livros.find((x) => x.id === id) || info);
    $('#leitor-pagina').textContent = '';
    $('#leitor-baixar').hidden = true;
    areaPdf.innerHTML = '';
    if (!aberta('leitor')) abrirCamada('leitor', { aoFechar: fecharLeitor, foco: '[data-fechar]' });
    carregarDoc();
  }
  async function carregarDoc() {
    const info = L.info;
    const geracao = ++L.geracao;
    estadoLeitor(t('Baixando o livro…', 'Descargando el libro…'), 0);
    try {
      const pdfjs = await carregarPdfjs();
      const buf = await baixar(info.arq, (p) => {
        if (geracao !== L.geracao) return;
        $('#leitor-barra').style.setProperty('--p', String(p));
        $('#leitor-estado-txt').textContent = `${t('Baixando o livro…', 'Descargando el libro…')} ${Math.round(p * 100)}%`;
      });
      if (geracao !== L.geracao) return;
      estadoLeitor(t('Abrindo o livro…', 'Abriendo el libro…'));
      const plano = await decifrar(buf, estado.chave);
      if (L.blob) URL.revokeObjectURL(L.blob);
      L.blob = URL.createObjectURL(new Blob([plano], { type: 'application/pdf' }));
      const baixarPdf = $('#leitor-baixar');
      baixarPdf.href = L.blob;
      baixarPdf.download = `${info.titulo} - Fit que Viraliza.pdf`; // o PDF continua em português
      baixarPdf.hidden = false;
      const doc = await pdfjs.getDocument({ data: new Uint8Array(plano) }).promise;
      if (geracao !== L.geracao) { doc.destroy(); return; }
      L.doc = doc; L.total = doc.numPages;
      const vp = (await doc.getPage(1)).getViewport({ scale: 1 });
      L.ar = vp.width / vp.height;
      montarPaginas();
      estadoLeitor(null);
      const salva = lidas[L.id];
      if (salva > 1 && salva <= L.total) { irPara(salva); aviso(t(`Continuando da página ${salva}`, `Continuando desde la página ${salva}`)); }
      areaPdf.focus({ preventScroll: true });
    } catch (e) {
      if (geracao !== L.geracao) return;
      estadoLeitor(t('Não consegui abrir o livro. Confira a internet e tente de novo.', 'No pude abrir el libro. Revisa tu conexión e inténtalo de nuevo.'), null, true);
    }
  }
  const alturaPg = () => L.w / L.ar + 10;
  function montarPaginas() {
    const base = Math.min(areaPdf.clientWidth - 16, 920);
    L.w = Math.round(L.zoom ? base * 1.8 : base);
    areaPdf.style.setProperty('--pg-w', L.w + 'px');
    areaPdf.style.setProperty('--pg-ar', String(L.ar));
    let h = '';
    for (let n = 1; n <= L.total; n++) h += `<div class="pg" data-n="${n}"></div>`;
    areaPdf.innerHTML = h;
    for (const t of L.tarefas.values()) t.cancel();
    L.tarefas.clear();
    if (L.obs) L.obs.disconnect();
    L.obs = new IntersectionObserver((entradas) => {
      for (const en of entradas) { const n = Number(en.target.dataset.n); if (en.isIntersecting) desenhar(en.target, n); else apagar(en.target, n); }
    }, { root: areaPdf, rootMargin: '120% 0px' });
    $$('.pg', areaPdf).forEach((pg) => L.obs.observe(pg));
    L.atual = 0;
    numeroPagina();
  }
  async function desenhar(pg, n) {
    if (pg.querySelector('canvas') || L.tarefas.has(n) || !L.doc) return;
    const geracao = L.geracao, w = L.w;
    let tarefa = null;
    try {
      const page = await L.doc.getPage(n);
      if (geracao !== L.geracao || w !== L.w || !pg.isConnected) return;
      const vp1 = page.getViewport({ scale: 1 });
      const dpr = Math.min(window.devicePixelRatio || 1, L.zoom ? 2 : 2.5);
      const vp = page.getViewport({ scale: (w * dpr) / vp1.width });
      const canvas = document.createElement('canvas');
      canvas.width = Math.floor(vp.width); canvas.height = Math.floor(vp.height);
      tarefa = page.render({ canvasContext: canvas.getContext('2d', { alpha: false }), viewport: vp });
      L.tarefas.set(n, tarefa);
      await tarefa.promise;
      if (L.tarefas.get(n) === tarefa) L.tarefas.delete(n);
      if (geracao !== L.geracao || w !== L.w || !pg.isConnected) return;
      pg.append(canvas);
    } catch (e) {
      if (tarefa && L.tarefas.get(n) === tarefa) L.tarefas.delete(n);
    }
  }
  function apagar(pg, n) {
    const t = L.tarefas.get(n);
    if (t) { t.cancel(); L.tarefas.delete(n); }
    const c = pg.querySelector('canvas');
    if (c) { c.width = 0; c.height = 0; c.remove(); }
  }
  function numeroPagina() {
    if (!L.total) return;
    const n = Math.min(L.total, Math.max(1, Math.floor((areaPdf.scrollTop + areaPdf.clientHeight * 0.35) / alturaPg()) + 1));
    if (n === L.atual) return;
    L.atual = n;
    $('#leitor-pagina').textContent = `${n} de ${L.total}`;
    lidas[L.id] = n;
    salvarLidas();
  }
  function irPara(n) { areaPdf.scrollTop = (n - 1) * alturaPg(); numeroPagina(); }
  areaPdf.addEventListener('scroll', () => requestAnimationFrame(numeroPagina), { passive: true });
  $('#leitor-zoom').addEventListener('click', () => {
    if (!L.doc) return;
    const atual = L.atual || 1;
    L.zoom = !L.zoom;
    $('.leitor').toggleAttribute('data-zoom', L.zoom);
    $('#leitor-zoom').setAttribute('aria-label', L.zoom ? 'Diminuir a letra' : 'Aumentar a letra');
    montarPaginas();
    irPara(atual);
  });
  $('#leitor-tentar').addEventListener('click', () => carregarDoc());
  function fecharLeitor() {
    L.geracao++;
    if (L.obs) { L.obs.disconnect(); L.obs = null; }
    for (const t of L.tarefas.values()) t.cancel();
    L.tarefas.clear();
    if (L.doc) { L.doc.destroy(); L.doc = null; }
    L.total = 0; L.zoom = false;
    $('.leitor').removeAttribute('data-zoom');
    $('#leitor-zoom').setAttribute('aria-label', 'Aumentar a letra');
    if (L.blob) { const u = L.blob; L.blob = null; setTimeout(() => URL.revokeObjectURL(u), 2000); }
    guarda.gravar('paginas', lidas);
    setTimeout(() => { if (!aberta('leitor')) areaPdf.innerHTML = ''; }, 380);
    renderFileiras();
  }

  // ---------- aviso rápido ----------
  let tAviso = 0;
  function aviso(txt) {
    const el = $('#aviso');
    el.textContent = txt;
    el.classList.add('visivel');
    clearTimeout(tAviso);
    tAviso = setTimeout(() => el.classList.remove('visivel'), 2600);
  }

  // ---------- setas das fileiras (computador) ----------
  function ligarSetas() {
    for (const caixa of $$('.trilho-caixa:not([data-setas])')) {
      caixa.dataset.setas = '1';
      const trilho = $('.trilho', caixa);
      caixa.insertAdjacentHTML('beforeend',
        `<button class="seta seta-esq" type="button" tabindex="-1" aria-label="Voltar">${ico('caret-left')}</button>`
        + `<button class="seta seta-dir" type="button" tabindex="-1" aria-label="Avançar">${ico('caret-right')}</button>`);
      const esq = $('.seta-esq', caixa), dir = $('.seta-dir', caixa);
      const andar = (s) => trilho.scrollBy({ left: s * trilho.clientWidth * 0.85, behavior: quieto() ? 'auto' : 'smooth' });
      esq.addEventListener('click', () => andar(-1));
      dir.addEventListener('click', () => andar(1));
      caixa._setas = () => {
        esq.disabled = trilho.scrollLeft < 8;
        dir.disabled = trilho.scrollLeft + trilho.clientWidth >= trilho.scrollWidth - 8;
      };
      trilho.addEventListener('scroll', () => requestAnimationFrame(caixa._setas), { passive: true });
      caixa._setas();
    }
  }
  window.addEventListener('resize', () => $$('.trilho-caixa').forEach((c) => c._setas?.()));

  // ---------- cliques ----------
  $('#fileiras').addEventListener('click', (e) => {
    const c = e.target.closest('.cartao');
    if (!c) return;
    if (c.dataset.pdf) abrirPdf(c.dataset.pdf);
    else if (c.dataset.chave) abrirReceita(c.dataset.chave);
  });
  $('#destaque-acoes').addEventListener('click', (e) => {
    const b = e.target.closest('[data-acao]');
    if (!b) return;
    const acao = b.dataset.acao;
    if (acao === 'liberar') abrirLiberar();
    else if (acao === 'ver') $('#fileiras').scrollIntoView({ behavior: quieto() ? 'auto' : 'smooth', block: 'start' });
    else if (acao === 'buscar') irPraBusca();
    else if (acao === 'livro1') abrirPdf(D.pdfs[0].id);
    else if (acao === 'explorar') abrirExplorar();
  });
  $('#abrir-busca').addEventListener('click', irPraBusca);
  $('#selo').addEventListener('click', () => (estado.liberado ? $('#fileiras').scrollIntoView({ behavior: quieto() ? 'auto' : 'smooth' }) : abrirLiberar()));
  $('#esquecer').addEventListener('click', () => {
    if (!confirm(t('Esquecer a senha neste aparelho? Pra ver as receitas de novo, vai precisar digitar a senha.', '¿Olvidar la contraseña en este dispositivo? Para ver las recetas de nuevo tendrás que escribirla otra vez.'))) return;
    guarda.apagar('chave');
    location.reload();
  });
  const topo = $('#topo');
  const aoRolar = () => topo.classList.toggle('solido', window.scrollY > 24);
  window.addEventListener('scroll', aoRolar, { passive: true });

  // ---------- textos fixos da página nas duas línguas ----------
  const FIXOS = [
    ['.pular', 'Pular para as receitas', 'Ir a las recetas'],
    ['.destaque-sobre', 'Coleção', 'Colección'],
    ['.selo-txt-fechado', 'Liberar', 'Desbloquear'],
    ['.selo-txt-aberto', 'Liberado', 'Desbloqueado'],
    ['#abrir-busca', null, null, 'aria-label', 'Buscar receita', 'Buscar receta'],
    ['#busca-texto', null, null, 'placeholder', 'Buscar: frango, bolo, air fryer, sem glúten…', 'Buscar: pollo, pastel, freidora de aire, sin gluten…'],
    ['#busca-texto', null, null, 'aria-label', 'Buscar receita pelo nome', 'Buscar receta por nombre'],
    ['.filtro[data-kcal="200"]', 'Até 200 kcal', 'Hasta 200 kcal'],
    ['.filtro[data-kcal="350"]', 'Até 350 kcal', 'Hasta 350 kcal'],
    ['#t-fav', 'Suas favoritas', 'Tus favoritas'],
    ['#t-explorar', 'Explorar receitas aleatoriamente', 'Explorar recetas al azar'],
    ['.explorar-sub', 'Deslize pra cima e descubra receitas de todos os livros e temas, uma por tela.', 'Desliza hacia arriba y descubre recetas de todos los libros y temas, una por pantalla.'],
    ['#t-pdfs', 'Os 10 livros em PDF', 'Los 10 libros en PDF'],
    ['#fileira-pdfs .fileira-info', 'pra ler aqui ou guardar', 'para leer aquí o guardar (en portugués)'],
    ['.secao-titulo h2', 'Mais receitas em vídeo', 'Más recetas en video'],
    ['.secao-titulo p', 'Receitas dos perfis de nutrição que mais viralizaram, com o vídeo original de cada uma.', 'Recetas de los perfiles de nutrición que más se viralizaron, con el video original de cada una (en portugués).'],
    ['#esquecer', 'Esquecer a senha neste aparelho', 'Olvidar la contraseña en este dispositivo'],
    ['.rodape p:not(.rodape-marca)', 'Os vídeos das receitas extras são posts públicos do Instagram, tocados pelo player do próprio Instagram, com o crédito de quem criou. As receitas dos livros são versões nossas, com macros calculados pela Tabela TACO. Valores aproximados, que não substituem o acompanhamento de um nutricionista.',
      'Los videos de las recetas extra son publicaciones públicas de Instagram, reproducidas por el reproductor del propio Instagram, con el crédito de quien las creó. Las recetas de los libros son versiones nuestras, con macros calculados por la Tabla TACO de Brasil. Valores aproximados, que no sustituyen la orientación de un nutricionista.'],
    ['#liberar-titulo', 'Liberar as receitas', 'Desbloquear las recetas'],
    ['#camada-liberar .folha-texto', 'Digite a senha que você recebeu no WhatsApp junto com este link. Depois disso este aparelho lembra dela.', 'Escribe la contraseña que recibiste por WhatsApp junto con este enlace. Después, este dispositivo la recordará.'],
    ['.senha-rotulo', 'Senha', 'Contraseña'],
    ['#senha-enviar .botao-txt', 'Liberar', 'Desbloquear'],
    ['#senha-dica', 'Pode digitar com ou sem espaço, maiúscula ou acento.', 'Puedes escribirla con o sin espacios, mayúsculas o acentos.'],
    ['#explorar-titulo', 'Explorar receitas', 'Explorar recetas'],
    ['#explorar-embaralhar', null, null, 'aria-label', 'Embaralhar de novo', 'Mezclar de nuevo'],
    ['#leitor-baixar', null, null, 'aria-label', 'Baixar o PDF', 'Descargar el PDF'],
  ];
  function aplicarIdioma() {
    html.lang = ES() ? 'es' : 'pt-BR';
    document.title = ES() ? 'Fit que Viraliza · Área de miembros' : 'Fit que Viraliza · Área de membros';
    for (const [sel, pt, es, attr, apt, aes] of FIXOS) {
      const el = $(sel);
      if (!el) continue;
      if (pt != null) el.textContent = ES() ? es : pt;
      if (attr) el.setAttribute(attr, ES() ? aes : apt);
    }
    const b = $('#idioma');
    b.setAttribute('aria-label', ES() ? 'Ver em português' : 'Ver en español');
    $$('[data-l]', b).forEach((x) => x.classList.toggle('ativo', x.dataset.l === idioma));
  }
  $('#idioma').addEventListener('click', () => {
    idioma = ES() ? 'pt' : 'es';
    guarda.gravar('idioma', idioma);
    aplicarIdioma();
    montarFileiras();
    ligarSetas();
    renderTudo();
    if (receitaAberta) abrirReceita(receitaAberta);
    if (aberta('explorar')) montarFeed();
    aviso(ES() ? 'Ahora en español' : 'Agora em português');
  });

  // ---------- início ----------
  async function iniciar() {
    aplicarIdioma();
    montarFileiras();
    ligarSetas();
    renderTudo();
    $('#busca-grade').hidden = true;
    aoRolar();
    if (!estado.liberado) return;
    try {
      await dadosAtuais();
      estado.chave = await chaveGuardada();
      if (!estado.chave) throw Object.assign(new Error('sem chave'), { name: 'OperationError' });
      estado.segredo = await abrirCofre(estado.chave);
      renderFileiras();
    } catch (e) {
      if (e && (e.name === 'OperationError' || e.name === 'DataError' || e instanceof SyntaxError)) {
        guarda.apagar('chave');
        estado.liberado = false; estado.chave = null;
        html.removeAttribute('data-liberado');
        renderTudo();
      }
    }
  }
  iniciar();
})();
