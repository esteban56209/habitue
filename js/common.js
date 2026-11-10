// =====================================================================
// Fonctions partagées par toutes les pages : connexion à Supabase,
// en-tête, pied de page, messages d'erreur en français.
// =====================================================================
(function () {
  const cfg = window.HABITUE_CONFIG || {};
  const configured = /^https:\/\//.test(cfg.SUPABASE_URL || "") && (cfg.SUPABASE_ANON_KEY || "").length > 20;
  const inApp = location.pathname.includes("/app/");
  const root = inApp ? "../" : "";

  const H = (window.H = {
    cfg, configured, root,
    sb: configured && window.supabase ? window.supabase.createClient(cfg.SUPABASE_URL, cfg.SUPABASE_ANON_KEY) : null,
    $: (sel) => document.querySelector(sel),
    // Empêche qu'un texte saisi par un utilisateur soit interprété comme du code (faille XSS)
    esc: (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])),
    date: (d) => (d ? new Date(d).toLocaleDateString("fr-FR", { day: "numeric", month: "short", year: "numeric" }) : "—"),
    dateTime: (d) => (d ? new Date(d).toLocaleString("fr-FR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "—"),
    show(el, text, kind) {
      if (typeof el === "string") el = H.$(el);
      if (!el) return;
      el.textContent = text || "";
      el.className = "msg " + (kind === "ok" ? "ok" : "err") + (text ? "" : " hidden");
    },
    busy(btn, on) { if (btn) btn.disabled = !!on; },
    // Traduit les erreurs techniques en phrases claires
    fr(error) {
      const m = (error && (error.message || error.error_description)) || String(error || "");
      const map = [
        [/Invalid login credentials/i, "E-mail ou mot de passe incorrect."],
        [/Email not confirmed/i, "Ton e-mail n'est pas encore confirmé. Clique sur le lien reçu par e-mail."],
        [/already registered|already been registered/i, "Un compte existe déjà avec cet e-mail."],
        [/Password should be at least/i, "Le mot de passe est trop court (8 caractères minimum)."],
        [/rate limit|too many requests/i, "Trop de tentatives. Réessaie dans quelques minutes."],
        [/BAD_PIN/, "Le code PIN doit contenir 4 à 6 chiffres."],
        [/BAD_NAME/, "Le nom saisi est trop court ou trop long."],
        [/BAD_REWARD/, "Décris la récompense en 2 à 80 caractères."],
        [/BAD_STAMPS/, "Le nombre de tampons doit être compris entre 3 et 20."],
        [/BAD_CONTACT/, "Entre un numéro de téléphone ou un e-mail valide."],
        [/BAD_EMAIL/, "Entre une adresse e-mail valide."],
        [/BAD_MESSAGE/, "Ton message doit contenir entre 5 et 2000 caractères."],
        [/CARD_NOT_FOUND/, "Cette carte de fidélité est introuvable ou désactivée."],
        [/CARD_INACTIVE/, "Cette carte est momentanément désactivée par le commerçant."],
        [/TOO_MANY/, "Trop de demandes pour le moment. Réessaie plus tard."],
        [/FORBIDDEN/, "Accès réservé à l'administrateur."],
        [/Failed to fetch|NetworkError/i, "Connexion impossible. Vérifie ta connexion Internet."]
      ];
      for (const [re, txt] of map) if (re.test(m)) return txt;
      return "Une erreur est survenue. Réessaie. (" + m.slice(0, 120) + ")";
    },
    async session() {
      if (!H.sb) return null;
      const { data } = await H.sb.auth.getSession();
      return data.session;
    },
    // Pages réservées aux commerçants : renvoie { user, merchant, card } ou redirige.
    async requireMerchant(opts) {
      const s = await H.session();
      if (!s) { location.href = root + "connexion.html"; return null; }
      const { data: merchant } = await H.sb.from("merchants").select("id,business_name,created_at").maybeSingle();
      const { data: card } = await H.sb.from("cards").select("*").maybeSingle();
      if ((!merchant || !card) && !(opts && opts.allowSetup)) { location.href = root + "app/ma-carte.html"; return null; }
      return { user: s.user, merchant, card };
    },
    async logout() { if (H.sb) await H.sb.auth.signOut(); location.href = root + "index.html"; },
    cardUrl(cardId) { return new URL(root + "c.html?id=" + cardId, location.href).href; }
  });

  // ----- En-tête et pied de page communs -----
  async function layout() {
    const page = location.pathname.split("/").pop() || "index.html";
    const s = await H.session();
    const link = (href, label) => `<a href="${root}${href}" class="${href.endsWith(page) ? "active" : ""}">${label}</a>`;
    let nav;
    if (inApp) {
      nav = link("app/tableau-de-bord.html", "Tableau de bord") + link("app/ma-carte.html", "Ma carte") +
        link("app/clients.html", "Mes clients") + link("app/parametres.html", "Paramètres") +
        `<a href="#" id="logout">Déconnexion</a>`;
    } else {
      nav = link("service.html", "Comment ça marche") + link("contact.html", "Contact") +
        (s ? `<a class="btn small" href="${root}app/tableau-de-bord.html">Mon espace</a>`
           : link("connexion.html", "Connexion") + `<a class="btn small" href="${root}inscription.html">Essayer gratuitement</a>`);
    }
    const top = document.getElementById("top");
    if (top) top.innerHTML = `<div class="wrap"><a class="brand" href="${root}index.html"><img src="${root}assets/icon.svg" alt="">Habitué</a><nav class="nav" aria-label="Menu">${nav}</nav></div>`;
    const foot = document.getElementById("foot");
    if (foot) foot.innerHTML = `<div class="wrap"><div>© ${new Date().getFullYear()} Habitué — La carte de fidélité sans carton</div>
      <div><a href="${root}service.html">Comment ça marche</a><a href="${root}contact.html">Contact</a><a href="${root}confidentialite.html">Confidentialité</a></div></div>`;
    const lo = document.getElementById("logout");
    if (lo) lo.addEventListener("click", (e) => { e.preventDefault(); H.logout(); });
    if (!configured) {
      const b = document.createElement("div");
      b.className = "msg err"; b.style.margin = "0"; b.style.borderRadius = "0";
      b.textContent = "Site non configuré : renseigne l'URL et la clé Supabase dans js/config.js.";
      document.body.prepend(b);
    }
  }
  H.ready = layout();
})();
