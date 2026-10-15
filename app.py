#!/usr/bin/env python3
"""TP1 — Scanner réseau pédagogique enrichi par IA.

Interface inspirée de NotebookLM : panneau « Sources », discussion IA,
pastilles de citations [n] et panneau « Studio ».
"""
import html as htmllib
import os
import re
from datetime import datetime

from flask import Flask, jsonify, render_template_string, request
import markdown
import nmap
from groq import Groq

app = Flask(__name__)

CIBLES_AUTORISEES = ["192.168.1.42"]
MODELE_IA = "openai/gpt-oss-120b"

# Dernier scan conservé en mémoire (application pédagogique mono-utilisateur).
DERNIER_SCAN = {
    "cible": None,
    "resultats": [],
    "horodatage": None,
    "historique": [],  # derniers échanges, pour garder le fil de la discussion
}


# --------------------------------------------------------------------------- #
# Services externes : créés à la demande, avec messages d'erreur clairs.
# --------------------------------------------------------------------------- #
def obtenir_scanner():
    """Retourne (scanner Nmap, message d'erreur éventuel)."""
    try:
        return nmap.PortScanner(), None
    except Exception as exc:  # nmap absent, droits insuffisants, ...
        return None, f"Nmap n'est pas disponible sur ce serveur ({exc})."


def obtenir_client():
    """Retourne (client Groq, message d'erreur éventuel)."""
    cle = os.environ.get("GROQ_API_KEY")
    if not cle:
        return None, "Clé API GROQ_API_KEY absente : l'analyse IA est indisponible."
    try:
        return Groq(api_key=cle), None
    except Exception as exc:
        return None, f"Client IA indisponible ({exc})."


# --------------------------------------------------------------------------- #
# Markdown, citations et assainissement de sortie LLM.
# --------------------------------------------------------------------------- #
def vers_html(texte_md):
    return markdown.markdown(
        texte_md or "", extensions=["tables", "fenced_code", "sane_lists"]
    )


def assainir(html_sortie):
    """Retire les éléments dangereux qu'un LLM pourrait faire passer."""
    html_sortie = re.sub(
        r"<script\b[^>]*>.*?</script>", "", html_sortie, flags=re.I | re.S
    )
    html_sortie = re.sub(r"\son\w+\s*=\s*\"[^\"]*\"", "", html_sortie, flags=re.I)
    html_sortie = re.sub(r"\son\w+\s*=\s*'[^']*'", "", html_sortie, flags=re.I)
    html_sortie = re.sub(r"<iframe\b", "&lt;iframe", html_sortie, flags=re.I)
    return html_sortie


def ajouter_citations(html_sortie, resultats):
    """Transforme les marqueurs [n] en pastilles citant la source n."""

    def _pastille(matche):
        n = int(matche.group(1))
        if 1 <= n <= len(resultats):
            r = resultats[n - 1]
            etiquette = (
                f"{r['service']} — port {r['port']}/{r['protocole']} ({r['version']})"
            )
            return (
                f'<span class="cite" title="{htmllib.escape(etiquette)}">{n}</span>'
            )
        return matche.group(0)

    return re.sub(r"\[(\d{1,2})\]", _pastille, html_sortie)


def inventaire_textuel(resultats, selection=None):
    """Liste numérotée des sources, dans la numérotation du panneau Sources."""
    lignes = []
    for i, r in enumerate(resultats, start=1):
        if selection is not None and i not in selection:
            continue
        lignes.append(
            f"[{i}] {r['hote']} — port {r['port']}/{r['protocole']}, "
            f"service « {r['service']} », version « {r['version']} », "
            f"état « {r['etat']} »"
        )
    return "\n".join(lignes) or "(aucun port ouvert détecté)"


def synthese_ia(client, resultats, cible):
    prompt = (
        "Tu es l'assistant pédagogique d'un TP de réseau (niveau licence, "
        "laboratoire EC2LT).\n"
        f"Inventaire Nmap de la cible autorisée {cible} :\n"
        f"{inventaire_textuel(resultats)}\n\n"
        "Rédige en français une synthèse pédagogique au format Markdown, "
        "structurée ainsi :\n"
        "### Rôle probable des services\n"
        "### Risques génériques connus\n"
        "### Recommandations de durcissement\n\n"
        "Cite chaque service dont tu parles avec la pastille [n] "
        "(n = numéro de la source). Reste générique : parle de bonnes "
        "pratiques, jamais d'exploitation. "
        "N'émets aucune instruction d'exploitation."
    )
    reponse = client.chat.completions.create(
        model=MODELE_IA,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1200,
    )
    return reponse.choices[0].message.content


# --------------------------------------------------------------------------- #
# Routes.
# --------------------------------------------------------------------------- #
def rendre_page(**contexte):
    base = dict(
        resultats=None,
        synthese_html="",
        erreur=None,
        cible="",
        cibles=CIBLES_AUTORISEES,
        horodatage=DERNIER_SCAN["horodatage"],
        ia_dispo=bool(os.environ.get("GROQ_API_KEY")),
    )
    base.update(contexte)
    return render_template_string(TEMPLATE, **base)


@app.route("/", methods=["GET", "POST"])
def index():
    resultats, synthese_html, erreur, cible = None, "", None, ""

    if request.method == "POST":
        cible = (request.form.get("cible") or "").strip()

        # Liste blanche : seul le poste du laboratoire est scannable.
        if cible not in CIBLES_AUTORISEES:
            erreur = (
                f"Cible « {cible or '—'} » non autorisée. "
                f"Liste blanche du laboratoire : {', '.join(CIBLES_AUTORISEES)}."
            )
            return rendre_page(erreur=erreur, cible=cible), 403

        scanner, err = obtenir_scanner()
        if scanner is None:
            return rendre_page(erreur=err, cible=cible), 500

        try:
            scanner.scan(hosts=cible, arguments="-sV -T4")
        except Exception as exc:
            return rendre_page(
                erreur=f"Le scan a échoué ({exc}).", cible=cible
            ), 500

        resultats = []
        for hote in scanner.all_hosts():
            for proto in scanner[hote].all_protocols():
                for port, info in sorted(scanner[hote][proto].items()):
                    resultats.append(
                        {
                            "hote": hote,
                            "port": port,
                            "protocole": proto,
                            "service": info.get("name"),
                            "version": info.get("version") or "non détectée",
                            "etat": info.get("state"),
                        }
                    )

        horodatage = datetime.now().strftime("%d/%m/%Y à %H:%M")
        DERNIER_SCAN.update(
            cible=cible,
            resultats=resultats,
            horodatage=horodatage,
            historique=[],
        )

        if resultats:
            client, err_ia = obtenir_client()
            if client is None:
                erreur = err_ia
            else:
                try:
                    synthese_md = synthese_ia(client, resultats, cible)
                    synthese_html = ajouter_citations(
                        assainir(vers_html(synthese_md)), resultats
                    )
                except Exception as exc:
                    erreur = (
                        f"L'analyse IA n'a pas abouti ({exc}). "
                        "Les sources Nmap restent consultables."
                    )

    return rendre_page(
        resultats=resultats,
        synthese_html=synthese_html,
        erreur=erreur,
        cible=cible,
    )


@app.route("/api/question", methods=["POST"])
def api_question():
    """Réponses de suivi sur les sources du dernier scan (chat NotebookLM)."""
    donnees = request.get_json(silent=True) or {}
    question = (donnees.get("question") or "").strip()
    if not question:
        return jsonify(erreur="Posez une question avant d'envoyer."), 400
    if not DERNIER_SCAN["resultats"]:
        return jsonify(erreur="Aucune source chargée : lancez d'abord un scan."), 400

    # Sources cochées dans le panneau de gauche (numérotation du panneau).
    # Champ absent : on prend toutes les sources ; liste vide : refus.
    inclus = donnees.get("sources")
    if inclus is None or not isinstance(inclus, list):
        inclus = list(range(1, len(DERNIER_SCAN["resultats"]) + 1))
    selection = {
        i for i in inclus
        if isinstance(i, int) and 1 <= i <= len(DERNIER_SCAN["resultats"])
    }
    if not selection:
        return jsonify(
            erreur="Cochez au moins une source dans le panneau Sources."
        ), 400

    # Requête valide : on vérifie ensuite la disponibilité du service IA.
    client, err = obtenir_client()
    if client is None:
        return jsonify(erreur=err), 503

    systeme = (
        "Tu es l'assistant pédagogique du TP1 (laboratoire EC2LT). "
        "Réponds en français, avec un ton courtois et pédagogique.\n"
        f"Sources sélectionnées (scan du {DERNIER_SCAN['horodatage']} "
        f"sur {DERNIER_SCAN['cible']}) :\n"
        f"{inventaire_textuel(DERNIER_SCAN['resultats'], selection)}\n\n"
        "Ne répond qu'à partir de ces sources. Termine chaque affirmation "
        "pertinente par une pastille [n] renvoyant à la source utilisée. "
        "N'émets aucune instruction d'exploitation ni commande offensive ; "
        "si la question sort du cadre de ce scan, redis-le poliment."
    )

    historique = DERNIER_SCAN["historique"][-10:]
    try:
        reponse = client.chat.completions.create(
            model=MODELE_IA,
            messages=[
                {"role": "system", "content": systeme},
                *historique,
                {"role": "user", "content": question},
            ],
            max_tokens=900,
        )
    except Exception as exc:
        return jsonify(erreur=f"Le service IA a répondu en erreur ({exc})."), 502

    texte = reponse.choices[0].message.content
    reponse_html = ajouter_citations(assainir(vers_html(texte)), DERNIER_SCAN["resultats"])

    # On conserve le fil de la discussion (limité en taille).
    DERNIER_SCAN["historique"] = (
        historique
        + [
            {"role": "user", "content": question},
            {"role": "assistant", "content": texte},
        ]
    )[-12:]

    return jsonify(reponse_html=reponse_html)


# --------------------------------------------------------------------------- #
# Interface (inspirée de NotebookLM).
# --------------------------------------------------------------------------- #
TEMPLATE = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TP1 Scan réseau enrichi par IA</title>
<link rel="icon" type="image/png" href="{{ url_for('static', filename='moustique.png') }}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    color-scheme: light;
    --bg:#ffffff; --panel:#ffffff; --soft:#f0f4f9; --soft-2:#f8fafd;
    --border:#e3e3e3; --border-2:#dadce0;
    --text:#1f1f1f; --muted:#5f6368;
    --accent:#1a73e8; --accent-2:#185abc; --on-accent:#ffffff;
    --user-bubble:#d3e3fd; --user-text:#041e49;
    --cite-bg:#e8f0fe; --cite-tx:#1967d2;
    --err-bg:#fce8e6; --err-tx:#c5221f;
    --shadow:0 1px 2px rgba(60,64,67,.08), 0 2px 6px rgba(60,64,67,.06);
    --grad:linear-gradient(135deg,#4285f4,#9b72cb 55%,#d96570);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      color-scheme: dark;
      --bg:#1b1b1b; --panel:#1b1b1b; --soft:#303134; --soft-2:#282a2c;
      --border:#3c4043; --border-2:#444746;
      --text:#e3e3e3; --muted:#9aa0a6;
      --accent:#a8c7fa; --accent-2:#c2e7ff; --on-accent:#062e6f;
      --user-bubble:#004a77; --user-text:#e8f0fe;
      --cite-bg:#1e3a5f; --cite-tx:#a8c7fa;
      --err-bg:#5c1b15; --err-tx:#f2b8b5;
      --shadow:0 1px 3px rgba(0,0,0,.45);
    }
  }
  * { box-sizing:border-box; }
  [hidden] { display:none !important; }
  html, body { height:100%; }
  body {
    font-family:'Inter','Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
    background:var(--bg); color:var(--text); margin:0;
    -webkit-font-smoothing:antialiased;
  }
  button { font-family:inherit; }

  /* ---------------- barre supérieure ---------------- */
  .appbar {
    height:64px; display:flex; align-items:center; justify-content:space-between;
    gap:16px; padding:0 20px; border-bottom:1px solid var(--border);
  }
  .brand { display:flex; align-items:center; gap:12px; min-width:0; }
  .logo {
    width:38px; height:38px; border-radius:12px; flex:none;
    display:grid; place-items:center; overflow:hidden;
  }
  .logo img { width:100%; height:100%; object-fit:contain; display:block; }
  .brand h1 { font-size:15.5px; font-weight:600; margin:0; white-space:nowrap;
    overflow:hidden; text-overflow:ellipsis; }
  .brand p { margin:1px 0 0; font-size:12px; color:var(--muted); }
  .chip-ghost {
    display:inline-flex; align-items:center; gap:6px; font-size:12px;
    color:var(--muted); border:1px solid var(--border); border-radius:999px;
    padding:6px 12px; white-space:nowrap;
  }

  /* ---------------- disposition 3 panneaux ---------------- */
  .layout {
    display:grid; gap:14px; padding:14px 16px;
    grid-template-columns:320px minmax(0,1fr) 380px;
    grid-template-areas:'sources chat studio';
    height:calc(100vh - 64px); height:calc(100dvh - 64px);
  }
  .panel {
    grid-area:sources; background:var(--panel); border:1px solid var(--border);
    border-radius:16px; display:flex; flex-direction:column;
    min-height:0; overflow:hidden;
  }
  .panel-chat { grid-area:chat; }
  .panel-studio { grid-area:studio; }
  .panel-head {
    display:flex; align-items:center; justify-content:space-between; gap:8px;
    padding:14px 16px; border-bottom:1px solid var(--border); flex:none;
  }
  .panel-head h2 { margin:0; font-size:14px; font-weight:600; }
  .panel-body { flex:1; min-height:0; overflow-y:auto; padding:10px; }
  .panel-body::-webkit-scrollbar, .messages::-webkit-scrollbar,
  .doc::-webkit-scrollbar { width:8px; }
  .panel-body::-webkit-scrollbar-thumb, .messages::-webkit-scrollbar-thumb,
  .doc::-webkit-scrollbar-thumb {
    background:var(--border-2); border-radius:8px;
  }
  .count-badge {
    font-size:11px; font-weight:600; color:var(--muted);
    background:var(--soft); border-radius:999px; padding:3px 10px;
  }

  /* ---------------- formulaire de scan ---------------- */
  .scan-form {
    padding:14px 14px 12px; border-bottom:1px solid var(--border);
    display:flex; flex-direction:column; gap:10px; flex:none;
  }
  .field span {
    display:block; font-size:10.5px; font-weight:600; letter-spacing:.06em;
    text-transform:uppercase; color:var(--muted);
  }
  .field input {
    width:100%; margin-top:5px; padding:10px 12px; border-radius:10px;
    border:1px solid var(--border-2); background:var(--soft);
    color:var(--text); font-size:13px; outline:none; font-family:inherit;
  }
  .field input:focus { border-color:var(--accent); background:var(--panel); }
  .btn-primary {
    display:flex; align-items:center; justify-content:center; gap:8px;
    background:var(--accent); color:var(--on-accent); border:none;
    border-radius:999px; padding:10px 18px; font-size:13px; font-weight:600;
    cursor:pointer; transition:background .15s;
  }
  .btn-primary:hover { background:var(--accent-2); }
  .btn-primary:disabled { opacity:.6; cursor:wait; }
  .scan-loading {
    display:flex; align-items:center; gap:8px; font-size:12px; color:var(--muted);
  }
  .spin {
    width:14px; height:14px; border-radius:50%; flex:none;
    border:2px solid var(--border-2); border-top-color:var(--accent);
    animation:spin 1s linear infinite;
  }
  @keyframes spin { to { transform:rotate(360deg); } }

  /* ---------------- sources ---------------- */
  .source {
    display:flex; align-items:center; gap:8px; padding:6px 8px;
    border-radius:12px; transition:background .15s;
  }
  .source:hover { background:var(--soft); }
  .source-main {
    flex:1; min-width:0; display:flex; align-items:center; gap:10px;
    background:none; border:none; padding:4px 0; cursor:pointer;
    text-align:left; color:inherit;
  }
  .source-icon {
    width:34px; height:34px; border-radius:9px; flex:none;
    background:var(--cite-bg); color:var(--cite-tx);
    display:grid; place-items:center;
  }
  .source-name {
    display:block; font-size:13px; font-weight:600;
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
  }
  .source-sub {
    display:block; font-size:11.5px; color:var(--muted);
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
  }
  .source-detail {
    display:none; margin:2px 8px 8px 52px; font-size:12px;
    color:var(--muted); line-height:1.7;
  }
  .source.open .source-detail { display:block; }
  .source-detail b { color:var(--text); font-weight:600; }
  .src-check {
    appearance:none; -webkit-appearance:none; width:18px; height:18px;
    border:2px solid var(--border-2); border-radius:5px; flex:none;
    background:var(--panel); cursor:pointer; position:relative; margin:0;
  }
  .src-check:checked { background:var(--accent); border-color:var(--accent); }
  .src-check:checked::after {
    content:''; position:absolute; left:4px; top:1px; width:4px; height:8px;
    border:solid var(--on-accent); border-width:0 2px 2px 0; transform:rotate(45deg);
  }

  /* ---------------- discussion ---------------- */
  .chat-head {
    display:flex; align-items:center; justify-content:space-between; gap:10px;
    padding:12px 20px; border-bottom:1px solid var(--border); flex:none;
  }
  .chat-head h2 { margin:0; font-size:15px; font-weight:600; }
  .chat-head p { margin:2px 0 0; font-size:12px; color:var(--muted); }
  .messages {
    flex:1; min-height:0; overflow-y:auto; padding:20px 20px 6px;
    display:flex; flex-direction:column; gap:18px;
  }
  .msg { display:flex; gap:12px; max-width:860px; }
  .msg-user { align-self:flex-end; flex-direction:row-reverse; max-width:76%; }
  .avatar {
    width:30px; height:30px; border-radius:50%; flex:none; background:var(--grad);
    display:grid; place-items:center; color:#fff;
  }
  .bubble { font-size:14px; line-height:1.65; padding-top:3px; min-width:0; }
  .msg-assistant .bubble { flex:1; }
  .msg-user .bubble {
    background:var(--user-bubble); color:var(--user-text);
    padding:10px 16px; border-radius:18px 18px 4px 18px;
  }
  .msg-meta {
    display:flex; align-items:center; gap:8px; flex-wrap:wrap;
    font-size:11.5px; color:var(--muted); margin-bottom:5px;
  }
  .msg-meta strong { color:var(--text); font-size:12.5px; }
  .tag {
    font-size:10.5px; font-weight:600; color:var(--muted);
    background:var(--soft); border:1px solid var(--border);
    border-radius:999px; padding:1px 8px;
  }
  .msg-systeme { align-self:flex-start; }
  .err {
    background:var(--err-bg); color:var(--err-tx); border-radius:12px;
    padding:10px 14px; font-size:13px; line-height:1.5;
    display:flex; align-items:flex-start; gap:8px;
  }
  .err svg { flex:none; margin-top:1px; }
  .ico-p {
    width:16px; height:16px; vertical-align:-3px; margin-right:5px;
    color:var(--accent); flex:none;
  }
  .chip-ghost svg { flex:none; }
  .typing {
    display:flex; gap:5px; padding:12px 16px; background:var(--soft);
    border-radius:18px; width:fit-content;
  }
  .typing i {
    width:7px; height:7px; border-radius:50%; background:var(--muted);
    animation:blink 1.2s infinite;
  }
  .typing i:nth-child(2) { animation-delay:.2s; }
  .typing i:nth-child(3) { animation-delay:.4s; }
  @keyframes blink {
    0%, 80%, 100% { opacity:.25; transform:translateY(0); }
    40% { opacity:1; transform:translateY(-3px); }
  }

  /* contenu markdown de l'IA */
  .synthese p { margin:0 0 10px; }
  .synthese p:last-child { margin-bottom:0; }
  .synthese h1, .synthese h2, .synthese h3, .synthese h4 {
    margin:16px 0 6px; font-size:14px; font-weight:600;
  }
  .synthese h1:first-child, .synthese h2:first-child,
  .synthese h3:first-child { margin-top:0; }
  .synthese ul, .synthese ol { margin:0 0 10px; padding-left:22px; }
  .synthese li { margin:3px 0; }
  .synthese code {
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    font-size:12.5px; background:var(--soft); border-radius:5px; padding:1px 5px;
  }
  .synthese pre {
    background:var(--soft-2); border:1px solid var(--border);
    border-radius:10px; padding:10px 12px; overflow-x:auto; margin:0 0 10px;
  }
  .synthese pre code { background:none; padding:0; }
  .synthese table { border-collapse:collapse; margin:0 0 12px; font-size:13px; }
  .synthese th, .synthese td {
    border:1px solid var(--border); padding:6px 10px; text-align:left;
  }
  .synthese th { background:var(--soft); font-weight:600; }
  .cite {
    display:inline-block; background:var(--cite-bg); color:var(--cite-tx);
    border:1px solid transparent; border-radius:6px; padding:0 6px;
    font-size:11px; font-weight:600; margin:0 2px; cursor:help;
    vertical-align:1px;
  }
  .cite:hover { border-color:currentColor; }

  /* suggestions + saisie */
  .suggestions {
    display:flex; gap:8px; flex-wrap:wrap; padding:8px 20px 0; flex:none;
  }
  .sugg {
    background:var(--panel); border:1px solid var(--border-2);
    border-radius:999px; padding:7px 14px; font-size:12.5px;
    color:var(--text); cursor:pointer; transition:.15s;
  }
  .sugg:hover { background:var(--soft); border-color:var(--accent); color:var(--accent); }
  .composer {
    margin:12px 20px 16px; flex:none; display:flex; align-items:center; gap:8px;
    background:var(--panel); border:1px solid var(--border-2); border-radius:28px;
    padding:5px 5px 5px 18px; box-shadow:var(--shadow);
  }
  .composer:focus-within { border-color:var(--accent); }
  .composer input {
    flex:1; min-width:0; border:none; outline:none; background:transparent;
    color:var(--text); font-size:14px; padding:10px 0; font-family:inherit;
  }
  .send {
    width:40px; height:40px; border-radius:50%; border:none; flex:none;
    background:var(--accent); color:var(--on-accent); display:grid;
    place-items:center; cursor:pointer; transition:background .15s;
  }
  .send:hover:not(:disabled) { background:var(--accent-2); }
  .send:disabled { background:var(--soft); color:var(--muted); cursor:not-allowed; }
  .send .spinner { display:none; }
  .send.busy svg { display:none; }
  .send.busy .spinner {
    display:block; width:16px; height:16px; border-radius:50%;
    border:2px solid var(--border-2); border-top-color:var(--accent);
    animation:spin 1s linear infinite;
  }

  /* ---------------- studio ---------------- */
  .studio-card {
    background:var(--panel); border:1px solid var(--border);
    border-radius:14px; padding:14px; margin-bottom:12px;
  }
  .studio-card h3 {
    margin:0 0 10px; font-size:13px; font-weight:600;
    display:flex; align-items:center; gap:9px;
  }
  .studio-icon {
    width:26px; height:26px; border-radius:8px; background:var(--soft);
    color:var(--muted); display:grid; place-items:center; flex:none;
  }
  .studio-head { display:flex; align-items:center; justify-content:space-between; }
  .btn-ghost {
    background:none; border:1px solid var(--border-2); color:var(--muted);
    border-radius:999px; padding:4px 12px; font-size:11.5px; font-weight:600;
    cursor:pointer; transition:.15s;
  }
  .btn-ghost:hover { background:var(--soft); color:var(--text); }
  .stats { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
  .stat { background:var(--soft); border-radius:10px; padding:10px 12px; }
  .stat b { display:block; font-size:18px; font-weight:600; }
  .stat span { font-size:11px; color:var(--muted); }
  .doc {
    font-size:13px; line-height:1.6; max-height:340px; overflow-y:auto;
    border-top:1px solid var(--border); padding-top:10px;
  }
  .pill-list { display:flex; flex-wrap:wrap; gap:6px; }
  .pill {
    background:var(--soft); border-radius:999px; padding:5px 11px;
    font-size:11.5px; color:var(--muted);
  }

  /* ---------------- états vides ---------------- */
  .empty { text-align:center; color:var(--muted); padding:34px 16px; line-height:1.6; }
  .empty svg { opacity:.45; margin-bottom:8px; }
  .empty b { display:block; color:var(--text); font-size:13.5px; margin-bottom:4px; }

  /* ---------------- responsive ---------------- */
  @media (max-width:1180px) {
    .layout {
      grid-template-columns:300px minmax(0,1fr);
      grid-template-rows:minmax(0,1fr) auto;
      grid-template-areas:'sources chat' 'studio studio';
    }
    .panel-studio { max-height:34vh; }
  }
  @media (max-width:860px) {
    .appbar { height:auto; padding:12px 16px; flex-wrap:wrap; }
    .layout {
      display:flex; flex-direction:column; height:auto; padding:12px;
    }
    .panel { min-height:auto; }
    .panel-body { overflow:visible; }
    .panel-studio { max-height:none; }
    .messages { max-height:62vh; }
    .msg-user { max-width:90%; }
  }
</style>
</head>
<body>

<header class="appbar">
  <div class="brand">
    <div class="logo">
      <img src="{{ url_for('static', filename='moustique.png') }}"
           alt="Logo de l'application — moustique">
    </div>
    <div>
      <h1>TP1 Scan réseau enrichi par IA</h1>
      <p>Carnet pédagogique · Laboratoire EC2LT</p>
    </div>
  </div>
  <span class="chip-ghost" title="Seule la cible du laboratoire est scannable">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
         stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
      <rect x="4" y="10.5" width="16" height="10.5" rx="2.5"/>
      <path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/>
      <path d="M12 14.5v3"/>
    </svg>
    Liste blanche : {{ cibles | join(' · ') }}
  </span>
</header>

<main class="layout">

  <!-- ============ SOURCES ============ -->
  <section class="panel panel-sources">
    <form class="scan-form" method="POST"
          onsubmit="document.getElementById('load').hidden=false;this.querySelector('button[type=submit]').disabled=true">
      <label class="field">
        <span>Cible du laboratoire</span>
        <input type="text" name="cible" value="{{ cible or '192.168.1.42' }}" required>
      </label>
      <button class="btn-primary" type="submit">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="9"/><path d="M12 12l6-4"/>
        </svg>
        Lancer le scan Nmap
      </button>
      <div class="scan-loading" id="load" hidden>
        <span class="spin"></span> Scan + analyse IA en cours (10-30 s)…
      </div>
    </form>

    <div class="panel-head">
      <h2>Sources</h2>
      {% if resultats %}
      <span class="count-badge" id="count-sources">{{ resultats|length }} / {{ resultats|length }}</span>
      {% endif %}
    </div>

    <div class="panel-body">
      {% if resultats %}
        {% for r in resultats %}
        <div class="source" data-idx="{{ loop.index }}">
          <button class="source-main" type="button" title="Détails de la source">
            <span class="source-icon">
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                   stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/>
                <path d="M14 3v5h5"/><path d="M9 13h6M9 17h6"/>
              </svg>
            </span>
            <span style="min-width:0">
              <span class="source-name">{{ loop.index }} · {{ r.service }}</span>
              <span class="source-sub">Port {{ r.port }}/{{ r.protocole }} · {{ r.version }}</span>
            </span>
          </button>
          <input type="checkbox" class="src-check" data-idx="{{ loop.index }}"
                 checked title="Inclure cette source dans la discussion">
        </div>
        <div class="source-detail">
          <div><b>Hôte :</b> {{ r.hote }}</div>
          <div><b>État :</b> {{ r.etat }}</div>
          <div><b>Version :</b> {{ r.version }}</div>
        </div>
        {% endfor %}
      {% else %}
        <div class="empty">
          <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/>
            <path d="M14 3v5h5"/>
          </svg>
          <b>Aucune source pour l'instant</b>
          Lancez un scan sur la cible autorisée : chaque port ouvert
          devient une source citable par l'IA.
        </div>
      {% endif %}
    </div>
  </section>

  <!-- ============ DISCUSSION ============ -->
  <section class="panel panel-chat">
    <div class="chat-head">
      <div>
        <h2>Discussion</h2>
        <p>Les pastilles [n] renvoient aux sources du panneau de gauche.</p>
      </div>
      <span class="tag" title="Modèle d'analyse">gpt-oss-120b</span>
    </div>

    <div class="messages" id="messages">

      <div class="msg msg-assistant">
        <div class="avatar">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2l1.9 5.6L19.5 9l-4.4 3.6L16 18l-4-2.8L8 18l.9-5.4L4.5 9l5.6-1.4z"/>
          </svg>
        </div>
        <div class="bubble">
          <div class="msg-meta"><strong>Assistant IA</strong><span class="tag">TP1 · EC2LT</span></div>
          <p><svg class="ico-p" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
            <path d="M7.5 13.5V6.4a1.4 1.4 0 0 1 2.8 0v5.6"/>
            <path d="M10.3 12V4.6a1.4 1.4 0 0 1 2.8 0v7.4"/>
            <path d="M13.1 12V5.4a1.4 1.4 0 0 1 2.8 0v6.6"/>
            <path d="M15.9 13V8.4a1.4 1.4 0 0 1 2.8 0V15"/>
            <path d="M7.5 13.5v2A6.5 6.5 0 0 0 14 22h1.9a5.6 5.6 0 0 0 5.6-5.6v-3"/>
            <path d="M7.5 14.4l-2 3a1.6 1.6 0 0 0 2.7 1.7l1.4-2.1"/>
          </svg>Bonjour ! Je suis l'assistant pédagogique de ce carnet de scan.
          Chaque port ouvert détecté par Nmap devient une <strong>source</strong>
          sélectionnable dans le panneau de gauche.</p>
          {% if resultats %}
          <p><svg class="ico-p" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 11.5a8.5 8.5 0 0 1-8.5 8.5H4l2.3-2.3A8.5 8.5 0 1 1 21 11.5z"/>
            <path d="M8.5 11h7M8.5 14.5h4.5"/>
          </svg>Posez-moi une question sur les services détectés, ou
          cochez/décochez les sources à prendre en compte.</p>
          {% else %}
          <p><svg class="ico-p" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/>
            <path d="M12 12l6.4-6.4"/>
          </svg>Lancez d'abord un scan sur la cible autorisée pour charger
          les sources, puis revenez discuter ici.</p>
          {% endif %}
        </div>
      </div>

      {% if erreur %}
      <div class="msg msg-systeme">
        <div class="err">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
            <path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>
          </svg>
          <span>{{ erreur }}</span>
        </div>
      </div>
      {% endif %}

      {% if resultats is not none and resultats|length == 0 %}
      <div class="msg msg-systeme">
        <div class="err">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
            <path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>
          </svg>
          <span>Le scan ne rapporte aucun port ouvert : hôte
          injoignable, hors ligne, ou pare-feu filtrant tout le scan.</span>
        </div>
      </div>
      {% endif %}

      {% if synthese_html %}
      <div class="msg msg-assistant">
        <div class="avatar">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2l1.9 5.6L19.5 9l-4.4 3.6L16 18l-4-2.8L8 18l.9-5.4L4.5 9l5.6-1.4z"/>
          </svg>
        </div>
        <div class="bubble">
          <div class="msg-meta">
            <strong>Assistant IA</strong>
            <span class="tag">Synthèse du scan</span>
            {% if horodatage %}<span class="tag">{{ horodatage }}</span>{% endif %}
          </div>
          <div class="synthese">{{ synthese_html | safe }}</div>
        </div>
      </div>
      {% endif %}
    </div>

    {% if resultats %}
    <div class="suggestions">
      <button type="button" class="sugg">Quel est le rôle de chaque service détecté ?</button>
      <button type="button" class="sugg">Quels sont les risques les plus préoccupants ?</button>
      <button type="button" class="sugg">Que recommandes-tu de durcir en priorité ?</button>
    </div>
    {% endif %}

    <form class="composer" id="chat-form" autocomplete="off">
      <input id="chat-input" type="text"
             placeholder="{% if ia_dispo %}Posez une question sur les sources…{% else %}IA indisponible : clé GROQ_API_KEY manquante{% endif %}"
             {% if not ia_dispo %}disabled{% endif %}>
      <button class="send" id="chat-send" type="submit" disabled aria-label="Envoyer">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 19V5"/><path d="M5 12l7-7 7 7"/>
        </svg>
        <span class="spinner"></span>
      </button>
    </form>
  </section>

  <!-- ============ STUDIO ============ -->
  <section class="panel panel-studio">
    <div class="panel-head"><h2>Studio</h2></div>
    <div class="panel-body">

      <div class="studio-card">
        <h3>
          <span class="studio-icon">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>
            </svg>
          </span>
          Statistiques du scan
        </h3>
        <div class="stats">
          <div class="stat">
            <b>{% if resultats %}{{ resultats|length }}{% else %}—{% endif %}</b>
            <span>ports ouverts</span>
          </div>
          <div class="stat">
            <b>{% if resultats %}{{ resultats|map(attribute='service')|unique|list|length }}{% else %}—{% endif %}</b>
            <span>services distincts</span>
          </div>
          <div class="stat">
            <b style="font-size:13px">{% if cible %}{{ cible }}{% else %}—{% endif %}</b>
            <span>cible scannée</span>
          </div>
          <div class="stat">
            <b style="font-size:13px">{% if horodatage %}{{ horodatage }}{% else %}—{% endif %}</b>
            <span>horodatage</span>
          </div>
        </div>
      </div>

      <div class="studio-card">
        <div class="studio-head">
          <h3 style="margin-bottom:10px">
            <span class="studio-icon">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                   stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/>
                <path d="M14 3v5h5"/>
              </svg>
            </span>
            Synthèse du scan
          </h3>
          {% if synthese_html %}
          <button class="btn-ghost" id="copie" type="button">Copier</button>
          {% endif %}
        </div>
        {% if synthese_html %}
        <div class="doc synthese" id="doc-synthese">{{ synthese_html | safe }}</div>
        {% else %}
        <div class="empty" style="padding:18px 8px">
          <b>Rien à produire pour l'instant</b>
          La synthèse pédagogique s'affichera ici après un scan réussi.
        </div>
        {% endif %}
      </div>

      <div class="studio-card">
        <h3>
          <span class="studio-icon">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <path d="M22 10L12 5 2 10l10 5 10-5z"/>
              <path d="M6 12v5c0 1.7 2.7 3 6 3s6-1.3 6-3v-5"/>
            </svg>
          </span>
          Repères pédagogiques
        </h3>
        <div class="pill-list">
          <span class="pill">Un service = un rôle probable</span>
          <span class="pill">Une version détectée n'est pas une faille</span>
          <span class="pill">L'IA cite ses sources [n]</span>
          <span class="pill">Durcissement générique, jamais d'exploitation</span>
        </div>
      </div>

    </div>
  </section>
</main>

<script>
(function () {
  var messages  = document.getElementById('messages');
  var form      = document.getElementById('chat-form');
  var input     = document.getElementById('chat-input');
  var sendBtn   = document.getElementById('chat-send');
  var enCours   = false;

  function esc(t) {
    var d = document.createElement('div');
    d.textContent = t;
    return d.innerHTML;
  }
  function scrollBas() { messages.scrollTop = messages.scrollHeight; }
  function majBouton() {
    sendBtn.disabled = enCours || !input.value.trim();
  }

  var AVATAR =
    '<div class="avatar"><svg width="16" height="16" viewBox="0 0 24 24" ' +
    'fill="currentColor"><path d="M12 2l1.9 5.6L19.5 9l-4.4 3.6L16 18l-4-2.8' +
    'L8 18l.9-5.4L4.5 9l5.6-1.4z"/></svg></div>';
  var ICO_ERR =
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">' +
    '<path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>';
  var ICO_OK =
    '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" ' +
    'stroke="currentColor" stroke-width="2.4" stroke-linecap="round" ' +
    'stroke-linejoin="round"><path d="M4 12.5l5 5L20 6.5"/></svg>';

  function bulle(role, contenuHtml, metaHtml) {
    var wrap = document.createElement('div');
    if (role === 'user') {
      wrap.className = 'msg msg-user';
      wrap.innerHTML = '<div class="bubble">' + contenuHtml + '</div>';
    } else if (role === 'systeme') {
      wrap.className = 'msg msg-systeme';
      wrap.innerHTML = '<div class="err">' + ICO_ERR + '<span>' +
        contenuHtml + '</span></div>';
    } else {
      wrap.className = 'msg msg-assistant';
      wrap.innerHTML = AVATAR +
        '<div class="bubble">' +
        (metaHtml ? '<div class="msg-meta">' + metaHtml + '</div>' : '') +
        contenuHtml + '</div>';
    }
    messages.appendChild(wrap);
    scrollBas();
    return wrap;
  }

  /* ---- saisie / envoi ---- */
  if (input) { input.addEventListener('input', majBouton); }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    var question = (input.value || '').trim();
    if (!question || enCours) return;
    input.value = '';
    enCours = true;
    sendBtn.classList.add('busy');
    majBouton();
    bulle('user', esc(question));

    var indicateur = document.createElement('div');
    indicateur.className = 'msg msg-assistant';
    indicateur.innerHTML = AVATAR +
      '<div class="bubble"><div class="typing"><i></i><i></i><i></i></div></div>';
    messages.appendChild(indicateur);
    scrollBas();

    var inclus = Array.prototype.map.call(
      document.querySelectorAll('.src-check'),
      function (c) { return c.checked ? parseInt(c.dataset.idx, 10) : null; }
    ).filter(function (n) { return n !== null; });

    try {
      var r = await fetch('/api/question', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: question, sources: inclus })
      });
      var data = await r.json();
      indicateur.remove();
      if (data.erreur) {
        bulle('systeme', esc(data.erreur));
      } else {
        bulle('assistant', data.reponse_html,
              '<strong>Assistant IA</strong><span class="tag">' + inclus.length +
              ' source' + (inclus.length > 1 ? 's' : '') + ' incluse' +
              (inclus.length > 1 ? 's' : '') + '</span>');
      }
    } catch (err) {
      indicateur.remove();
      bulle('systeme', 'Impossible de joindre le serveur (' + esc(String(err)) + ').');
    } finally {
      enCours = false;
      sendBtn.classList.remove('busy');
      majBouton();
      if (!input.disabled) input.focus();
    }
  });

  /* ---- suggestions ---- */
  Array.prototype.forEach.call(document.querySelectorAll('.sugg'), function (b) {
    b.addEventListener('click', function () {
      if (enCours || !input || input.disabled) return;
      input.value = b.textContent.trim();
      majBouton();
      form.requestSubmit();
    });
  });

  /* ---- panneau sources : détails + cases à cocher ---- */
  Array.prototype.forEach.call(document.querySelectorAll('.source-main'), function (b) {
    b.addEventListener('click', function () {
      b.closest('.source').classList.toggle('open');
    });
  });
  var compteur = document.getElementById('count-sources');
  function majCompteur() {
    if (!compteur) return;
    var checks = document.querySelectorAll('.src-check');
    var n = document.querySelectorAll('.src-check:checked').length;
    compteur.textContent = n + ' / ' + checks.length;
  }
  Array.prototype.forEach.call(document.querySelectorAll('.src-check'), function (c) {
    c.addEventListener('change', majCompteur);
  });
  majCompteur();

  /* ---- copie de la synthèse ---- */
  var copie = document.getElementById('copie');
  if (copie) {
    copie.addEventListener('click', function () {
      var doc = document.getElementById('doc-synthese');
      if (!doc || !navigator.clipboard) return;
      navigator.clipboard.writeText(doc.innerText).then(function () {
        copie.innerHTML = ICO_OK + ' Copié';
        setTimeout(function () { copie.textContent = 'Copier'; }, 1500);
      });
    });
  }

  scrollBas();
  if (input && !input.disabled) input.focus();
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
