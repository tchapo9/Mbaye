<p align="center">
  <img src="static/moustique.png" alt="Logo de l'application" width="110">
</p>

<h1 align="center">TP1 — Scanner réseau enrichi par IA</h1>

<p align="center">
  Application web pédagogique (Flask) : scan Nmap d'une machine autorisée,
  synthèse IA et discussion avec citations de sources —<br>
  dans une interface inspirée de <b>Google NotebookLM</b>.
</p>

---

## Présentation

En une phrase : elle scanne un poste autorisé du laboratoire avec **Nmap**,
transforme chaque port ouvert en **« source » documentaire**, puis laisse un
**assistant IA** (modèle Groq `openai/gpt-oss-120b`) produire une synthèse
pédagogique et répondre aux questions de l'étudiant.

Ce TP illustre la compétence **« A7 — Collecte de données avec IA »** du
référentiel EC2LT : la collecte réseau est enrichie par une IA générative
encadrée (elle reste pédagogique et ne produit jamais de mode d'emploi
d'attaque).

### Fonctionnement en 4 étapes

| Étape | Action | Technologie |
|---|---|---|
| 1 | Saisie de la cible + contrôle de la **liste blanche** (refus 403 sinon) | Flask, `CIBLES_AUTORISEES` |
| 2 | Scan des ports avec détection de versions (`-sV -T4`) | Nmap + python-nmap |
| 3 | Synthèse Markdown structurée avec pastilles de citation `[n]` | API Groq — gpt-oss-120b |
| 4 | Questions de suivi : l'IA ne répond qu'à partir des **sources cochées** | Route `POST /api/question` |

## Fonctionnalités

- **Panneau Sources** — chaque port ouvert est une source cochable (service, port, version, détails dépliables).
- **Panneau Discussion** — chat avec l'IA, réponses en Markdown, **pastilles de citation `[n]`** renvoyant au service et au port exacts, questions suggérées, fil conservé sur 10 échanges.
- **Panneau Studio** — statistiques du scan, synthèse pédagogique copiable en un clic, repères du TP.
- **Interface NotebookLM** — mode clair/sombre automatique (`prefers-color-scheme`), mise en page responsive (desktop / tablette / mobile), icônes SVG natives.
- **États soignés** — chargement pendant le scan (10-30 s), indicateur de frappe IA, erreurs affichées dans le fil de discussion au lieu de planter.

## Prérequis

- **Python 3.10+** (testé sous 3.13) et `venv`
- Le binaire **Nmap** : `sudo apt install nmap`
- Une **clé d'API Groq** (gratuite sur <https://console.groq.com>)
- Le laboratoire : la cible autorisée est **`192.168.1.42`** (à ajuster dans `CIBLES_AUTORISEES`)

## Installation

```bash
# 1. Environnement virtuel isolé
python3 -m venv venv

# 2. Activation
source venv/bin/activate        # Windows : venv\Scripts\activate

# 3. Dépendances (Flask, python-nmap, Markdown, groq — versions épinglées)
pip install -r requirements.txt
```

## Configuration et démarrage

```bash
# Exporter la clé Groq (à faire à chaque session)
export GROQ_API_KEY=votre_cle

# Lancer le serveur
python app.py
```

Puis ouvrir **<http://localhost:5000>**.

## Utilisation

1. Saisir `192.168.1.42` dans le panneau **Sources** et lancer le scan.
2. Une fois la synthèse affichée, cocher les sources pertinentes (par défaut : toutes).
3. Poser une question dans le panneau **Discussion** — l'IA s'appuie uniquement sur les sources cochées et cite ses réponses avec des pastilles `[n]` survolables.
4. Utiliser le bouton **Copier** du Studio pour réutiliser la synthèse (compte rendu, rapport…).

Toute autre adresse que la cible autorisée renvoie une **page d'erreur 403** stylisée : c'est voulu (liste blanche côté serveur).

## Routes

| Méthode / Route | Rôle |
|---|---|
| `GET /` | Rendu de l'interface (état initial ou dernier scan) |
| `POST /` | Contrôle de la liste blanche, scan Nmap, génération de la synthèse |
| `POST /api/question` | Question de suivi du chat → JSON `{ reponse_html }` |

## Structure du projet

```
tp1_webapp/
├── app.py                                    # Application Flask unique (serveur + logique + interface)
├── requirements.txt                          # Dépendances Python épinglées
├── static/
│   └── moustique.png                         # Logo de l'application
├── venv/                                     # Environnement virtuel (non versionné)
└── .git/
```

## Sécurité et conformité pédagogique

- **Liste blanche côté serveur** : la cible est vérifiée dans le Python (`CIBLES_AUTORISEES`), pas seulement dans le formulaire.
- **Sorties IA assainies** : `<script>`, attributs `on*` et `<iframe>` retirés du Markdown rendu.
- **Prompts encadrés** : l'IA reste pédagogique et refuse les questions hors périmètre du scan.
- **Robustesse** : Nmap et le client Groq sont créés à la demande ; clé absente ou binaire manquant ⇒ message explicite dans l'interface.
- **Usage réservé au laboratoire** : l'application ne scanne que la machine de démonstration du TP.

## Dépannage

| Symptôme | Cause / solution |
|---|---|
| « IA indisponible : clé GROQ_API_KEY manquante » | `export GROQ_API_KEY=votre_cle` avant le lancement |
| « Nmap n'est pas disponible sur ce serveur » | `sudo apt install nmap` (ou droits insuffisants) |
| « Cible non autorisée » (403) | Comportement normal : seule `192.168.1.42` est scannable |
| Scan rapide mais aucun port affiché | Hôte injoignable ou pare-feu : vérifier la connectivité |
| Réponses IA lentes | Comptez 10-30 s (scan + appel du modèle) |

## Documentation

La documentation complète — installation illustrée, interface, sécurité,
architecture et guide de prise de capture — se trouve dans
[`Documentation_TP1_Scanner_reseau_IA.docx`](Documentation_TP1_Scanner_reseau_IA.docx)
(12 figures : captures de terminal pour la mise en place, captures de
l'interface pour la suite).

---

<p align="center">
  Laboratoire EC2LT · TP1 · Usage pédagogique uniquement — ne scanner que
  les machines dont vous avez l'autorisation.
</p>
