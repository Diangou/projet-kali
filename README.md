# VulnScope

Framework de scan de vulnérabilités qui centralise **Trivy**, **Nmap**, **Nuclei** et
**Semgrep** derrière une interface web unique et un format de résultats commun.

> ⚠️ **À usage exclusif sur des cibles pour lesquelles vous possédez une
> autorisation écrite.** Chaque scan exige une confirmation d'autorisation,
> vérifiée côté serveur (pas seulement dans l'interface).

## Lancer le projet

Prérequis : Python 3.10+, et au moins un des quatre outils installé et sur le
`PATH` (`trivy`, `nmap`, `nuclei`, `semgrep`) — l'application détecte
automatiquement lesquels sont disponibles et désactive les autres proprement.

```bash
pip install semgrep flask   # + trivy/nmap/nuclei installés séparément (binaires CLI)
python -m webapp.app
```

Ouvrir http://127.0.0.1:5000. Depuis le Dashboard, "New Scan" ouvre une page
par outil : un champ, une case d'autorisation, un bouton.

## Lancer les tests

```bash
python -m pytest tests/
```

## Outils intégrés

| Outil | Rôle | Ce qu'il attend comme cible |
|---|---|---|
| **Trivy** | CVE d'images de conteneur et dépendances | une référence d'image (`bkimminich/juice-shop:latest`) |
| **Nmap** | Découverte réseau et services (profil rapide, top 100 ports) | une URL, dont l'hôte est extrait automatiquement |
| **Nuclei** | Détection par templates (CVE connues, mauvaises configs) | l'URL cible complète |
| **Semgrep** | Analyse statique de code source | un chemin local **ou** une URL de dépôt git (cloné automatiquement) |

## Architecture

```
vuln_scanner/
├── trivy_tool.py, nmap_tool.py, nuclei_tool.py, semgrep_tool.py  # un wrapper subprocess par outil
├── utils/
│   ├── models.py    # Vulnerability — le format commun que connaît l'UI
│   ├── severity.py  # normalize() : sévérité propre à chaque outil → échelle commune
│   └── mapper.py    # sortie native de chaque outil → list[Vulnerability]
└── scan_manager.py  # orchestrateur : un thread par moteur, état en mémoire

webapp/
├── app.py           # routes Flask (pages + API JSON)
├── templates/       # dashboard, sélecteur d'outil, page de scan, résultats, historique
└── static/          # CSS (thème sombre) + JS (fetch/polling, sans framework front)
```

Chaque scan expose la **commande exacte exécutée** (`GET /api/scans/<id>`),
affichée sur la page de résultats — utile pour la reproductibilité et le
débogage.

## Limites connues

- Autorisation **déclarative** (case à cocher vérifiée côté serveur), pas de
  liste blanche de périmètre appliquée techniquement.
- Historique des scans en mémoire — perdu au redémarrage du serveur.
- Aucune corrélation entre les résultats de différents outils, pas d'export
  de rapport (PDF/HTML).
- Ne couvre pas la logique métier (IDOR/BOLA, chaînes d'attaque
  multi-étapes) : les 4 outils reposent sur la comparaison à un référentiel
  connu (base CVE, templates, patterns AST), pas sur la compréhension des
  règles métier de l'application ciblée.
