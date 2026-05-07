# 🛡️ Blacklist Checker — URL & e-mail anti-arnaque

Vérifiez en un clic si une URL ou un e-mail figure dans les listes noires officielles
(**AMF**, **ACPR**, **Banque de France** via ABE Info Service) et dans les principales
bases internationales de phishing et de malware (**URLhaus**, **OpenPhish**,
**Phishing.Database**).

> **428 000+ entrées** indexées · **mise à jour automatique** · 100 % côté navigateur,
> rien n'est envoyé sur un serveur.

---

## ⚡ Démo rapide

Lancez un petit serveur local pour tester :

```bash
python -m http.server 8000
# puis ouvrez http://localhost:8000
```

Ou bien déployez gratuitement sur **GitHub Pages** (voir plus bas).

---

## 🌐 Mise en ligne sur GitHub Pages (recommandé)

1. **Créez un dépôt GitHub** (par exemple `blacklist-checker`) puis poussez le contenu de
   ce dossier :
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/VOTRE-USER/blacklist-checker.git
   git push -u origin main
   ```

2. **Activez GitHub Pages** :
   `Settings` → `Pages` → *Source* : **Deploy from a branch** → `main` / `/ (root)` →
   **Save**.

3. Quelques secondes plus tard, votre site est en ligne sur :
   `https://VOTRE-USER.github.io/blacklist-checker/`

4. (Optionnel) Activez l'**action de mise à jour automatique** : `Settings` → `Actions`
   → `General` → cochez **Allow all actions**, puis **Workflow permissions** → cochez
   **Read and write permissions**. Le fichier
   `.github/workflows/update-blacklist.yml` rafraîchira la base **chaque jour à 4 h
   UTC**.

---

## 🗂️ Structure du projet

```
.
├── index.html                 # Page principale
├── assets/
│   ├── style.css              # Thème sombre, design moderne
│   └── app.js                 # Recherche + parcours de la base
├── data/
│   ├── meta.json              # Stats + métadonnées (1 Ko)
│   ├── abe.json               # Liste ABE détaillée (1.5 Mo)
│   └── blacklist.txt          # Index compact pour lookup (25 Mo)
├── scripts/
│   └── build_blacklist.py     # Pipeline de construction de la base
└── .github/workflows/
    └── update-blacklist.yml   # Mise à jour automatique quotidienne
```

---

## 🔄 Reconstruire / mettre à jour la base

Le script télécharge **toutes les sources automatiquement** — aucun fichier local requis,
aucune dépendance à installer (Python 3 standard suffit).

```bash
python scripts/build_blacklist.py
```

Trois fichiers sont régénérés dans `data/` :

| Fichier            | Contenu                                     |
|--------------------|---------------------------------------------|
| `meta.json`        | Statistiques globales + descriptifs sources |
| `abe.json`         | Liste ABE Info Service complète             |
| `blacklist.txt`    | Index compact pour la vérification rapide   |

---

## 📡 Sources de données

| Source                | Volume     | Endpoint utilisé                                                        |
|-----------------------|------------|-------------------------------------------------------------------------|
| **ABE Info Service**  | ~9 400     | `https://www.abe-infoservice.fr/fr/abeis-liste-noire.csv` (CSV officiel) |
| **URLhaus**           | ~27 000    | `https://urlhaus.abuse.ch/downloads/csv_recent/`                        |
| **OpenPhish**         | ~270       | `https://openphish.com/feed.txt`                                        |
| **Phishing.Database** | ~390 000   | `Phishing.Database/phishing-domains-ACTIVE.txt` (mitchellkrogza)        |

**Toutes les sources sont récupérées automatiquement** par le workflow GitHub Action
(quotidien à 4 h UTC) — aucune intervention manuelle, aucun fichier à uploader.

---

## 🔒 Confidentialité

L'application est **100 % statique** : aucune requête vers un backend, aucune analytique,
aucun cookie. Votre saisie ne quitte jamais le navigateur. La base est téléchargée
en bloc une fois (~25 Mo, mise en cache par le navigateur ensuite).

---

## ⚠️ Limites importantes

- L'**absence** d'un domaine ou d'un e-mail dans la base **ne garantit pas** qu'il soit
  fiable — les escrocs créent en permanence de nouveaux domaines.
- En cas de doute, vérifiez directement sur
  [abe-infoservice.fr](https://www.abe-infoservice.fr/).
- L'outil est fourni **à but informatif** et **sans garantie**.

---

## 📜 Licence

Code MIT. Les listes proviennent de bases publiques — chaque source a sa propre
licence (référez-vous à leurs pages).
