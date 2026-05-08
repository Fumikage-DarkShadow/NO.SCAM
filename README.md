# 🛡️ NOSCAM — Détecteur d'arnaques URL & e-mail

Vérifiez en un clic si une URL ou un e-mail figure dans les listes noires officielles
**AMF**, **ACPR**, **Banque de France** (via ABE Info Service) et dans les principales
bases internationales de phishing et malware (**URLhaus**, **OpenPhish**, **Phishing.Database**).

> **428 000+ domaines & e-mails** indexés · **mise à jour quotidienne automatique** ·
> 100 % côté navigateur, aucune donnée envoyée à un serveur.

---

## 🌐 Tester directement en ligne

# 👉 **[https://fumikage-darkshadow.github.io/NO.SCAM/](https://fumikage-darkshadow.github.io/NO.SCAM/)**

Aucune installation nécessaire. Ouvrez le lien, collez une URL ou un e-mail, cliquez
sur **Vérifier** — c'est tout.

Exemples à tester :
- `cashlum.com` → 🚨 dans la liste noire AMF
- `paris-titrisation.fr` → 🚨 (entrée du 30 avril 2026)
- `google.com` → ✅ propre

---

## 🔄 Comment la base se met à jour automatiquement

Aucune intervention manuelle. Un workflow GitHub Actions tourne **chaque jour à 4 h UTC**
([.github/workflows/update-blacklist.yml](.github/workflows/update-blacklist.yml))
et exécute [scripts/build_blacklist.py](scripts/build_blacklist.py), qui :

1. Télécharge le **CSV officiel** de l'ABE Info Service
   `https://www.abe-infoservice.fr/fr/abeis-liste-noire.csv`
   → ~9 400 URLs et e-mails certifiés AMF/ACPR/Banque de France.
2. Télécharge la liste **URLhaus** d'abuse.ch
   `https://urlhaus.abuse.ch/downloads/csv_recent/`
   → ~27 000 URLs distribuant du malware.
3. Télécharge le flux **OpenPhish**
   `https://openphish.com/feed.txt`
   → ~270 URLs de phishing récentes.
4. Télécharge **Phishing.Database**
   `mitchellkrogza/Phishing.Database/phishing-domains-ACTIVE.txt`
   → ~390 000 domaines de phishing actifs.
5. **Fusionne, déduplique** sur `(type, valeur)` → un seul ensemble de 428 000 entrées.
6. Régénère trois fichiers dans `data/` :
   - `meta.json` — stats globales (1 Ko).
   - `blacklist.txt` — index compact `type|valeur|source|catégorie` (25 Mo, gzippé par GitHub Pages).
   - `abe.json` — métadonnées détaillées de la liste française.
7. Si le contenu a changé, **commit et push automatique** par `github-actions[bot]`.
   GitHub Pages redéploie le site sous 30 s.

Ce qui se passe côté navigateur quand quelqu'un visite le site :
1. Téléchargement de `meta.json` (1 Ko) + `blacklist.txt` (25 Mo gzippé → ~5 Mo réseau).
2. Indexation des 428 000 lignes en mémoire (Set par source) en moins de 2 secondes.
3. Toute vérification est ensuite **instantanée** et **locale** — la saisie ne quitte pas
   ta machine.

---

## 💻 Lancer le projet en local

Pour modifier le code ou tester sans déployer :

```bash
# 1) Cloner le repo
git clone https://github.com/Fumikage-DarkShadow/NO.SCAM.git
cd NO.SCAM

# 2) (Optionnel) Régénérer la base de données depuis les sources fraîches
#    Aucune dépendance Python à installer : juste la lib standard.
python scripts/build_blacklist.py

# 3) Servir le site en local — un simple serveur HTTP suffit
python -m http.server 8000
```

Puis ouvre **http://localhost:8000** dans ton navigateur.

> ⚠️ N'ouvre pas `index.html` directement avec `file://` : les `fetch()` JavaScript
> ne marchent pas en `file://`, il faut un vrai serveur HTTP local.

---

## 🗂️ Structure du projet

```
.
├── index.html                 # Page principale
├── assets/
│   ├── style.css              # Thème noir/rouge anti-scam
│   └── app.js                 # Recherche + indexation côté navigateur
├── data/
│   ├── meta.json              # Stats + liste des sources (1 Ko)
│   ├── abe.json               # Liste ABE Info Service (1.5 Mo)
│   └── blacklist.txt          # Index compact (25 Mo)
├── scripts/
│   └── build_blacklist.py     # Pipeline de construction de la base
├── .github/workflows/
│   └── update-blacklist.yml   # Mise à jour automatique quotidienne
└── deploy.ps1                 # Script de déploiement (Windows)
```

---

## 🔒 Confidentialité & limites

- **100 % statique** : aucun backend, aucune analytique, aucun cookie. Toute
  vérification se fait dans ton navigateur.
- **Limites** : l'absence d'un domaine ou d'un e-mail dans la base ne garantit
  *pas* qu'il soit fiable — les escrocs créent en permanence de nouveaux domaines.
  En cas de doute, vérifie directement sur
  [abe-infoservice.fr](https://www.abe-infoservice.fr/).
- L'outil est fourni **à but informatif** et **sans garantie**.

---

## 📜 Licence

Code MIT. Les listes noires proviennent de bases publiques — chaque source a sa
propre licence (voir leurs pages d'origine).
