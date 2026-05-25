# 🏢 Badgeuse Pro — Auto-hébergée 100% RGPD

## Démarrage rapide

```bash
# 1. Installer les dépendances (une seule fois)
npm install

# 2. Lancer le serveur
node server.js
# ou en mode surveillance automatique :
npm run dev

# 3. Ouvrir dans le navigateur
http://localhost:3000
```

## Identifiants par défaut
- **Admin** : `admin` / `admin1234`
- ⚠️ **Changez le mot de passe** dès la première connexion (onglet Paramètres)

## Fonctionnalités

### Interface Employé
- Pavé numérique pour saisir son NIP (4–8 chiffres)
- Bouton **Arrivée** / **Départ**
- Protection anti-doublon (impossible de pointer deux arrivées consécutives)
- Affichage des derniers pointages du jour

### Interface Admin (onglet Administration)
- **Gestion employés** : Ajouter, modifier, activer/désactiver, supprimer
- **Historique** : Filtrer par date et par employé
- **Récapitulatif** : Vue synthèse par employé sur une période
- **Export CSV** : Compatible Excel (encodage UTF-8 BOM)
- **Changement de mot de passe**

## Conformité RGPD ✅
| Point | Détail |
|---|---|
| Localisation des données | Fichier `badgeuse.db` sur votre serveur uniquement |
| Tiers | Aucun — zéro appel externe |
| NIP | Hashés SHA-256, jamais stockés en clair |
| Sessions | Cookies HttpOnly + SameSite=Strict, expiration 8h |
| Export | CSV disponible pour droit d'accès RGPD |
| Suppression | Suppression complète d'un employé + ses pointages |

## Changer le port
```bash
PORT=8080 node server.js
```

## Sauvegarde
Sauvegardez simplement le fichier `badgeuse.db` — c'est toute votre base de données.

## Prérequis
- Node.js 18+
- Aucune base de données externe requise

## Structure des fichiers
```
badgeuse/
├── server.js      ← Serveur HTTP + API REST
├── index.html     ← Interface utilisateur (tout-en-un)
├── package.json   ← Dépendances
├── badgeuse.db    ← Base SQLite (créée au premier démarrage)
└── README.md      ← Ce fichier
```
