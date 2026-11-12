# DO7U — Plateforme communautaire complète

Projet autonome prêt à déployer : site public, espace membre et tableau de bord administrateur, avec backend Node.js sans framework et stockage JSON.

## Fonctionnalités
- Site public DO7U responsive.
- Connexion administrateur.
- Création, modification, archivage et réactivation des membres.
- Code membre DO7U généré automatiquement et PIN personnel (hashé avec scrypt).
- Cotisations mensuelles : confirmation réservée à l'admin, état payé/non payé, historique personnel du membre.
- Annonces/publicités administratives.
- Réactions « J'aime » et commentaires des membres.
- Discussions, avis et suggestions des membres avec modération admin.
- Réunions : calendrier, lieu, ordre du jour, présence et compte rendu.
- Stockage JSON sur disque persistant si configuré.

## Déploiement Render (recommandé)
1. Décompressez le ZIP.
2. Envoyez le dossier du projet dans un nouveau dépôt GitHub.
3. Dans Render, choisissez **New + > Blueprint** et connectez le dépôt contenant `render.yaml`.
4. Définissez `ADMIN_PASSWORD` avec un mot de passe long et unique (au moins 16 caractères). `ADMIN_USER` vaut `admin` par défaut, modifiable dans Render.
5. Le Blueprint configure un disque persistant monté sur `/var/data` et `DATA_DIR=/var/data`.
6. Déployez. L'application et l'API sont servies depuis le même domaine.

Si vous créez le service Web manuellement : Runtime Node, Build Command `npm install`, Start Command `npm start`; ajoutez `DATA_DIR=/var/data`, `ADMIN_USER=admin`, `ADMIN_PASSWORD=...`, et attachez un Persistent Disk au chemin `/var/data`.

## Pages
- Accueil : `/`
- Espace membre : `/member.html`
- Administration : `/admin.html`

## Première utilisation
1. Ouvrez `/admin.html`.
2. Connectez-vous avec l'identifiant `admin` et le mot de passe défini dans `ADMIN_PASSWORD`.
3. Dans Membres, créez les membres avec un PIN provisoire de 4 à 8 chiffres.
4. Remettez à chaque membre son code DO7U généré et son PIN de manière privée.
5. Le membre se connecte sur `/member.html`.

## Sécurité et limites à connaître
- Changez impérativement le mot de passe administrateur avant la mise en ligne. Le mot de passe de secours codé dans le serveur ne doit pas être utilisé en production.
- Le PIN n'est jamais stocké en clair.
- Les pages membres ne permettent pas de confirmer une cotisation : seul le backend admin peut le faire.
- Les sessions sont stockées en mémoire : un redémarrage du service déconnecte les sessions, mais les données JSON restent sur le disque persistant.
- Le JSON convient à un petit groupe. Pour une communauté à grande échelle ou des écritures simultanées fréquentes, migrer vers PostgreSQL.
- Ajoutez une politique de confidentialité et les coordonnées officielles du groupe avant d'ouvrir largement l'accès.
- Sauvegardez régulièrement le fichier `db.json`.

## Lancer localement
Node.js 18 ou plus récent :
```bash
npm start
```
Puis ouvrez `http://localhost:3000`. Pour définir le mot de passe admin sous PowerShell :
```powershell
$env:ADMIN_PASSWORD="UnMotDePasseLongEtUnique"
npm start
```
