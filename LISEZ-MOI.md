# Habitué — le code du logiciel

Carte de fidélité digitale pour commerces de proximité.
Site en HTML / CSS / JavaScript simples : rien à installer, rien à compiler.

## À quoi sert chaque fichier

| Fichier | Rôle |
|---|---|
| `index.html` | Page d'accueil (présentation, bouton d'inscription) |
| `service.html` | « Comment ça marche », tarif, questions fréquentes |
| `inscription.html` | Création du compte commerçant |
| `connexion.html` | Connexion + « mot de passe oublié » |
| `app/tableau-de-bord.html` | Chiffres du commerçant et derniers passages |
| `app/ma-carte.html` | Réglage de la carte, QR code, affiche à imprimer |
| `app/clients.html` | Liste des clients, recherche, suppression |
| `app/parametres.html` | Espace personnel : PIN, mot de passe, suppression du compte |
| `c.html` | La carte vue par le client après scan du QR code |
| `admin.html` | Ton interface d'administration (commerçants + messages) |
| `contact.html` | Formulaire de contact (messages visibles dans l'admin) |
| `confidentialite.html` | Politique de confidentialité |
| `css/style.css` | Toute l'apparence du site (couleurs, boutons, mobile) |
| `js/config.js` | **Le seul fichier à modifier** : adresse et clé de ta base Supabase |
| `js/common.js` | Code partagé : connexion à la base, menu, messages d'erreur |
| `assets/` | Le logo |
| `supabase/schema.sql` | La base de données : tables, règles de sécurité, fonctions |

## Comment la sécurité est assurée

- Le navigateur ne peut écrire dans aucune table directement. Toute écriture
  passe par une fonction de `schema.sql` qui vérifie les droits.
- Un commerçant ne peut lire que ses propres données (règles « RLS »).
- Le code PIN est stocké haché (illisible), jamais en clair. Il est vérifié
  côté serveur. Après 5 codes faux, la validation se bloque 15 minutes.
- Les mots de passe sont gérés par Supabase Auth, jamais par notre code.
- `js/config.js` ne contient que la clé publique. La clé secrète
  (`service_role`) ne doit jamais apparaître dans ce dossier.

## Limites connues du MVP

- Un client retrouve sa carte en redonnant le même téléphone ou e-mail.
  Quelqu'un qui connaît ce contact pourrait donc ouvrir la carte, mais pas
  ajouter de tampon (il faut le PIN du commerçant).
- Une seule carte par commerce. La liste des clients affiche les 1000 derniers.
- Pas de paiement en ligne : il sera ajouté en phase 7.
