

# Projet Alertes ANSSI – Veille Automatisée des Vulnérabilités

##  Présentation

**Projet Alertes ANSSI** est un script Python de **veille cybersécurité automatisée** permettant de :

* Récupérer les **flux RSS officiels de l’ANSSI** (Alertes & Avis)
* Extraire automatiquement les **CVE associées**
* Enrichir les CVE via les APIs **MITRE (CVE)**,  **FIRST (EPSS)**,  **NVD (CWE)**
* Croiser les vulnérabilités avec le catalogue **CISA KEV** (exploitation active)
* Calculer une **criticité**
* Détecter les **vulnérabilités critiques**
* Générer et envoyer automatiquement une **alerte email** via **Brevo SMTP**

Ce projet simule un **outil SOC / RSSI** de surveillance continue des menaces.

---

##  Architecture du pipeline

```
Flux RSS ANSSI
   ├── Alertes
   └── Avis
        ↓
Extraction des CVE
        ↓
Enrichissement (MITRE / EPSS)
        ↓
Croisement CISA KEV
        ↓
Construction DataFrame
        ↓
Détection des alertes critiques
        ↓
Envoi email automatique
```

---

## Technologies utilisées

* **Python 3.9+**
* `feedparser` – Lecture des flux RSS
* `requests` – Appels API
* `pandas` – Manipulation de données
* `smtplib` – Envoi SMTP
* APIs externes :

  * ANSSI CERT-FR
  * MITRE CVE
  * FIRST EPSS
  * CISA KEV
  * Brevo SMTP

---



## Configuration


##  Mode LOCAL / ONLINE

```python
MODE_LOCAL = False
```

| Mode    | Description                                 |
| ------- | ------------------------------------------- |
| `False` | Télécharge les flux et bulletins en ligne   |
| `True`  | Utilise uniquement les fichiers JSON locaux |

---

## Sources de données

| Source     | Description                          |
| ---------- | ------------------------------------ |
| ANSSI RSS  | Bulletins Alertes & Avis             |
| MITRE CVE  | Détails CVE, CVSS, CWE               |
| FIRST EPSS | Probabilité d’exploitation           |
| CISA KEV   | Vulnérabilités exploitées activement |
| NVD        | Sources complémentaire pour les CWE  |

---

## Critères de détection des alertes

Une CVE est considérée **critique** si **au moins un** des critères suivants est vrai :

* **CVSS ≥ 9**
* **EPSS ≥ 0.8**
* **Présente dans le catalogue CISA KEV**

```python
(df["Score CVSS"] >= 9) OR
(df["Score EPSS"] >= 0.8) OR
(df["Exploitation Active (CISA)"] == "OUI")
```

---

## Contenu de l’email d’alerte

Chaque email contient :

* Introduction professionnelle
* Liste détaillée des CVE critiques
* Indicateur d’exploitation active
* Scores CVSS / EPSS
* Lien vers le bulletin ANSSI
* Recommandations
* Signature officielle

---

## Sorties générées

### Fichiers

| Fichier                   | Description              |
| ------------------------- | ------------------------ |
| `anssi_cve_dataframe.csv` | Tableau complet des CVE  |
| `flux_alerte.json`        | Cache flux Alertes       |
| `flux_avis.json`          | Cache flux Avis          |
| `details_cve_anssi.json`  | Cache enrichissement CVE |

---

## Exécution

```bash
python main.py
```

---




##  Interface Graphique (GUI)

Le projet inclut également une **interface graphique (GUI)** basée sur le même pipeline que la version en ligne de commande.

Cette interface permet de :

* Lancer le pipeline de veille **sans utiliser le terminal**
* Suivre visuellement l’avancement des différentes étapes
* Visualiser les résultats de manière plus accessible
* Rendre l’outil **utilisable par des profils non techniques** (RSSI, analystes, étudiants)

Le **moteur de collecte, d’enrichissement et de détection** est strictement identique au script principal, garantissant :

* la cohérence des résultats
* l’absence de duplication logique
* une maintenance simplifiée



---

## Notebook d’Analyse & Visualisation des Vulnérabilités

En complément du pipeline automatisé, le projet inclut un **notebook Jupyter** dédié à l’**analyse exploratoire**, la **visualisation** et la **priorisation des vulnérabilités détectées**.

### Fichier

```
notebook.ipynb
```

---

## Objectifs du notebook

Ce notebook a pour objectifs de :

* Exploiter le fichier de sortie `anssi_cve_dataframe.csv`
* Réaliser une **analyse statistique avancée** des vulnérabilités
* Visualiser les **tendances de sécurité**
* Aider à la **priorisation opérationnelle** des alertes
* Servir de **support décisionnel** pour un SOC ou un RSSI

---

## Contenu du notebook

### Chargement du dataset

* Import du fichier CSV généré par le pipeline
* Vérification de l’intégrité des données
* Génération de données factices si nécessaire (mode démonstration)

---

###  Nettoyage et préparation des données

* Conversion des scores CVSS et EPSS en valeurs numériques
* Gestion des valeurs manquantes
* Création d’une colonne **Gravité** basée sur le score CVSS :

  * Critique
  * Haute
  * Moyenne
  * Faible

---

### Analyse de la gravité (CVSS)

* Étude de la distribution des scores CVSS
* Identification des niveaux de risque dominants
* Mise en évidence de la proportion de failles critiques

 **Objectif** : comprendre le niveau global de menace

---

###  Analyse technique des vulnérabilités (CWE)

* Analyse des **types de failles les plus fréquentes**
* Classement des catégories CWE
* Identification des faiblesses structurelles récurrentes

 **Objectif** : cibler les failles de conception les plus communes

---

### Analyse croisée CVSS vs EPSS (Risque réel)

* Comparaison entre :

  * **Sévérité théorique (CVSS)**
  * **Probabilité réelle d’exploitation (EPSS)**
* Visualisation des vulnérabilités :

  * CVSS élevé + EPSS élevé → **Urgences absolues**
  * CVSS élevé + EPSS faible → Risque théorique
  * CVSS faible + EPSS élevé → Menace opportuniste

 **Analyse clé pour la priorisation SOC**

---

###  Analyse par éditeur (Vendor Analysis)

* Identification des éditeurs les plus impactés
* Analyse de la dispersion des scores
* Visualisation via **boxplots**

 **Objectif** : orienter les efforts de patch management

---

### Analyse temporelle

* Étude de l’évolution des vulnérabilités dans le temps
* Détection des périodes d’activité intense
* Visualisation des pics de publications

 **Objectif** : comprendre la dynamique des menaces

---

###  Synthèse pour le module d’alerte

* Filtrage final des vulnérabilités critiques
* Production du sous-ensemble utilisé par :

  * le **module d’emailing**
  * les **alertes automatiques**

 **Lien direct avec le pipeline d’envoi d’alertes**

---


##  Contexte académique

Projet réalisé dans le cadre du module Langage Python en A3 à l'ESILV.



