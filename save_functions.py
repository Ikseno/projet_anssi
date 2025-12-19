import json

def sauvegarder_dict_en_json(dictionnaire, nom_fichier):
    with open(nom_fichier, 'w', encoding='utf-8') as f:
        json.dump(dictionnaire, f, indent=4, ensure_ascii=False)

def charger_json_en_dict(nom_fichier):
    try:
        with open(nom_fichier, 'r', encoding='utf-8') as f:
            # json.load transforme directement le fichier en dictionnaire Python
            donnees = json.load(f)
        return donnees
    except FileNotFoundError:
        print(f"Erreur : Le fichier '{nom_fichier}' n'a pas été trouvé.")
        return {}
    except json.JSONDecodeError:
        print(f"Erreur : Le fichier '{nom_fichier}' n'est pas un JSON valide.")
        return {}