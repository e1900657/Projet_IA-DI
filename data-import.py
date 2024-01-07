# V3 : Intégration d'ElasticSearch

import os
import lxml.etree as ET
import shelve
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import urllib3

import ipaddress
from datetime import datetime
import binascii
import base64
import hashlib
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

noms_applications_uniques = {}

# Vérifier si le chemin du dossier est passé en argument
if len(sys.argv) != 2:
    print("Usage: python data_import.py <path_to_folder_with_xml>")
    sys.exit(1)

# Dossier contenant les fichiers XML
folder_path = sys.argv[1]

# Liste pour stocker les noms des fichiers XML
xml_files = [file for file in os.listdir(folder_path) if file.endswith(".xml")]

if not xml_files:
    print("Aucun fichier XML trouvé dans le dossier spécifié.")
    sys.exit(1)
    

# Nom de l'index Elastic Search 
elk_index = "search-test-projet-v2"

# Variable globale pour stocker le compteur d'entiers uniques
compteur_entiers_uniques = 1

# Initialisation de la connexion à Elasticsearch en fonction du prénom
def init_elasticsearch_connection():
    """
    Initialise la connexion à Elasticsearch.

    Args:

    Returns:
        es (elasticsearch.client.Elasticsearch): L'objet de connexion Elasticsearch.
    """

    es = Elasticsearch(
        "https://localhost:9200",
        api_key="YOUR API-KEY==",
        ca_certs="http_ca.crt"
    )
    
    if not es.ping():
        ELASTIC_PASSWORD = "XX"
        es = Elasticsearch(['https://localhost:9200'], basic_auth=('elastic', ELASTIC_PASSWORD), verify_certs=False)
        
        if not es.ping():
            prenom = input("Votre nom d'authentification : ")
            password = input('Votre mot de passe : ')
            es = Elasticsearch(['https://localhost:9200'], basic_auth=(prenom, password), verify_certs=False)
    
    return es

es = init_elasticsearch_connection()

if es.ping():
    print("Connected to Elasticsearch")
else:
    print("Could not connect to Elasticsearch")
    exit()

def lire_fichier_config(chemin_fichier = "config.txt"):
    # Dictionnaire pour stocker les fonctions de conversion
    config_functions = {}

    # Ouvrir le fichier de configuration en mode lecture
    with open(chemin_fichier, 'r') as file:
        for line in file:
            # Séparer le nom de l'attribut et la fonction de conversion
            attribut, fonction_conversion = line.strip().split('->')

            # Associer la fonction de conversion à l'attribut
            config_functions[attribut.strip()] = globals().get(fonction_conversion.strip())

    return config_functions



# Fonction de conversion pour les valeurs de type chaîne
def convert_string_en_entier(string_value, flow_dict, tag, max_int_size=2**31 - 1):
    try:
        int_value = int(string_value)
        while int_value > max_int_size:
            int_value %= (max_int_size)
        flow_dict[tag + '_int'] = int(int_value)
    except ValueError:
        flow_dict[tag + '_int'] = 0
    return flow_dict



# Fonction de conversion pour le nom de l'application
def convert_unique_en_entier(appName, flow_dict, tag):
    global compteur_entiers_uniques
    if appName in noms_applications_uniques:
        flow_dict[tag + '_int'] = noms_applications_uniques[appName]
    else:
        resultat = compteur_entiers_uniques
        noms_applications_uniques[appName] = resultat
        compteur_entiers_uniques += 1
        convert_string_en_entier(resultat, flow_dict, tag)
    return flow_dict


# Fonction pour attribuer une valeur en fonction des drapeaux TCP
def convert_tcp_flags_en_entier(tcp_flags, flow_dict, tag):
    # Initialisez toutes les valeurs à 0
    for flag in ['F', 'S', 'R', 'A', 'P', 'Illegal8','Illegal7','U']:
        flow_dict[tag + '_' + flag + '_int'] = 0

    if tcp_flags != "N/A" and tcp_flags is not None:
        flags = tcp_flags.split(',')
        for flag in flags:
            flag = flag.strip()
            if flag in ['F', 'S', 'R', 'A', 'P', 'Illegal8','Illegal7','U']:
                flow_dict[tag + '_' + flag + '_int'] = 1
            else:
                print(f"Drapeau TCP inconnu : {flag}")

    return flow_dict


# Fonction de conversion pour les adresses IP
def convert_ip_en_entier(ip_address, flow_dict, tag):
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        ip_packed = ip_obj.packed
        integer_value = int.from_bytes(ip_packed, byteorder='big')
        convert_string_en_entier(integer_value, flow_dict, tag)
    except (ValueError, ipaddress.AddressValueError):
        print(f"Erreur lors de la conversion de la valeur '{ip_address}' en entier à partir du format ip.")
        flow_dict[tag + '_int'] = 0
    return flow_dict

# Fonction de conversion pour les dates en entier
def convert_date_en_entier(date_string, flow_dict, tag):
    flow_dict[tag + '_int'] = 0
    if date_string is not None:  # Vérification pour éviter les valeurs None
        try:
            date_obj = datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S")
            timestamp = date_obj.timestamp()
            integer_value = int(timestamp)
            convert_string_en_entier(integer_value, flow_dict, tag)
        except ValueError:
            print(f"Erreur lors de la conversion de la valeur '{date_string}' en entier à partir du format date.")

    return flow_dict


# Fonction de conversion pour les valeurs en base64
def convert_base64_en_entier(base64_encoded, flow_dict, tag):
    flow_dict[tag + '_int'] = 0
    if base64_encoded is not None:  # Vérification pour éviter les valeurs None
        try:
            encoded_bytes = base64_encoded.encode('utf-8')
            decoded_bytes = base64.b64decode(encoded_bytes)
            integer_value = int.from_bytes(decoded_bytes, byteorder='big')
            convert_string_en_entier(integer_value, flow_dict, tag)
        except ValueError:
            print(f"Erreur lors de la conversion de la valeur '{base64_encoded}' en entier à partir du format base64.")
    return flow_dict


# Fonction de conversion pour le Tag
def convert_tag_en_entier(tag_string, flow_dict, tag):
    flow_dict[tag + '_int'] = 0
    if tag_string is not None:  # Vérification pour éviter les valeurs None
        if tag_string == 'Attack':
            flow_dict[tag + '_int'] = 1
        else:
            flow_dict[tag + '_int'] = 0
    return flow_dict


# Fonction de conversion pour les chaînes UTF-8
def convert_utf_en_entier(utf_string, flow_dict, tag):
    flow_dict[tag + '_int'] = 0
    if utf_string is not None:  # Vérification pour éviter les valeurs None
        try:
            cleaned_string = ''.join(char for char in utf_string if char.isprintable() and char.isascii())
            sha256_hash = hashlib.sha256(cleaned_string.encode('utf-8')).hexdigest()
            integer_value = int(sha256_hash, 16)
            convert_string_en_entier(integer_value, flow_dict, tag)
        except ValueError:
            print(f"Erreur lors de la conversion de la valeur '{utf_string}' en entier à partir du format utf.")
    return flow_dict


fonctions_conversion = lire_fichier_config()



# Define the mapping with a multi-field for protocolName
mapping = {
    "mappings": {
        "properties": {
            "protocolName": {
                "type": "text",
                "fields": {
                    "keyword": {
                        "type": "keyword"
                    }
                }
            },
            "appName": {
                "type": "text",
                "fields": {
                    "keyword": {
                        "type": "keyword"
                    }
                }
            }
        }
    }
}

# Création de l'index
es.options(ignore_status=400).indices.create(index=elk_index, body=mapping)  # Ignores l'erreur index existe déjà

# Initialize the shelve file for storage
# shelve_db = shelve.open("flow_data.db")

# Pour chaque fichier XML du dossier
for filename in os.listdir(folder_path):
    if filename.endswith(".xml"):
        print("* Indexing file " + filename)
        file_path = os.path.join(folder_path, filename)

        to_index = []

        # Parse the XML file using lxml
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Get the root element name (which depends on the file)
        root_element = root.tag

        # Initialize a list to store flow dictionaries
        flow_data = []

        flow_elements = root.xpath("//TestbedMonJun14Flows | //TestbedSatJun12 | //TestbedSunJun13Flows | //TestbedThuJun17-1Flows | //TestbedThuJun17-2Flows | //TestbedTueJun15-1Flows | //TestbedTueJun15-2Flows | //TestbedWedJun16-1Flows | //TestbedWedJun16-2Flows")

        # Loop through the flow elements and convert each flow to a dictionary
        for flow_elem in flow_elements:
            flow_dict = {}
            for child_elem in flow_elem.getchildren():
                if child_elem.tag == "Tag":
                    flow_dict[child_elem.tag] = child_elem.text
                else:
                    flow_dict[child_elem.tag] = int(child_elem.text) if child_elem.tag.endswith(("Bytes", "Packets", "Port")) else child_elem.text

                if child_elem.tag in fonctions_conversion:
                    fonction_conversion = fonctions_conversion[child_elem.tag]
                    if fonction_conversion:
                        flow_dict = fonction_conversion(child_elem.text, flow_dict, child_elem.tag)
                    else:
                        print(f"Aucune fonction de conversion définie pour {child_elem.tag}")
                elif child_elem.text == None:
                    flow_dict[child_elem.tag + '_int'] = 0
                else:
                    print(f"{child_elem.tag} n'est pas répertorié dans le dictionnaire fonctions_conversion.")
            flow_data.append(flow_dict)

        # Index the flow data in Elasticsearch with the origin file information
        for flow in flow_data:
            flow["origin_file"] = filename

            to_index.append({
                '_op_type': 'index',
                '_index': elk_index,
                '_source': flow
            })

        # Store the flow data in the shelve file with the root element name as the key
        # shelve_db[root_element] = flow_data

        success, failed = bulk(es, to_index, index=elk_index)

        # Check for successful and failed indexing operations
        print(f"Successfully indexed {success} documents.")

        if len(failed) > 0:
            print(f"Failed to index {failed} documents.")
            for idx, doc in enumerate(failed, start=1):
                print(f"Failed document #{idx}:")
                print(doc)
# Close the shelve file and Elasticsearch connection
# shelve_db.close()

es.close()
print('END')
