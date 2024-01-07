import os
import sys
import lxml.etree as ET
import pandas as pd
from tqdm import tqdm
import ipaddress
from datetime import datetime
import binascii
import base64
import hashlib
import pickle

if len(sys.argv) != 3:
    print("Usage: python import_xml.py <path_to_folder_with_xml> <output_filename>")
    sys.exit(1)

# Dossier contenant les fichiers XML
folder_path = sys.argv[1]
output_filename = sys.argv[2]
output_filename = output_filename.replace('.pkl','')

noms_applications_uniques = {}
compteur_entiers_uniques = 1

# Liste pour stocker les noms des fichiers XML
xml_files = [file for file in os.listdir(folder_path) if file.endswith(".xml")]

if not xml_files:
    print("Aucun fichier XML trouvé dans le dossier spécifié.")
    sys.exit(1)

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

# Fonction de conversion pour les int
def convert_to_int(string, flow_dict, tag):
    string = str(string).strip()
    flow_dict[tag + '_int'] = int(float(string))
    return flow_dict

# Fonction de conversion pour duration
def convert_duration_to_int(duration, flow_dict, tag):
    duration = str(duration).strip()
    flow_dict[tag + '_int'] = int(float(duration) * 1000)
    return flow_dict

# Fonction pour attribuer une valeur en fonction des protocoles
def convert_protocol_en_entier(protocol, flow_dict, tag):
    protocol = str(protocol).strip()
    flags = ['UDP', 'TCP']
    # Initialisez toutes les valeurs à 0
    for flag in flags:
        flow_dict[tag + '_' + flag + '_int'] = 0

    if protocol is not None:
        if protocol in flags:
            flow_dict[tag + '_' + protocol + '_int'] = 1
        else
            print(f"Protocol inconnu : {prtocol}")

    return flow_dict

def convert_bytes_to_int(bytes_value, flow_dict, tag):
    string_value = bytes_value.decode("utf-8").strip()
    try:
        int_value = int(string_value)
    except ValueError:
        try:
            int_value = int(float(string_value))
        except ValueError:
            int_value = None  # Ou une autre valeur par défaut si nécessaire
    
    flow_dict[tag + '_int'] = int_value
    return flow_dict


def convert_tcp_flags_en_entier_challenge_2(tcp_flags, flow_dict, tag):
    # Initialisez toutes les valeurs à 0
    for flag in ['F', 'S', 'R', 'A', 'P', 'Illegal8','Illegal7','U']:
        flow_dict[tag + '_' + flag + '_int'] = 0

    if tcp_flags != "N/A" and tcp_flags is not None:
        tcp_flags = str(tcp_flags).replace('.','')
        flags = list(tcp_flags)
        for flag in flags:
            flag = flag.strip()
            if flag in ['F', 'S', 'R', 'A', 'P', 'Illegal8','Illegal7','U']:
                flow_dict[tag + '_' + flag + '_int'] = 1
            else:
                print(f"Drapeau TCP inconnu : {flag}")

    return flow_dict

    
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
        elif tag_string == 'normal':
            flow_dict[tag + '_int'] = 0
        elif tag_string == 'attacker':
            flow_dict[tag + '_int'] = 1
        elif tag_string == 'victim':
            flow_dict[tag + '_int'] = 2
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

if __name__ == "__main__":
    fonctions_conversion = lire_fichier_config()
    
    # Initialiser une liste pour stocker les données
    data_list = []
    
    # Pour chaque fichier XML du dossier
    for filename in tqdm(os.listdir(folder_path), desc="Processing XML files", unit="file"):
        if filename.endswith(".xml"):
            print("* Processing file " + filename)
            file_path = os.path.join(folder_path, filename)
    
            # Parse the XML file using lxml
            tree = ET.parse(file_path)
            root = tree.getroot()
    
            # Get the root element name (which depends on the file)
            root_element = root.tag
    
            # Loop through the flow elements and convert each flow to a dictionary
            for flow_elem in root.xpath("//*"):
                flow_dict = {}
                for child_elem in flow_elem.getchildren():
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
    
                flow_dict["origin_file"] = filename
                data_list.append(flow_dict)
    
    # Créer un DataFrame Pandas à partir de la liste de données
    df = pd.DataFrame(data_list)
    
    # Sauvegarder le DataFrame dans un fichier pickle
    df.to_pickle(output_filename + ".pkl")
    
    print(f"Data has been processed and saved to '{output_filename}.pkl'.")
