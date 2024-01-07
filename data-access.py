# Accès aux données
# Voici quelques requêtes sur nos données indexées dans Elasticsearch

from elasticsearch import Elasticsearch
from tabulate import tabulate as tabulate_function
import urllib3
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        api_key="YOUR API KEY==",
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

# Nom de l'index Elastic Search 
index_name = "search-test-projet-v2"

def get_distinct_protocols(es, index='search-test-projet-v2'):
    """
    Obtient la liste des protocoles distincts présents dans le champ 'protocolName' de l'index Elasticsearch spécifié.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.

    Returns:
        list: Liste des protocoles distincts.
    """
    # Définissez la requête d'agrégation
    aggregation = {
        "distinct_protocols": {
            "terms": {
                "field": "protocolName.keyword",  # Utilisez le champ de protocole
                "size": 100,  # Ajustez la taille selon vos besoins
            }
        }
    }
    # Exécutez la requête d'agrégation
    response = es.search(index=index, aggs=aggregation, size=0)
    # Récupérez les résultats de l'agrégation
    distinct_protocols =  [bucket['key'] for bucket in response['aggregations']['distinct_protocols']['buckets']]
    
    return distinct_protocols

def get_protocols_count(es, index='search-test-projet-v2'):
    """
    Obtient la liste des protocoles distincts présents dans le champ 'protocolName' de l'index Elasticsearch spécifié.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.

    Returns:
        reponse: reponse protocoles.
    """
    # Définissez la requête d'agrégation
    aggregation = {
        "distinct_protocols": {
            "terms": {
                "field": "protocolName.keyword",  # Utilisez le champ de protocole
                "size": 100,  # Ajustez la taille selon vos besoins
            }
        }
    }
    # Exécutez la requête d'agrégation
    response = es.search(index=index, aggs=aggregation, size=0)
    protocol_counts = response['aggregations']['distinct_protocols']['buckets']

    return protocol_counts


def afficher_distinct_protocol_tabulate(es,index='search-test-projet-v2'):
    """
    Affiche les protocoles en utilisant la bibliothèque 'tabulate'.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.
    """

    # Appel de la fonction pour obtenir les protocoles distincts
    distinct_protocols_list = get_distinct_protocols(es, index)
    print("* Liste des protocoles :")
    # Créez une liste de tuples à partir des données
    # Noms des colonnes
    colonnes = ["Protocole"]

    # Utilisez la fonction renommée 'tabulate_function' pour formater les données en tableau
    tableau = tabulate_function([(protocole,) for protocole in distinct_protocols_list], headers=colonnes, tablefmt="fancy_grid")
    print(tableau)


def get_flows_by_protocol(protocol_to_search, index='search-test-projet-v2', size=10):
    """
    Retrieves a list of flows for a given protocol from Elasticsearch.

    Args:
        protocol_name (str): The protocol name to filter flows.
        index (str): The Elasticsearch index to search in.
        size (int): The number of flows to retrieve.

    Returns:
        list: A list of flow documents matching the protocol name.
    """

    # Définissez la requête de recherche avec un filtre sur le champ protocolName
    search_query = {
        "match": {
            "protocolName": protocol_to_search
        }
    }

    # Exécutez la requête de recherche
    response = es.search(index=index, query=search_query)
    return response


# Définissez le protocole que vous recherchez
protocol_to_search = 'icmp_ip'

flows = get_flows_by_protocol(protocol_to_search,index_name)

# Liste des flows pour un protocole donné
print("* Liste des flows pour un protocole :")

# Exécutez la requête de recherche
total = flows['hits']['total']['value']

print("TOTAL :", total)

# Récupérez les résultats de la recherche


hits = flows['hits']['hits']
# Affichez les flows pour le protocole donné
#print(f"Liste des flows pour le protocole '{protocol_to_search}':")
#afficher_flows_par_protocole(hits)
#for hit in hits:
#    flow = hit['_source']
#    print(flow)

# Nombre de flows pour chaque protocole

# Récupérez les résultats de l'agrégation


def afficher_protocol_counts_tabulate(es, index='search-test-projet-v2'):
    """
    Affiche le nombre de flows pour chaque protocole en utilisant la bibliothèque 'tabulate'.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.
    """

    protocol_counts = get_protocols_count(es,index)

    print("* Nombre de flows pour chaque protocole :")
    # Créez une liste de tuples à partir des données
    data_tuples = [(entry['key'], entry['doc_count']) for entry in protocol_counts]

    # Noms des colonnes
    colonnes = ["Protocole", "Nombre de Flows"]

    # Utilisez la fonction renommée 'tabulate_function' pour formater les données en tableau
    tableau = tabulate_function(data_tuples, headers=colonnes, tablefmt="fancy_grid")
    print(tableau)


def get_payload_lengths_by_protocol(es, index='search-test-projet-v2'):
    """
    Récupère la longueur en octets des données encodées en Base64 pour les champs
    'destinationPayloadAsBase64' et 'sourcePayloadAsBase64' pour chaque protocole.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.

    Returns:
        list: Liste de tuples contenant le nom du protocole, les longueurs des données source
        et les longueurs des données destination en octets.
    """
    # Définissez la requête d'agrégation
    aggregation = {
        "protocols": {
            "terms": {
                "field": "protocolName.keyword",
                "size": 1000
            },
            "aggs": {
                "payload_source": {
                    "terms": {
                        "field": "sourcePayloadAsBase64.keyword",
                        "size": 1000
                    }
                },
                "payload_destination": {
                    "terms": {
                        "field": "destinationPayloadAsBase64.keyword",
                        "size": 1000
                    }
                }
            }
        }
    }

    response = es.search(index=index, aggs=aggregation, size=0)
    protocol_buckets = response['aggregations']['protocols']['buckets']

    data_tuples = []
    
    for protocol_data in protocol_buckets:
        protocol_name = protocol_data['key']
        payload_source_terms = protocol_data['payload_source']['buckets']
        payload_destination_terms = protocol_data['payload_destination']['buckets']

        # Calculer la longueur totale en octets des données encodées en Base64 pour chaque protocole
        total_source_length = sum(len(base64.b64decode(term['key'])) for term in payload_source_terms)
        total_destination_length = sum(len(base64.b64decode(term['key'])) for term in payload_destination_terms)


        # Ajouter les longueurs calculées à la liste des tuples de données
        data_tuples.append((protocol_name, total_source_length, total_destination_length))

    return data_tuples


def afficher_payload_par_protocole(es, index='search-test-projet-v2'):
    """
    Affiche la taille des payload source et destination pour chaque protocole en utilisant 'tabulate'.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.
    """
    print("* Tableau des Total Payload par Protocole :")
    total_bytes_by_protocol = get_payload_lengths_by_protocol(es, index)


    colonnes = ["Protocole", "Total Source Payload (bytes)", "Total Destination Payload (bytes)"]

    tableau = tabulate_function(total_bytes_by_protocol, headers=colonnes, tablefmt="fancy_grid")
    print(tableau)


def get_total_bytes_by_protocol(es, index='search-test-projet-v2'):
    """
    Récupère la taille en byte source et destination pour chaque protocole dans Elasticsearch.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.

    Returns:
        list: Liste de dictionnaires contenant la taille en byte pour chaque protocole.
    """
    # Définissez la requête d'agrégation
    aggregation = {
        "protocols": {
            "terms": {
                "field": "protocolName.keyword",
                "size": 1000
            },
            "aggs": {
                "total_source_bytes": {
                    "sum": {
                        "field": "totalSourceBytes"
                    }
                },
                "total_destination_bytes": {
                    "sum": {
                        "field": "totalDestinationBytes"
                    }
                }
            }
        }
    }

    response = es.search(index=index, aggs=aggregation, size=0)


    protocol_buckets = response['aggregations']['protocols']['buckets']

    return protocol_buckets

def afficher_total_bytes_par_protocole(es, index='search-test-projet-v2'):
    """
    Affiche la taille de byte source et destination pour chaque protocole en utilisant 'tabulate'.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.
    """
    print("* Tableau des Total Bytes par Protocole :")
    total_bytes_by_protocol = get_total_bytes_by_protocol(es, index)

    data_tuples = [(protocol_data['key'], protocol_data['total_source_bytes']['value'], protocol_data['total_destination_bytes']['value']) for protocol_data in total_bytes_by_protocol]

    colonnes = ["Protocole", "Total Source Bytes", "Total Destination Bytes"]

    tableau = tabulate_function(data_tuples, headers=colonnes, tablefmt="fancy_grid")
    print(tableau)


# Nombre total de paquets en source et destination pour chaque protocole


def get_total_packets_by_protocol(es, index='search-test-projet-v2'):
    """
    Récupère le nombre total de paquets en source et destination pour chaque protocole dans Elasticsearch.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.

    Returns:
        list: Liste de dictionnaires contenant le nombre total de paquets pour chaque protocole.
    """
    # Définissez la requête d'agrégation
    aggregation = {
        "protocols": {
            "terms": {
                "field": "protocolName.keyword",
                "size": 1000
            },
            "aggs": {
                "total_source_packets": {
                    "sum": {
                        "field": "totalSourcePackets"
                    }
                },
                "total_destination_packets": {
                    "sum": {
                        "field": "totalDestinationPackets"
                    }
                }
            }
        }
    }

    response = es.search(index=index, aggs=aggregation, size=0)

    protocol_buckets = response['aggregations']['protocols']['buckets']

    return protocol_buckets

def afficher_total_packets_par_protocole(es, index='search-test-projet-v2'):
    """
    Affiche le nombre total de paquets en source et destination pour chaque protocole en utilisant 'tabulate'.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.
    """
    print("* Tableau des Total Packets par Protocole :")
    total_packets_by_protocol = get_total_packets_by_protocol(es, index)

    data_tuples = [(protocol_data['key'], protocol_data['total_source_packets']['value'], protocol_data['total_destination_packets']['value']) for protocol_data in total_packets_by_protocol]

    colonnes = ["Protocole", "Total Source Packets", "Total Destination Packets"]

    tableau = tabulate_function(data_tuples, headers=colonnes, tablefmt="fancy_grid")
    print(tableau)



def get_distinct_applications(es, index='search-test-projet-v2'):
    """
    Obtient la liste des applications distinctes présentes dans le champ 'appName' de l'index Elasticsearch spécifié.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.

    Returns:
        list: Liste des applications distinctes.
    """
    # Définissez la requête d'agrégation
    aggregation = {
        "distinct_apps": {
            "terms": {
                "field": "appName.keyword",  # Utilisez le champ de l'application
                "size": 1000,  # Ajustez la taille selon vos besoins
            }
        }
    }
    # Exécutez la requête d'agrégation
    response = es.search(index=index, aggs=aggregation, size=0)
    # Récupérez les résultats de l'agrégation
    distinct_apps = [bucket['key'] for bucket in response['aggregations']['distinct_apps']['buckets']]

    return distinct_apps

def afficher_distinct_applications_tabulate(es, index='search-test-projet-v2'):
    """
    Affiche les applications distinctes en utilisant la bibliothèque 'tabulate'.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.
    """
    # Appel de la fonction pour obtenir les applications distinctes
    distinct_applications_list = get_distinct_applications(es, index)
    print("* Liste des applications distinctes :")
    # Créez une liste de tuples à partir des données
    data_tuples = [(app,) for app in distinct_applications_list]

    # Noms des colonnes
    colonnes = ["Application"]

    # Utilisez la fonction renommée 'tabulate_function' pour formater les données en tableau
    tableau = tabulate_function(data_tuples, headers=colonnes, tablefmt="fancy_grid")
    print(tableau)


def get_flows_by_application(application_to_search, es, index='search-test-projet-v2'):
    """
    Récupère une liste de flux pour une application donnée à partir d'Elasticsearch.

    Args:
        application_to_search (str): Le nom de l'application pour filtrer les flux.
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): L'index Elasticsearch à interroger.

    Returns:
        list: Une liste de documents de flux correspondant au nom de l'application.
    """
    # Définissez la requête de recherche avec un filtre sur le champ 'appName'
    search_query = {
        "match": {
            "appName.keyword": application_to_search
        }
    }

    # Exécutez la requête de recherche
    response = es.search(index=index, query=search_query)
    return response

def afficher_flows_par_application_tabulate(es, application_to_search, index='search-test-projet-v2'):
    """
    Affiche la liste des flux pour une application donnée en utilisant la bibliothèque 'tabulate'.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        application_to_search (str): Le nom de l'application pour filtrer les flux.
        index (str): L'index Elasticsearch à interroger.
    """
    # Obtenez les flux pour l'application spécifiée
    flows = get_flows_by_application(application_to_search, es, index)
    
    print(f"* Liste des flux pour l'application '{application_to_search}':")

    # Vérifiez s'il y a des résultats
    total = flows['hits']['total']['value']
    if total == 0:
        print("Aucun flux trouvé pour cette application.")
        return

    # Récupérez les résultats de la recherche
    hits = flows['hits']['hits']
    
    # Créez une liste de données de flux
    data = []
    for hit in hits:
        flow = hit['_source']
        data.append((flow['source'], flow['destination'], flow['sourcePort'], flow['destinationPort']))

    # Définissez les noms des colonnes
    colonnes = ["Adresse IP source", "Adresse IP de destination", "Port source", "Port de destination"]

    # Utilisez la fonction 'tabulate_function' pour formater les données sous forme de tableau
    tableau = tabulate_function(data, headers=colonnes, tablefmt="fancy_grid")
    print(tableau)



def get_flows_count_by_application(es, index='search-test-projet-v2'):
    """
    Obtient le nombre de flux pour chaque application à partir de l'index Elasticsearch.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.

    Returns:
        list: Liste de dictionnaires contenant le nom de l'application et le nombre de flux.
    """
    # Définissez la requête d'agrégation
    aggregation = {
        "flows_count_by_app": {
            "terms": {
                "field": "appName.keyword",  # Utilisez le champ de l'application
                "size": 1000,  # Ajustez la taille selon vos besoins
            }
        }
    }
    # Exécutez la requête d'agrégation
    response = es.search(index=index, aggs=aggregation, size=0)
    
    # Récupérez les résultats de l'agrégation
    flows_count_by_app = []
    for bucket in response['aggregations']['flows_count_by_app']['buckets']:
        app_name = bucket['key']
        flow_count = bucket['doc_count']
        flows_count_by_app.append({"Application": app_name, "Nombre de Flux": flow_count})

    return flows_count_by_app

def afficher_nombre_flows_par_application_tabulate(es, index='search-test-projet-v2'):
    """
    Affiche le nombre de flux pour chaque application en utilisant la bibliothèque 'tabulate'.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.
    """
    # Appel de la fonction pour obtenir le nombre de flux par application
    flows_count_by_application = get_flows_count_by_application(es, index)
    
    print("* Nombre de flux pour chaque application :")

    # Vérifiez s'il y a des résultats
    if not flows_count_by_application:
        print("Aucun flux trouvé.")
        return

    # Utilisez la fonction 'tabulate_function' pour formater les données sous forme de tableau
    tableau = tabulate_function(flows_count_by_application, headers="keys", tablefmt="fancy_grid")
    print(tableau)



def get_payload_sizes_by_application(es, index='search-test-projet-v2'):
    """
    Récupère la taille des charges utiles source et destination pour chaque application en utilisant la longueur des données
    encodées en Base64.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.

    Returns:
        list: Liste de dictionnaires contenant le nom de l'application, la taille des charges utiles source
        et la taille des charges utiles destination.
    """
    # Définissez la requête d'agrégation
    aggregation = {
        "payload_sizes_by_app": {
            "terms": {
                "field": "appName.keyword",  # Utilisez le champ de l'application
                "size": 1000,  # Ajustez la taille selon vos besoins
            },
            "aggs": {
                "source_payload_size": {
                    "terms": {
                        "field": "sourcePayloadAsBase64.keyword",
                        "size": 1000
                    }
                },
                "destination_payload_size": {
                    "terms": {
                        "field": "destinationPayloadAsBase64.keyword",
                        "size": 1000
                    }
                }
            }
        }
    }
    # Exécutez la requête d'agrégation
    response = es.search(index=index, aggs=aggregation, size=0)
    
    # Récupérez les résultats de l'agrégation
    payload_sizes_by_app = []
    for bucket in response['aggregations']['payload_sizes_by_app']['buckets']:
        app_name = bucket['key']
        source_payload_terms = bucket['source_payload_size']['buckets']
        destination_payload_terms = bucket['destination_payload_size']['buckets']

        # Calculer la longueur totale des charges utiles source et destination en octets en décodant Base64
        total_source_length = sum(len(base64.b64decode(term['key'])) for term in source_payload_terms)
        total_destination_length = sum(len(base64.b64decode(term['key'])) for term in destination_payload_terms)

        # Ajouter les longueurs calculées à la liste des dictionnaires de données
        payload_sizes_by_app.append({
            "Application": app_name,
            "Taille Charges Utiles Source (octets)": total_source_length,
            "Taille Charges Utiles Destination (octets)": total_destination_length
        })

    return payload_sizes_by_app

def afficher_taille_charges_utiles_par_application_tabulate(es, index='search-test-projet-v2'):
    """
    Affiche la taille des charges utiles source et destination pour chaque application en utilisant la bibliothèque 'tabulate'.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.
    """
    # Appel de la fonction pour obtenir la taille des charges utiles par application
    payload_sizes_by_application = get_payload_sizes_by_application(es, index)
    
    print("* Taille des Charges Utiles Source et Destination pour Chaque Application :")

    # Vérifiez s'il y a des résultats
    if not payload_sizes_by_application:
        print("Aucune donnée de taille de charges utiles trouvée.")
        return

    # Utilisez la fonction 'tabulate_function' pour formater les données sous forme de tableau
    tableau = tabulate_function(payload_sizes_by_application, headers="keys", tablefmt="fancy_grid")
    print(tableau)


def get_total_bytes_by_application(es, index='search-test-projet-v2'):
    """
    Récupère la taille totale en octets des données source et destination pour chaque application dans Elasticsearch.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.

    Returns:
        list: Liste de dictionnaires contenant le nom de l'application, la taille totale des octets source,
        et la taille totale des octets de destination.
    """
    # Définissez la requête d'agrégation
    aggregation = {
        "total_bytes_by_app": {
            "terms": {
                "field": "appName.keyword",  # Utilisez le champ de l'application
                "size": 1000,  # Ajustez la taille selon vos besoins
            },
            "aggs": {
                "total_source_bytes": {
                    "sum": {
                        "field": "totalSourceBytes"
                    }
                },
                "total_destination_bytes": {
                    "sum": {
                        "field": "totalDestinationBytes"
                    }
                }
            }
        }
    }
    # Exécutez la requête d'agrégation
    response = es.search(index=index, aggs=aggregation, size=0)
    
    # Récupérez les résultats de l'agrégation
    total_bytes_by_app = []
    for bucket in response['aggregations']['total_bytes_by_app']['buckets']:
        app_name = bucket['key']
        total_source_bytes = bucket['total_source_bytes']['value']
        total_destination_bytes = bucket['total_destination_bytes']['value']

        # Ajoutez les totaux calculés à la liste des dictionnaires de données
        total_bytes_by_app.append({
            "Application": app_name,
            "Total des octets source": total_source_bytes,
            "Total des octets de destination": total_destination_bytes
        })

    return total_bytes_by_app

def afficher_total_bytes_par_application_tabulate(es, index='search-test-projet-v2'):
    """
    Affiche la taille totale en octets des données source et destination pour chaque application en utilisant la bibliothèque 'tabulate'.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.
    """
    # Appelez la fonction pour obtenir la taille totale en octets par application
    total_bytes_by_application = get_total_bytes_by_application(es, index)
    
    print("* Taille totale des octets source et de destination pour chaque application :")

    # Vérifiez s'il y a des résultats
    if not total_bytes_by_application:
        print("Aucune donnée de taille totale des octets trouvée.")
        return

    # Utilisez la fonction 'tabulate_function' pour formater les données sous forme de tableau
    tableau = tabulate_function(total_bytes_by_application, headers="keys", tablefmt="fancy_grid")
    print(tableau)



def get_total_packets_by_application(es, index='search-test-projet-v2'):
    """
    Récupère le nombre total de paquets source et destination pour chaque application dans Elasticsearch.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.

    Returns:
        list: Liste de dictionnaires contenant le nom de l'application, le nombre total de paquets source,
        et le nombre total de paquets de destination.
    """
    # Définissez la requête d'agrégation
    aggregation = {
        "total_packets_by_app": {
            "terms": {
                "field": "appName.keyword",  # Utilisez le champ de l'application
                "size": 1000,  # Ajustez la taille selon vos besoins
            },
            "aggs": {
                "total_source_packets": {
                    "sum": {
                        "field": "totalSourcePackets"
                    }
                },
                "total_destination_packets": {
                    "sum": {
                        "field": "totalDestinationPackets"
                    }
                }
            }
        }
    }
    # Exécutez la requête d'agrégation
    response = es.search(index=index, aggs=aggregation, size=0)
    
    # Récupérez les résultats de l'agrégation
    total_packets_by_app = []
    for bucket in response['aggregations']['total_packets_by_app']['buckets']:
        app_name = bucket['key']
        total_source_packets = bucket['total_source_packets']['value']
        total_destination_packets = bucket['total_destination_packets']['value']

        # Ajoutez les totaux calculés à la liste des dictionnaires de données
        total_packets_by_app.append({
            "Application": app_name,
            "Nombre total de paquets source": total_source_packets,
            "Nombre total de paquets de destination": total_destination_packets
        })

    return total_packets_by_app

def afficher_total_packets_par_application_tabulate(es, index='search-test-projet-v2'):
    """
    Affiche le nombre total de paquets source et destination pour chaque application en utilisant la bibliothèque 'tabulate'.

    Args:
        es (Elasticsearch): Objet Elasticsearch connecté.
        index (str): Nom de l'index Elasticsearch.
    """
    # Appelez la fonction pour obtenir le nombre total de paquets par application
    total_packets_by_application = get_total_packets_by_application(es, index)
    
    print("* Nombre total de paquets source et de destination pour chaque application :")

    # Vérifiez s'il y a des résultats
    if not total_packets_by_application:
        print("Aucune donnée de nombre total de paquets trouvée.")
        return

    # Utilisez la fonction 'tabulate_function' pour formater les données sous forme de tableau
    tableau = tabulate_function(total_packets_by_application, headers="keys", tablefmt="fancy_grid")
    print(tableau)

afficher_distinct_protocol_tabulate(es,index_name)
afficher_protocol_counts_tabulate(es,index_name)
afficher_payload_par_protocole(es,index_name)
afficher_total_bytes_par_protocole(es,index_name)
afficher_total_packets_par_protocole(es, index_name)
afficher_distinct_applications_tabulate(es, index_name)
afficher_flows_par_application_tabulate(es, 'HTTPImageTransfer', index_name)
afficher_nombre_flows_par_application_tabulate(es, index_name)
afficher_taille_charges_utiles_par_application_tabulate(es, index_name)
afficher_total_bytes_par_application_tabulate(es, index_name)
afficher_total_packets_par_application_tabulate(es, index_name)


# Liste des applications distinctes

# Définissez la requête d'agrégation
aggregation = {
    "distinct_apps": {
        "terms": {
            "field": "appName.keyword",  # Utilisez le champ de l'application
            "size": 1000  # Ajustez la taille selon vos besoins
        }
    }
}

response6 = es.search(index=index_name, aggs=aggregation, size=0)

distinct_apps = response6['aggregations']['distinct_apps']['buckets']

# Affichez la liste des applications distinctes
print("Liste des applications distinctes :")
# for bucket in distinct_apps:
#     app_name = bucket['key']
#     print(app_name)

print("TOTAL :", len(distinct_apps))

# Liste des flows pour une application donnée

# Nombre de flows pour chaque application

# Taille du paylod source et destination pour chaque application

