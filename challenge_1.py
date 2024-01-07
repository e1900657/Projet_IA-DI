# -*- coding: utf-8 -*-
import json
import pandas as pd
import pickle
import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.naive_bayes import MultinomialNB
import warnings

import os
from sklearn.metrics import roc_curve, auc, roc_auc_score
import matplotlib.pyplot as plt

import sys

# Vérifier si le chemin du dossier est passé en argument

# Vérifier si le nombre d'arguments est suffisant
if len(sys.argv) != 3:
    print("Usage: python script.py <path_pickle_train> <path_pickle_test>")
    sys.exit(1)

# Chemins des fichiers d'entrée et de sortie à partir des arguments de ligne de commande
path_pickle_train = sys.argv[1]
path_pickle_test = sys.argv[2]


# Vérification de l'existence du fichier train
if not os.path.exists(path_pickle_train):
    print(f"Le fichier {path_pickle_train} n'existe pas.")
    sys.exit(1)

# Vérification de l'existence du fichier test
if not os.path.exists(path_pickle_test):
    print(f"Le fichier {path_pickle_test} n'existe pas.")
    sys.exit(1)

# Vérification de l'extension du fichier
if not path_pickle_train.lower().endswith('.pkl'):
    print(f"Le fichier {path_pickle_train} n'a pas l'extension .pkl.")
    sys.exit(1)
    
# Vérification de l'extension du fichier
if not path_pickle_test.lower().endswith('.pkl'):
    print(f"Le fichier {path_pickle_test} n'a pas l'extension .pkl.")
    sys.exit(1)

# Import du fichier pickle train
try:
    with open(path_pickle_train, 'rb') as file:
        data_train = pickle.load(file)
    print("Import du fichier pickle train réussi.")
except Exception as e:
    print(f"Erreur lors de l'import du fichier pickle train : {e}")
    sys.exit(1)

# Import du fichier pickle test
try:
    with open(path_pickle_test, 'rb') as file:
        data_test = pickle.load(file)
    print("Import du fichier pickle test réussi.")
except Exception as e:
    print(f"Erreur lors de l'import du fichier pickle test : {e}")
    sys.exit(1)

# Compte le nombre d'occurrences de chaque classe dans data_train
counts = data_train['Tag_int'].value_counts()

# Affiche le tableau
print(counts)

warnings.filterwarnings("ignore", category=UserWarning)

def generate_classifier():
    """
    Génère un classificateur avec plusieurs options.

    Entrée: Aucune
    Sortie: Un dictionnaire contenant différents classificateurs.
    """
    classifier = {
        'Knn': knn_classifier,
        'Naive Bayes': naive_classifier,
        'Random Forest': random_forest_classifier,
        'Multilayer Perceptron': multiplayer_perceptron_classifier
    }
    return classifier

def knn_classifier():
    """
    Implémentation du classificateur K-NN.

    Entrée: Aucune (pour le moment, la valeur de k est fixée à 3)
    Sortie: Un modèle de classificateur K-NN configuré.
    """
    # Remplacez la valeur de k par celle que vous souhaitez utiliser
    k = 3
    knn_model = KNeighborsClassifier(n_neighbors=k)
    return knn_model

def naive_classifier():
    """
    Implémentation du classificateur Naive Bayes.

    Entrée: Aucune
    Sortie: Un modèle de classificateur Naive Bayes configuré.
    """
    nb_model = MultinomialNB()
    return nb_model

def random_forest_classifier():
    """
    Implémentation du classificateur Random Forest avec les meilleurs paramètres.

    Entrée: Aucune
    Sortie: Un modèle de classificateur Random Forest configuré avec les meilleurs paramètres.
    """
    rf_model = RandomForestClassifier(
        n_estimators=100,  # Nombre d'arbres dans la forêt
        max_depth=20,  # Profondeur maximale des arbres
        min_samples_leaf=1,  # Nombre minimum d'échantillons requis pour être une feuille
        min_samples_split=2,  # Nombre minimum d'échantillons requis pour diviser un nœud interne
        random_state=42  # Utilisé pour la reproductibilité des résultats
    )
    return rf_model

def gradient_boosting():
    return GradientBoostingClassifier(n_estimators=100, learning_rate=1.0, max_depth=1, random_state=42)

def multiplayer_perceptron_classifier():
    """
    Implémentation du classificateur Multilayer Perceptron.

    Entrée: Aucune
    Sortie: Un modèle de classificateur Multilayer Perceptron configuré.
    """
    mlp_model = MLPClassifier(hidden_layer_sizes=(50,))
    return mlp_model


classifier = generate_classifier()

# Demande à l'utilisateur de choisir un classificateur
selected_classifier = input("Choisissez un classificateur parmi 'Knn', 'Naive Bayes', 'Random Forest' ou 'Multilayer Perceptron': ")

# Vérifie si le choix de l'utilisateur est valide et l'affiche
if selected_classifier in classifier:
    print(f"Vous avez choisi le classificateur '{selected_classifier}'.")
    classifier = generate_classifier()[selected_classifier]()
else:
    print(f"Choix invalide. Veuillez sélectionner parmi {', '.join(generate_classifier())}. 😔")


# Liste des appNames disponibles
app_names_disponibles = ['HTTPWeb', 'HTTPImageTransfer', 'POP', 'IMAP', 'DNS', 'SMTP', 'ICMP', 'SSH', 'FTP']

# Demande à l'utilisateur de choisir un appName
user_input = input("Choisissez un appName parmi la liste {} : ".format(app_names_disponibles))

# Vérifie si l'input de l'utilisateur est valide
if user_input not in app_names_disponibles:
    print("Entrée invalide. Veuillez choisir parmi la liste fournie.")
else:
    # Affiche les éléments du tableau contenant l'appName choisi
    resultats_train = data_train[data_train['appName'] == user_input].sample(frac=0.5).reset_index(drop=True)

    if resultats_train.empty:
        print("Aucun élément avec l'appName '{}' trouvé.".format(user_input))
    else:
        print(len(resultats_train), "éléments avec l'appName '{}' :".format(user_input))
        print("le test est de ",len(data_test))

        # Keep only columns ending with '_int'
        int_columns = [col for col in resultats_train.columns if col.endswith('_int') and col != "Tag_int"]
        int_columns = [col for col in data_test.columns if col.endswith('_int') and col != "Tag_int"]

        # Sépare les données en fonction des colonnes nécessaires pour l'entraînement
        X_train = data_train.drop('Tag_int', axis=1)  # Remplace 'Tag_int' par le nom de la colonne cible
        y_train = data_train['Tag_int']  # Remplace 'Tag_int' par le nom de la colonne cible
        y_test = data_test['Tag_int']  # Remplace 'Tag_int' par le nom de la colonne cible
        X_test = data_test.drop('Tag_int', axis=1)  # Remplace 'Tag_int' par le nom de la colonne cible

        # Utilise un imputeur pour remplacer les NaN par la moyenne des colonnes
        imputer = SimpleImputer(strategy='mean')
        X_train_imputed = imputer.fit_transform(X_train[int_columns])
        X_test_imputed = imputer.transform(X_test[int_columns])

        # Entraîne le modèle
        classifier.fit(X_train_imputed, y_train)

        # Prédit sur les données de test
        predictions = classifier.predict(X_test_imputed)

        # Obtient les probabilités pour chaque classe
        class_probabilities = classifier.predict_proba(X_test_imputed)
        predictions = ['Normal' if label == 0 else 'Attack' for label in predictions]
        # Crée la structure JSON
        res = {
            'preds': list(predictions),
            'probs': class_probabilities.tolist(),
            'names': ['JOSSET', 'GARIN-HAMELINE'],  # Remplacez par vos noms d'équipe
            'method': selected_classifier,  # Remplacez par le nom de votre méthode
            'appName': user_input,  # L'appName choisi par l'utilisateur
            'version': '3'  # Remplacez par votre numéro de version
        }

        # Vérifie que le nombre de prédictions et de probabilités correspond au nombre de lignes dans les données de test
        if len(predictions) == len(class_probabilities) == len(X_test):

            output_filename = f"{res['names'][0]}_{res['names'][1]}_{res['appName']}_{res['version']}.res"
            with open(output_filename, "w") as f:
                json.dump(res, f)

            print(f"Fichier résultat JSON créé avec succès : {output_filename} 🌟✨")
        else:
            print("Erreur : Le nombre de prédictions ou de probabilités ne correspond pas au nombre de lignes dans les données de test.")
