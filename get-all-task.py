# -*- coding: utf-8 -*-

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
if len(sys.argv) != 2:
    print("Usage: python get-all-task.py <path_to_pickle_file>")
    sys.exit(1)

path_pickle = sys.argv[1]

# Vérification de l'existence du fichier
if not os.path.exists(path_pickle):
    print(f"Le fichier {path_pickle} n'existe pas.")
    sys.exit(1)

# Vérification de l'extension du fichier
if not path_pickle.lower().endswith('.pkl'):
    print(f"Le fichier {path_pickle} n'a pas l'extension .pkl.")
    sys.exit(1)
    

# Crée le dossier "courbes" s'il n'existe pas
output_folder = 'courbes_all'
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

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
    Implémentation du classificateur Random Forest.

    Entrée: Aucune
    Sortie: Un modèle de classificateur Random Forest configuré.
    """
    rf_model = RandomForestClassifier(n_estimators=100)
    return rf_model

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

print(classifier)
# Import du fichier pickle
try:
    with open(path_pickle, 'rb') as file:
        data = pickle.load(file)
    print("Import du fichier pickle réussi.")
    # Fais quelque chose avec les données importées si nécessaire
except Exception as e:
    print(f"Erreur lors de l'import du fichier pickle : {e}")


# Liste des appNames disponibles
app_names_disponibles = ['HTTPWeb', 'HTTPImageTransfer', 'POP', 'IMAP', 'DNS', 'SMTP', 'ICMP', 'SSH', 'FTP']

# Demande à l'utilisateur de choisir un appName
#user_input = input("Choisissez un appName parmi la liste {} : ".format(app_names_disponibles))

# Vérifie si l'input de l'utilisateur est valide
for user_input in app_names_disponibles:
#if user_input not in app_names_disponibles:
#    print("Entrée invalide. Veuillez choisir parmi la liste fournie.")
#else:
    # Affiche les éléments du tableau contenant l'appName choisi
    resultats = data[data['appName'] == user_input].sample(frac=1).reset_index(drop=True)

    if resultats.empty:
        print("Aucun élément avec l'appName '{}' trouvé.".format(user_input))
    else:
        print(len(resultats), "éléments avec l'appName '{}' :".format(user_input))


        # Divise les résultats en 5 parties de taille égale
        resultats_divises = np.array_split(resultats, 5)
        plt.figure(figsize=(8, 8))
        for partie_choisie in range(5):
            print(f"\n------ Task {partie_choisie} ------")
            # Sépare la partie choisie pour l'entraînement et les autres pour le test
            partie_test = resultats_divises[partie_choisie]
            parties_entrainement = pd.concat([resultats_divises[i] for i in range(5) if i != partie_choisie])

            # Keep only columns ending with '_int'
            int_columns = [col for col in data.columns if col.endswith('_int') and col != "Tag_int"]

            # Sépare les données en fonction des colonnes nécessaires pour l'entraînement
            y_train = parties_entrainement['Tag_int']  # Remplace 'target_column' par le nom de la colonne cible
            X_train = parties_entrainement.drop('Tag_int', axis=1)  # Remplace 'target_column' par le nom de la colonne cible
            y_test = partie_test['Tag_int']  # Remplace 'target_column' par le nom de la colonne cible
            X_test = partie_test.drop('Tag_int', axis=1)  # Remplace 'target_column' par le nom de la colonne cible

            # Utilise un imputeur pour remplacer les NaN par la moyenne des colonnes
            imputer = SimpleImputer(strategy='mean')
            X_train_imputed = imputer.fit_transform(X_train[int_columns])
            X_test_imputed = imputer.transform(X_test[int_columns])

            # Entraîne le modèle
            classifier.fit(X_train_imputed, y_train)

            # Prédit sur les données de test
            predictions = classifier.predict(X_test_imputed)

            # Évalue la précision du modèle
            accuracy = accuracy_score(y_test, predictions)
            print("Précision du modèle sur la partie test : {:.2f}%".format(accuracy * 100))

            conf_matrix = confusion_matrix(y_test, predictions)
            print(conf_matrix)

            # Calcule les probabilités des classes positives
            y_probs = classifier.predict_proba(X_test_imputed)
            try:

                # Calcule la courbe ROC
                fpr, tpr, _ = roc_curve(y_test, y_probs[:,1])

                # Calcule le AUC
                auc_value = auc(fpr,tpr)

                # Affiche la courbe ROC
                plt.plot(fpr, tpr, lw=1, alpha = .3, label =f'ROC task {partie_choisie} (AUC = {auc_value:.2f})')
            except:
                print(f'Erreur chargement {partie_choisie}')
        plt.plot([0,1],[0,1], linestyle='--', lw=2, color='gray', label='Aléatoire', alpha=.8)
        plt.xlabel('Taux de faux positifs')
        plt.ylabel('Taux de vrais positifs')
        plt.title(f'Courbe ROC de {user_input} pour du {selected_classifier}')
        plt.legend(loc="lower right")

        # Sauvegarde la courbe dans le dossier "courbes"
        output_path = os.path.join(output_folder, f'courbe_roc_{selected_classifier}_{user_input}.png')
        plt.savefig(output_path)
        print(f"Courbe ROC sauvegardée dans '{output_path}' 🌈✨")

