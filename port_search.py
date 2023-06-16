-------------------------------------------------------------------------------
# Name:        scanner©DM Version 2.0
# Purpose:     scan port et informations whois de la cible
#
# Author:      Cirphelion
#
# Created:     01/07/2015
# Copyright:   (c) ©DM Version 2.0 2015
# Licence:     ©DM Version 2.0
#-------------------------------------------------------------------------------
# -*- coding: cp-1252 -*-
# -*- coding: utf-8 -*-
import urllib
import socket
import subprocess
import sys
import os.path
import errno
from ipwhois import IPWhois
from pprint import pprint
from datetime import datetime
 
version = "\n                    ©DM Version 2.0"
 
# Scanner 2.0
print ("-" * 60)
print ("¤" * 60)
print (version)
print ("\nScan de Port Réseau Internet : A n'utiliser que pour soi-même")
print ("\n                  ScanDM  FrameWork")
print ("                    Version :  2.0 ")
print ("                  Codename : Cirphelion\n")
print ("¤" * 60)
print ("-" * 60)
 
# Demande NDD ou IP pour le scanning
try:
    remoteServer    = input("Entrez l'IP ou le NDD a scanner (ex:google.fr): ")
    remoteServerIP  = socket.gethostbyname(remoteServer)
except KeyboardInterrupt:
                                print ("\n[*]/!\ Arret /!\ ")
                                sys.exit()
 
# liste des ports à choisir
try:
    min_port =input("Entrez un port de départ : ")
except KeyboardInterrupt:
                                print ("\n[*]/!\ Arret /!\ ")
                                sys.exit()
try:
    max_port =input("Entrez un port de fin : ")
except KeyboardInterrupt:
                                print ("\n[*]/!\ Arret /!\ ")
                                sys.exit()
 
# socket information
TIMEOUT = 0.9 # modifiable facilement dans le programme
 
# Affecter à  min et max_port comme integrer
min_port = int(min_port)
max_port = int(max_port)
 
# scan Départ
print ("-" * 60)
print ("*" * 60)
print ("        Please wait, scan en cours....", remoteServerIP)
print ("*" * 60)
print ("-" * 60)
 
# Temps de l'analyse
t1 = datetime.now()
 
# Utilisation de la fonction de range pour spécifier les ports
# Try et except pour intercepter les erreurs
count_o = 0
count_f = 0
UNREACHABLE = 2 # inaccessible
TIMEOUT_ERROR = 3 # connection non aboutie dans les temps TIMEOUT
try:
    for port in range(min_port,max_port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            print ("Port {}: \t Ouvert".format(port))
            count_o = count_o + 1
        else:
            print ("Port {}: \t Fermé".format(port))
            count_f = count_f + 1
        sock.close()
 
except KeyboardInterrupt:
    print ("Appuyer sur Ctrl+C")
    sys.exit()
 
except socket.gaierror:
    print ('NDD non résolue')
    sys.exit()
 
except socket.error:
    print ("connexion impossible vers le serveur")
    sys.exit()
 
# Calcul du nouveau temps
t2 = datetime.now()
 
# Calcule de la différence de temps, pour voir combien de temps il a fallu pour exécuter le script
total =  t2 - t1
 
# Impression des informations à l'écran
print ('Scanning finis en: ', total)
print ("-" * 60)
print ("")
print ("Trouver %d ports ouverts" % (count_o,))
print ("Trouver %d ports fermés \n" % (count_f,))
 
# IpWhois Scanner
print ("-" * 60)
print ("*" * 60)
print ("Scanning Whois en Cours....please Wait")
print ("-" * 60)
print ("*" * 60)
obj = IPWhois(remoteServerIP)
results = obj.lookup(get_referral=True)
pprint(results)
 
# Création du Fichier Texte de sortie-changement du path de sortie
try:
    NomFichier = input("Veuillez entrer un nom de fichier : ")
    os.chdir('C:/Users/admin/Desktop/')
except KeyboardInterrupt:
    print ("Pas de Nom indiquer")
    sys.exit()
 
# création et ouverture du fichier .txt en mode write 'w' (écriture)
# si le fichier .txt existe déjà, il est écrasé
try:
    Fichier = open(NomFichier + ".txt",'w')
except KeyboardInterrupt:
    print ("Problème chemin Path")
    sys.exit()
# écriture dans le fichier avec la méthode write()
Fichier.write("Scanner v2.0 by Cirphelion")
Fichier.write("\n")
Fichier.write("*" * 40)
Fichier.write("\n")
Fichier.write("Ports Découvert sur la cible")
Fichier.write("\n")
Fichier.write("-" * 40)
Fichier.write("\n")
for port in range(min_port,max_port) :
    Fichier.write("Port {}: \t Ouvert \n".format(port))
Fichier.write("\n")
Fichier.write("*"*40)
Fichier.write("\n")
Fichier.write("Recherche Whois : ")
Fichier.write("\n")
Fichier.write("*"*40)
Fichier.write("\n")
Fichier.write(str(results)+"\n")
 
# fermeture du fichier avec la méthode close()
Fichier.close()
 
# fichier créé
print ("-" * 60)
print ("*" * 60)
print ("Votre Fichier est disponible sur votre bureau en .txt")
print ("-" * 60)

    print ("*" * 60)

