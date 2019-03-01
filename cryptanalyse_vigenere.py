# Sorbonne Universite 3I024 2018-2019
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : LEVESQUE PAUL-ANTOINE 3670460
# Etudiant.e 2 : AUBARD-POILLOT FLAVIEN 3670494
# coding : utf-8
import sys, getopt, string, math

# Alphabet franais
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Frquence moyenne des lettres en francais
#  modifier
freq_FR = [0.09213437454330574,
 0.010354490059155806, 
 0.030178992381545422,
 0.037536932666586184,
 0.17174754258773295,
 0.010939058717380115,
 0.0106150043524949,
 0.010717939268399616,
 0.07507259453174145,
 0.0038327371156619923,
 6.989407870073262e-05,
 0.06136827190067416,
 0.026498751437594118,
 0.07030835996721332,
 0.04914062053233872,
 0.023697905083841123,
 0.010160057440224678,
 0.06609311162084369,
 0.07816826681746844,
 0.0737433362349966,
 0.06356167517044624,
 0.016450524523290613,
 1.1437212878301701e-05,
 0.004071647784675406,
 0.0023001505899695645,
 0.0012263233808401269]

# Chiffrement Csar
def chiffre_cesar(txt, key):
    """
    prend en paramtre une chaine de caractres et une cl key
    hypothse : txt non vide et key positif ou nul
    retourne la chaine de caractres chiffre par Csar d'aprs la cl
    """
    res = ""
    for i in txt:
        res = res + chr((ord(i) - ord('A') + key)%26 + ord('A'))
    return res

# Dchiffrement Csar
def dechiffre_cesar(txt, key):
    """
    prend en parametre une chaine de caractere et une clef key
    hypothese : txt non vide et key positif ou nul
    retourne la chaine de caracetre dechiffre par Cesar d'apres la cle
    """
    res = ''
    for i in txt:
        res = res + chr((ord(i) - ord('A') - key)%26 + ord('A'))
    return res

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    prend en parametre une chaine de caractere et une clef key
    hypothese : txt non vide et key positif ou nul
    retourne la chaine de caracetre chiffre par Vigenere d'apres la cle
    """
    taille = len(key)
    i = 0
    res = ""
    while i < len(txt):
        res += chiffre_cesar(txt[i], key[i%taille])
        i += 1
    return res

# Dchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    prend en parametre une chaine de caractere et une clef key
    hypothese : txt non vide et key positif ou nul
    retourne la chaine de caracetre chiffre par Vigenere d'apres la cle
    """
    taille = len(key)
    i = 0
    res = ""
    chaine = txt
    while i < len(txt):
        res += dechiffre_cesar(chaine[i], key[i%taille])
        i += 1
    #print(res)
    return res

# Analyse de frquences
def freq(txt):
    """
    prend en parametre une chaine de caracteres
    hypothese : la chaine de caractere est non nulle
    retourne la liste qui contient la somme de toutes les occurences de chaque lettre
    dans la chaine de caracteres passee en parametre
    """
    hist = [0.0]*len(alphabet)
    for e in txt:
        hist[ord(e) - ord('A')] += 1
    return hist

# Renvoie l'indice dans l'alphabet
# de la lettre la plus frquente d'un texte
def lettre_freq_max(txt):
    """
    prend en parametre une chaine de caractere
    hypothese : la chaine de caractere est non nulle
    retourne l'indice de la lettre dans l'alphabet dont la frequence d'apparition est la 
    plus haute dans la chaine passee en parametre
    """
    hist = freq(txt)
    freq_max = 0
    for i in range(len(hist)):
        if hist[i] > hist[freq_max]:
            freq_max = i
    return freq_max

# indice de concidence
def indice_coincidence(hist):
    """
    prend en parametre un tableau qui correspond aux frequences des lettres d'un texte
    hypothese : le tableau est non nul et est de taille 26 -> les 26 lettres de l'alphabet
    retourne l'indice de coincidence 
    """
    n = sum(hist)
    indice = 0
    for i in range(len(hist)):
        indice += (hist[i]*(hist[i] - 1))/(n*(n - 1))
    return indice
    
# Recherche la longueur de la cl
def longueur_clef(cipher):
    """
    prend en parametre un texte chiffre
    hypothese : le texte chiffre est non nul
    retourne la longueur de la clef
    """
    for i in range(3,20):
        indice = 0
        for j in range(i):
            indice += indice_coincidence(freq(cipher[j:-1:i]))
            #on calcule l'indice de coincidence des frequences de 
            #cipher de l'indice j jusqua'a la fin par pas de i qui correspond
            #au decalage courant que l'on teste
        if indice/i > 0.06:
            return i
    return 0
    
# Renvoie le tableau des dcalages probables tant
# donn la longueur de la cl
# en utilisant la lettre la plus frquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    """
    prend en parametre une chaine de caractere et la taille de la cle
    hypothese : chaine de caractere non nulle et taille de la cle != 0
    retourne le tableau des decalages pour chaque lettre de l'alphabet
    """
    decalages=[0]*key_length
    for i in range(key_length):
        decalages[i] += (lettre_freq_max(cipher[i:-1:key_length]) - (ord('E') - ord('A')))%26
        #on incremente decalage[i] par la valeur de l'indice de la lettre de plus
        #haute frequence, de l'indice i jusqu'a la fin par pas de key_length
        #on soustrait la valeur de ord(E) - ord(A) pour avoir la valeur du decalage
        #par rapport a E, le tout modulo 26
    return decalages

# Cryptanalyse V1 avec dcalages par frequence max
def cryptanalyse_v1(cipher):
    """
    prend en parametre un texte a cryptanalyser
    hypothese :  le texte est non nul
    retourne le texte correctement cryptanalyse
    """
    len_cle = longueur_clef(cipher)
    decalages = clef_par_decalages(cipher, len_cle)
    return dechiffre_vigenere(cipher, decalages)

"""
le test est concluant pour 18 textes actuellement
on peut supposer que dans les tests loupes, la frequence max n'est pas celle du E 
notre algorithme ne prend pas en compte cette potentielle erreur 
en effet dans la fonction clef par decalages, la cle est determinee par rapport 
a la lettre E dans un texte car c'est la lettre qui a l'indice de coincidence 
le plus eleve dans la langue francaise 
"""

################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec dcalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    prend en parametre deux tableaux h1 et h2 qui correspondent aux frequences des lettres dans
    les deux textes et un indice d qui correspond au decalage
    hypothese : h1 et h2 non nuls et de meme taille, et d != 0
    retourne l'indice de coincidence mutuelle des deux textes
    """
    n1 = sum(h1)
    n2 = sum(h2)
    indice = 0
    for i in range(len(h1)):
        indice += (h1[i]*h2[(i+d)%26])/(n1*n2)
    return indice

# Renvoie le tableau des dcalages probables tant
# donn la longueur de la cl
# en comparant l'indice de dcalage mutuel par rapport
#  la premire colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    prend en parametres un texte et un entier qui correspond a la taille de la cle
    hypothese : texte non nul et taille de la cle != 0
    retourne un tableau d'entiers qui correspond au decalage
    """
    decalages=[0]*key_length
    for i in range(key_length):
        imax = -1
        dmax = -1
        ind = -1
        for j in range(26):
            ind = indice_coincidence_mutuelle(freq(cipher[0:-1:key_length]), freq(cipher[i:-1:key_length]), j)
            if ind > imax:
                imax = ind
                dmax = j
        decalages[i] = dmax
    return decalages

# Cryptanalyse V2 avec dcalages par ICM
def cryptanalyse_v2(cipher):
    """
    prend en parametre un texte a cryptanalyser
    hypothese : le texte est non nul
    retourne le texte correctement cryptanalyse
    """
    len_cle = longueur_clef(cipher) #longueur de la cle
    decalages = tableau_decalages_ICM(cipher, len_cle) #recuperation du tableau des decalages
    chaine = dechiffre_vigenere(cipher, decalages) #on dechiffre selon vigenere la chaine 
    lettre = (lettre_freq_max(chaine) - (ord('E') - ord('A')))%26 #lettre la plus frequente
    return dechiffre_cesar(chaine, lettre)

"""
il y a deux cas:
	-un ou le e est la lettre la plus frequente :
		dans ce cas la on va quand meme faire les operations suivantes sauf que 
		le lettre = A car E-E-A % 26 = A
		et donc que le cesar avec A va rien changer au vigenere

	-le second cas est donc que le dechiffre_vigenerev1 lui va faire comme si le
	E est la plus frequente, or c'est pas le cas donc on doit tout redecaler de la
	difference entre E et la frequence max  
	donc le lettre = (lettre_freq_max(chaine)-(ord('E')-ord('A')))%26 c'est ce qu'il
	fait : il va determiner la valeur du decalage entre chaine et ce que on
	doit renvoyer
	une fois que on a se decalage on va donc retablir le dechiffrage grace au cesar 
        et donc tout decaler avec lettre qui est je le rappel la diferrence entre E et
        la lettre de frequence max 
"""

# Execute la fonction cryptanalyse_vN o N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

def esperance(L):
    """
    prend en parametre une liste
    hypothese : la liste est non nulle
    retourne l'esperance de la variable de la liste
    """
    somme = 0
    len_liste = len(L)
    for i in range(len_liste):
        somme += L[i]
    esperance = float(somme)/len_liste
    return esperance

def numerateur(L1, L2):
    """
    prend en parametre deux listes
    hypothese : les deux listes sont de meme longueur et non nulles
    retourne le numerateur de la correlation de Pearson
    """
    esp_x = esperance(L1)
    esp_y = esperance(L2)
    num = 0
    for i in range(len(L1)): #par hypothese les deux listes ont la meme taille
        num += ((L1[i]-esp_x)*(L2[i]-esp_y))
    return num

def denominateur(L1, L2):
    """
    prend en parametre deux listes 
    hypothese : les deux listes sont de meme taille et non nulles
    retourne le denominateur de la correlation de Pearson
    """
    esp_x = esperance(L1)
    esp_y = esperance(L2)
    #print("esperance de x : " + str(esp_x))
    #print("esperance de y : " + str(esp_y))
    d_gauche = 0
    for i in range(len(L1)):
        d_gauche += ((L1[i]-esp_x)*(L1[i]-esp_x))
    d_droit = 0
    for i in range(len(L2)):
        d_droit += ((L2[i]-esp_y)*(L2[i]-esp_y))
    denominateur = ((math.sqrt(d_gauche))*(math.sqrt(d_droit)))
    return denominateur

# Prend deux listes de meme taille et
# calcule la correlation lineaire de Pearson
def correlation(L1, L2):
    """
    prend en parametre deux listes qui correspondent a deux variables aleatoires
    hypothese : les deux listes sont de meme longueur
    retourne la valeur de correlation entre les deux
    """
    cor = (numerateur(L1, L2)/denominateur(L1, L2))
    return cor

# Renvoie la meilleur cle possible par correlation
# etant donne une longueur de cle fixee
def clef_correlations(cipher, key_length):
    """
    prend en parametres un texte et une longueur de cle
    hypothese : le texte est non vide et la longueur de la cle != 0
    retourne un tuple qui contient la moyenne des indices de 
    correlation maximum du texte pour chaque lettre ainsi que 
    la cle sous forme d'un tableau d'entiers
    """
    key = [0]*key_length
    moy = 0.0
    for i in range(key_length):
        ind_max = -1
        lettre = -1
        #print("i = "+str(i))
        for j in range(26):
            chaine = chiffre_cesar(cipher,j)      
            ind = correlation(freq_FR, freq(chaine[i:-1:key_length]))
            if ind > ind_max:
                ind_max = ind
                lettre = (26-j)%26
        moy += ind_max
        key[i] = lettre
    return (moy/key_length,key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    prend en parametres un texte 
    hypothese : le texte est non vide 
    retourne le dechiffrage du texte
    """
    moyenne_max = -1
    decalages = []
    for i in range(1, 21):
        tmpM, tmpD = clef_correlations(cipher, i)
        if tmpM > moyenne_max:
            moyenne_max = tmpM
            decalages = tmpD
    return dechiffre_vigenere(cipher, decalages)


################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f = open(fichier, "r")
    txt = (f.readlines())[0].rstrip('\n')
    f.close()
    return txt

"""
def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)
"""
def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier == '':
        usage()
    if not(version == 1 or version == 2 or version == 3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])
