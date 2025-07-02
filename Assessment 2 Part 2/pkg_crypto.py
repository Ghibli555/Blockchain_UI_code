import hashlib  # Make sure hashlib is imported
'''
Referencing for This Project files:
Canvas sample code to do cryptography functions
Canvas sample code from jupiter server used as reference for calculations.

Online Resources:
Used for implementing Hashlib Md5 functionality:
hash lib documentation: https://docs.python.org/3/library/hashlib.html

Used for implementing Flask functionality and undestand commands to run a Flask web server.
Flask Official Documentation:https://flask.palletsprojects.com/en/latest/
Flask Tutorial by Miguel Grinberg:https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world

Used for reference to create Htlm and Css codes
W3Schools for HTML and CS help: https://www.w3schools.com/
Geeks for Geeks – Programming Tutorials & Examples:https://www.geeksforgeeks.org/

Git hub used as a reference to lean/understan sample code RSA- implementation:
https://github.com/thalees/RSA-implementation
'''
#> Generating PKG Values
#PKG will generate public key (pk) and secret key (sk) values based on the

#> Hard coded values for p,q,e are used to generate keys for warehouses
#   ABCD. Function generate_keys is used to take in these values to output
#   the public and private keys. Public Keys and Private Keys are stored
#   separately.
#Objetive of this

#--------------------------------------------------------------------------------#
#> Hard Coded Values p,q,e for PKG
p_pkg = 1004162036461488639338597000466705179253226703
q_pkg = 950133741151267522116252385927940618264103623
e_pkg = 973028207197278907211

#> Hard Coded Values p,q,e for Procurement Officer
p_po = 1080954735722463992988394149602856332100628417
q_po = 1158106283320086444890911863299879973542293243
e_po = 106506253943651610547613


#>ID of each Inventory
ID_Inventory = {'A': 126, 'B': 127, 'C': 128, 'D': 129}

#>Random numbers for each inventory.
r_Inventory = {'A': 621, 'B': 721, 'C': 821, 'D': 921}

#Public Key (e,n) from PKG_public.txt
pk_PKG= (973028207197278907211,
        954088232425229706382520201245618381050107066567161988535764573189666148989564060702644969)
#PKG Private Key PKG (d,n) generated private_key.txt
sk_PKG=(200741941128288805881102727578608580108883612200449762472742993774612841866556866387286291,
        954088232425229706382520201245618381050107066567161988535764573189666148989564060702644969)



#-----------------------------------------------------------------------------------------#
#Key Generation PKG

# >Function to compute RSA keys public to output
#   Key(e,n) and Private_Key(d,n) given p,q & e Values
def generate_keys(p,q,e):
    n = p*q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    #Returns public key and private key
    return(e,n),(d,n)

#PKG will receive identity from each server and sign each node identity
#   as their secret key and sign with PKG secret key pk_sk
#e.g g_1=ID_A^(d)mod n

def sign_nodes(sk_PKG,ID_Inventory):
    #extract private key from the location and assign the values to d,n
    d, n = sk_PKG
    #Results will be stored in an empty dictionary.
    signed_result = {}

    for label, ID in ID_Inventory.items():
        #Each record is signed with PKG secret key.
        signature = pow(ID, d, n)
        signed_result[label]= signature

    return signed_result

#-----------------------------------------------------------------------------------------#
#Harn-Identity-based Multi-signature

#Using a random number and public key of PKG
#   an encrypted t value is assigned to each node.
def encryption(r_Inventory,pk_PKG):
    e,n= pk_PKG
    #Results will be stored in an empty dictionary.
    encrypted_result = {}

    for label, r in r_Inventory.items():
        cipher_text = pow(r,e,n)
        encrypted_result[label] = cipher_text

    return encrypted_result

#Nodes ABCD compute:
def calculate_combined_t(cipher_text, n):
    result = 1
    for node in sorted(cipher_text):
        result = (result * cipher_text[node]) % n
    return result
#-----------------------------------------------------------------------------------------#
#Response Encryption

def encrypt_for_po(message:str,public_key):
    #Officers public key will be used to encrypt the response message back.
    e,n = public_key
    #Rsa works with numbers so the message needs to be encoded to numerical value.
    msg=int.from_bytes(message.encode(), byteorder='big')
    cipher = pow(msg, e, n)
    return cipher

def decrypt_by_po(cipher: int, private_key):
    #Decrypt message with the given PO private key
    d, n = private_key
    #Gets Orignal number representation encryption was done from.
    decrypted = pow(cipher, d, n)
    #converts the number back to bytes by dividing by /8 and rounding to nearest byte.
    msg_bytes = decrypted.to_bytes((decrypted.bit_length() + 7) // 8, byteorder='big')
    return msg_bytes.decode()
#-----------------------------------------------------------------------------------------#
#generate PO keys these will be used to encrypt the response and the PO will decrypt it:
po_public_key, po_private_key = generate_keys(p_po, q_po, e_po)

#-----------------------------------------------------------------------------------------#
#This function compited the final Harn identity-based multi signature.
def compute_harn_signature_md5(g_values, r_values, message, t_combined, n):
    #hashing the input message and converting it to MD5 hash
    hash_input = message
    hash_hex = hashlib.md5(hash_input.encode()).hexdigest()
    #Convert to an integer
    hash_val = int(hash_hex, 16)

    #Generate Partial Sigs for each warehouse node
    partial_sigs = {}
    for node in g_values:
        g_i = g_values[node]
        r_i = r_values[node]

        #calculates mod of g_i with n.
        g_mod = g_i % n
        r_exp = pow(r_i, hash_val, n)
        s_i = (g_mod * r_exp) % n
        #store result of partial signature s_i as per canvas formula
        partial_sigs[node] = s_i

    #compute the final Partial Signature this is done by multiplying all the signatures.
    #return S and partial_sigs and hash_val as output.
    S = 1
    for s in partial_sigs.values():
        S = (S * s) % n

    return S, partial_sigs, hash_val

#-----------------------------------------------------------------------------------------#
#Execute Functions:
#-----------------------------------------------------------------------------------------#
#PKG generation sp pk values and signed g value for each node:
#PKG Public Key - Creates a file to store them:
with open("PKG_public_key.txt", "w") as file:
    file.write("Generated Public Key for PKG:: \n\n")

    file.write("PKG: A\n")
    pk_pkg, sk_pkg = generate_keys(p_pkg, q_pkg, e_pkg)
    file.write(f"Public Key of PGK (e, n):{pk_pkg}\n")
print(f"Public Key of PGK (e, n):{pk_pkg}\n")

#PKG Private Key Creates a file to store them:
with open("PKG_private_key.txt", "w") as file:
    file.write("Generated Private Key for PKG:: \n\n")

    file.write("PKG: A\n")
    pk_pkg, sk_pkg = generate_keys(p_pkg, q_pkg, e_pkg)
    file.write(f"Private Key of PGK (d, n):{sk_pkg}\n")
print(f"Private Key of PGK (d, n):{sk_pkg}\n")

#Assign the function with parameters secret key of PKG and ID to output signatures:
signed_ids_g = sign_nodes(sk_PKG, ID_Inventory)
for node, sig in signed_ids_g.items():
    print(f"Node {node}: ID_{node} = {ID_Inventory[node]}, Signature g_{node} = {sig}")
print("\n")



#-----------------------------------------------------------------------------------------#
# Harn Identity-Based Multi-Sig: (USED TO TEST CODE)

# # #Assign the function with parameters random numbers
# # #   from dictionary and secret key of PKG to output cipher text:
cipher_text_t=encryption(r_Inventory,pk_PKG)
for node, cipher in cipher_text_t.items():
    print(f"Node {node}: Encryption t_{node} = {cipher}")

# # #Combined t
# # #Encrypts each node’s random number usingthe PKG public Key
# # # Encrypt random numbers
cipher_text_t =encryption(r_Inventory, pk_PKG)

# # # Compute and print final combined t
combined_t = calculate_combined_t(cipher_text_t, pk_PKG[1])
print(f"\nCombined t = {combined_t}\n")

# # # Input values
message = "0041218A"  # Format: itemID + quantity + price + warehouse
t_combined = combined_t  # Output of calculate_combined_t()
n = pk_PKG[1]  # PKG modulus

# # # Run function
S, partial_sigs, hash_val = compute_harn_signature_md5(signed_ids_g, r_Inventory, message, t_combined, n)


# # Output result
print("\nPartial Signatures:")
for node, sig in partial_sigs.items():
    print(f"s_{node} = {sig}")
print(f"\nFinal Multi-Signature S = {S}")
