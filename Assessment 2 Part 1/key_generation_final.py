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

Used for reference to create HTML and Css codes
W3Schools for HTML and CS help: https://www.w3schools.com/
Geeks for Geeks – Programming Tutorials & Examples:https://www.geeksforgeeks.org/
'''
#> Generating Digital Signatures using RSA Algorithm

#> Hard coded values for p,q,e are used to generate keys for warehouses 
#   ABCD. Function generate_keys is used to take in these values to output 
#   the public and private keys. Public Keys and Private Keys are stored 
#   separately. 

#--------------------------------------------------------------------------------#
#> Hard Coded Values p,q,e for Each Warehouse: 
#> Warehouse A
p_A = 1210613765735147311106936311866593978079938707
q_A = 1247842850282035753615951347964437248190231863
e_A = 815459040813953176289801

#> Warehouse B
p_B = 787435686772982288169641922308628444877260947
q_B = 1325305233886096053310340418467385397239375379
e_B = 692450682143089563609787

#> Warehouse C
p_C = 1014247300991039444864201518275018240361205111
q_C = 904030450302158058469475048755214591704639633
e_C = 1158749422015035388438057

#> Warehouse D
p_D = 1287737200891425621338551020762858710281638317
q_D = 1330909125725073469794953234151525201084537607
e_D = 33981230465225879849295979

# >Function to compute RSA keys public to output
#   Key(e,n) and Private_Key(d,n) given p,q & e Values
def generate_keys(p,q,e):
    n = p*q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    #Returns public key and private key
    return(e,n),(d,n)
#--------------------------------------------------------------------------------#

#>Gen Keys and print Keys for each locations of the warehouse [ABCD] using the function 
#   def generate_keys

# >The function generate_keys is called with inputs from Hardcoded values of p,q,e of each warehouse, 
#   the functions returns (e,n) and (d,n) and public key (pk_A) and private key (sk_A) 
#>Creates a file named generated keys in write mode: 
#   with statement closes file after the block has finished executing.
with open("Public_Keys.txt", "w") as file:
    file.write("Generated Public Keys for Warehouse ABCD: \n\n")

    # Warehouse A Key generation
    file.write("Warehouse Location: A\n")
    pk_A, sk_A = generate_keys(p_A, q_A, e_A)
    #f"...." creates a f string which allows  the variables p_A and sk_A to be embedded
    file.write(f"Public Key (e, n):{pk_A}\n")

    # Warehouse B Key generation
    pk_B, sk_B = generate_keys(p_B, q_B, e_B)
    file.write("Warehouse Location: B\n")
    file.write(f"Public Key (e, n):{pk_B}\n")

    # Warehouse C Key generation
    pk_C, sk_C = generate_keys(p_C, q_C, e_C)
    file.write("Warehouse Location: C\n")
    file.write(f"Public Key (e, n):{pk_C}\n")

    # Warehouse D Key generation
    pk_D, sk_D = generate_keys(p_D, q_D, e_D)
    file.write("Warehouse Location: D\n")
    file.write(f"Public Key (e, n):{pk_D}\n")

with open("Private_Keys.txt", "w") as file:
    file.write("Generated Private Keys for Warehouse ABCD: \n\n")

    # Warehouse A Key generation
    file.write("Warehouse Location: A\n")
    pk_A, sk_A = generate_keys(p_A, q_A, e_A)
    #f"...." creates a f string which allows  the variables p_A and sk_A to be embedded
    file.write(f"Private Key (d, n):{sk_A}\n")

    # Warehouse B Key generation
    pk_B, sk_B = generate_keys(p_B, q_B, e_B)
    file.write("Warehouse Location: B\n")
    file.write(f"Private Key (d, n):{sk_B}\n")

    # Warehouse C Key generation
    pk_C, sk_C = generate_keys(p_C, q_C, e_C)
    file.write("Warehouse Location: C\n")
    file.write(f"Private Key (d, n):{sk_C}\n")

    # Warehouse D Key generation
    pk_D, sk_D = generate_keys(p_D, q_D, e_D)
    file.write("Warehouse Location: D\n")
    file.write(f"Private Key (d, n):{sk_D}\n")
    
print("Keys have been saved to \"Private_keys.txt and Public_keys.txt\" file within the local folder.")

