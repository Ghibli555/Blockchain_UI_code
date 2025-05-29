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
import hashlib
#Resources
#documentation: https://docs.python.org/3/library/hashlib.html#module-hashlib
#Provides methods to use the haslib md5 

#Hard Coded Values for Private Keys taken from the file Private_keys.txt A.
#private_keys dictionary stores Private key pairs (d,n)
private_keys = {
    'A': (1359908369143705140915574118545189095499406328097208654560783239847135545871732205365749449,
          1510655732025614931618473113490936936007010876086492730422218817435607919502486239158421141),
    'B': (385554006345823895959076237099978492568148088900455562304224630322221920712351462955463639,
          1043592637028925963812797464507113356509508109284032337574598025668423558948865906670023913),
    'C': (59718784423799151459849899904574018009709157083418928937386561733370611446246317425827993,
          916910444232677830583692042601026220327574396695137541357168363411849184127399957852764263),
    'D': (456826729944023441542435595542382246049075898780851000828935272347310661251862889992482579,
          1713861192202060574132658988016647849520234158153264986650265683470192580439042716358687419)
}
#Hard Coded Values for Public Keys taken from Public_keys.txt A : (e,n)
public_keys = { 
    'A': (815459040813953176289801,
          1510655732025614931618473113490936936007010876086492730422218817435607919502486239158421141),
    'B': (692450682143089563609787,
          1043592637028925963812797464507113356509508109284032337574598025668423558948865906670023913),
    'C': (1158749422015035388438057,
          916910444232677830583692042601026220327574396695137541357168363411849184127399957852764263),
    'D': (33981230465225879849295979,
          1713861192202060574132658988016647849520234158153264986650265683470192580439042716358687419)
}

#Creating msg from Records
#def create_msg is a function to create a msg hash in dec. 
#m is created by input data (ID,Qty,Price,location):
#   >record is hashed with md5 hash e.g(ID:001,Qty:32,Price:12,Location:D md5hash(0013212D))
#   >e.g md5hash(0013212D) converted to decimal format.  
#   >output: Hash in dec form.
#>Note MD5 works on byte representations not actual numbers,
#   all values of inputs are received as strings and concatenated together as a rec_string. 
 
def create_msg(ID,Qty,Price,location):
    #combine inputs to a single string to calculate Hash Value
    rec_string =f"{ID}{Qty}{Price}{location}"
    hash_hex = hashlib.md5(rec_string.encode()).hexdigest()
    #hash lib outputs into a hex format, dec conversion needed to be used in RSA algorithm. 
    hash_dec = int(hash_hex,16)
    return hash_dec

# Based on the location chosen,ABCDs private key is selected
#    This is used to sign the record.  
def sign_record(location,message):
    #extract private key from the location and assign the values to d,n
    d,n = private_keys[location]
    signature = pow(message,d,n)
    return signature

#Verify record at each node:
# >Verify Record at all nodes A B C D with the public key 
#     of the signed record.
def verify_all_nodes(location,message,signature):
    for node in ['A', 'B', 'C', 'D']:
        #Public key is used to verify at each node ABCD with Signers location.
        e,n = public_keys[location]
        decrypted = pow(signature,e,n)
        if decrypted != message:
            print(f"Verification failed at location {node}")
            return False
        print(f"Verification at location {node} successful, with public key of {location}:(e={e},n={n})")
    return True

#Test Values
ID="001"
Qty="32"
Price="12"
location="D"

msg= create_msg(ID, Qty, Price, location)
sig = sign_record(location, msg)
print(f"Message:{msg}\n Signature:{sig} \n sent to all locations for verification")

#if all the nodes return true (ABCD all verify using the public key of the location)
#append mode "a" is used to ensure data does not get modified or edited. 
#Once all records are verified they are stored to the Verified_Temp_Pool.txt
if verify_all_nodes(location,msg,sig):
    with open ("Verified_Temp_Pool.txt","a") as file:
      file.write(f"ItemID:{ID}, ItemQTY:{Qty}, ItemPrice:{Price}, Location:{location}, Signature: {sig}\n")
else:
    print("Signature is invalid, verification failed record will not be stored.")






















# #Note append mode "a" is used to write as to w write mode as records will be amended, 
# #     without deleting any previous records. 
# if msg == m_2:
#     print(f"original message m({msg})=m_2({m_2}) Signature is valid")
#     with open("Verified_Temp_Pool.txt","a") as file:
#       file.write(f"ItemID: {ID}, Qty: {Qty}, Price: {Price}, Location: {location}, Signature: {sig}\n")
#       print("Record stored in Temp pool ready for consensus before being stored in main Inventories")
# else:
#     print("signature is invalid; record will not be stored inside the inventories")



