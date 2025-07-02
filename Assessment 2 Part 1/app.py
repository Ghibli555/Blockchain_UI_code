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

#(create_msg, sign_record, verify_all_nodes) is imported from signature.py
#Flask is used to create a web server. Allows inputs from front end to interact with
#   back end python. 
    
from flask import Flask, render_template, request,session
import hashlib

#Creates the flask app with name of current file as name: 
app = Flask(__name__)
app.secret_key = 'secretkey123'

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
    #create an empty list to hold result message from this function
    verification_results=[]
    for node in ['A', 'B', 'C', 'D']:
        #Public key is used to verify at each node ABCD with Signers location.
        e,n = public_keys[location]
        decrypted = pow(signature,e,n)
        if decrypted != message:
            verification_results.append(f"Verification failed at location {node}")
            return False, verification_results
        verification_results.append(f"Verification at location {node} successful, with public key of {location}:(e={e},n={n})")
    return True, verification_results

#Consensus:
# ABCD nodes are authorized trusted validators they will verify transactions,
#This will be done by each node voting to approve or reject a record. 
#Once majority agrees adn there is agreement across all nodes, the record is accepted. 
def consensus_POA(votes):
    approve = list(votes.values()).count(True)
    return approve >= 3

#Function to write to all Nodes (this will be only called if all the votes are true)
def write_Inventory_Database(ID, Qty, Price, location, sig):
    record = f"ItemID:{ID}, ItemQTY:{Qty}, ItemPrice:{Price}, Location:{location}, Signature:{sig}\n"
    for node in ['A', 'B', 'C', 'D']:
        #Each node will write the record 
        with open(f"Inventory_{node}.txt", "a") as f:
            f.write(record)
    return "Majority of Votes, Consensus formed. Record written to all Inventories A B C D"


#-------------------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    show_voting = False

    #Submit record and store in temp pool before voting happens
    if request.method == "POST" and "item_id" in request.form:
        location = request.form["location"]
        ID = request.form["item_id"]
        Qty = request.form["qty"]
        Price = request.form["price"]

        # Create a hashed message from the record using the create_msg function
        msg = create_msg(ID, Qty, Price, location)
        # Sign the message with the private key of the selected location Node
        sig = sign_record(location, msg)
        # Display the message and signature to front end.
        message_output = f"Message: {msg}"
        signature_output = f"Signature: {sig}"

        # Verify the signature at each node using the public key of the signer
        verified, verifications = verify_all_nodes(location, msg, sig)
        result["message"] = f"Message: {msg}"
        result["signature"] = f"Signature: {sig}"
        result["verifications"] = verifications

        # If all nodes verify successfully, store the record in the temporary pool
        if verified:
            with open("Verified_Temp_Pool.txt", "a") as f:
                f.write(f"ItemID:{ID}, ItemQTY:{Qty}, ItemPrice:{Price}, Location:{location}, Signature:{sig}\n")
            session["step"] = "voting"
            session["record"] = {"ID": ID, "Qty": Qty, "Price": Price, "location": location, "sig": sig}
            result["final"] = "Record verified and stored in the file Verified_Temp_Pool.txt.Next Each Node will vote:"
            show_voting = True
        else:
            result["final"] = "Signature verification failed. Record not stored."
            session.clear()

    # Voting Stage to form Consensus
    elif request.method == "POST" and "vote_A" in request.form:
        record = session.get("record")
        if not record:
            result["final"] = "No record found in session. Restart required."
        else:
            votes = {
                'A': request.form.get("vote_A") == "True",
                'B': request.form.get("vote_B") == "True",
                'C': request.form.get("vote_C") == "True",
                'D': request.form.get("vote_D") == "True"
            }

            #Consensus check for majority votes
            if consensus_POA(votes):
                result["final"] = write_Inventory_Database(**record)
            else:
                result["final"] = "Consensus has failed. Record only in Temp pool."

            session.clear()

    # Enable voting form if signature is verified and the record is store in temp pool
    show_voting = session.get("step") == "voting"

    return render_template("index.html", result=result, show_voting=show_voting)

# ---Run App -----#
if __name__ == "__main__":
    app.run(debug=True)
