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
#Note: pkg_crypto.py is a custom class made please for cryptography functions, please 
#   refer to pkg_crypto.py for all cryptography code. 
 
from flask import Flask, request, render_template
#Custom made packages imported from pkg_crypto.py 
from pkg_crypto import encryption, calculate_combined_t, compute_harn_signature_md5, signed_ids_g, r_Inventory, pk_PKG
#Packages for PO encryption and decryption from the pkg_crypto file. 
from pkg_crypto import encrypt_for_po, decrypt_by_po, po_public_key, po_private_key

import hashlib

# Initialize the Flask application
app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
#This function is used to query records across all the 4 inventories with preloaded data. 

#If  all the records match Across ABCD match
#   Verify consensus, encrypt result, and display all information to frontend. 

def query_inventory():
    result = None
    signature_data = {}

    if request.method == "POST":
        item_id = request.form["item_id"]
        warehouse_records = {}

        # Check if the item exists within the inside the inventory. 
        for warehouse in ["A", "B", "C", "D"]:
            try:
                with open(f"inventory_{warehouse}.txt", "r") as file:
                    for line in file:
                        if line.startswith(item_id):
                            record = line.strip().replace(",", "")
                            warehouse_records[warehouse] = record
                            break
            except FileNotFoundError:
                continue

        if len(warehouse_records) == 4:
            unique_records = set(warehouse_records.values())

            if len(unique_records) == 1:
                message = list(unique_records)[0]

                # Generate t values from encryption
                t_combined = calculate_combined_t(encryption(r_Inventory, pk_PKG), pk_PKG[1])

                # Compute Harn signatures: 
                S, partial_sigs, hash_val = compute_harn_signature_md5(
                    signed_ids_g, r_Inventory, message, t_combined, pk_PKG[1]
                )

                #Verify consensus
                expected = 1
                for node in signed_ids_g:
                    g_i = signed_ids_g[node] % pk_PKG[1]
                    r_i = r_Inventory[node]
                    r_exp = pow(r_i, hash_val, pk_PKG[1])
                    s_i = (g_i * r_exp) % pk_PKG[1]
                    expected = (expected * s_i) % pk_PKG[1]

                #Verify consensus of all nodes agree to S 
                all_nodes_agree = (S == expected)
                consensus_message = (
                    "Consensus achieved across all inventories A B C D."
                    if all_nodes_agree else
                    "Signature does not match for the records."
                )

                #Encrypt the message using this is done by PO public Key. 
                encrypted_msg = encrypt_for_po(message, po_public_key)

                # Decrypt and simulate the orignal message back.
                decrypted_msg = decrypt_by_po(encrypted_msg, po_private_key)

                #Send everything to frontend
                signature_data = {
                    "message": message,
                    "partial_sigs": partial_sigs,
                    "final_sig": S,
                    "t_combined": t_combined,
                    "consensus": consensus_message,
                    "warehouse_records": warehouse_records,
                    "encrypted_message": encrypted_msg,
                    "decrypted_message": decrypted_msg 
                }

            else:
                # IF the Records differ among warehouses: 
                result = (
                    f"Record mismatch across warehouses for item {item_id}:<br>" +
                    "<br>".join(f"{k}: {v}" for k, v in warehouse_records.items())
                )
        else:
            result = f"Item ID {item_id} not found in all warehouses."

    return render_template("query.html", result=result, sig=signature_data)

#Run the Flask Front end. 
if __name__ == "__main__":
    app.run(debug=True)