from Crypto.Hash import SHA256
from phe import paillier
from typing import List

from .utils import add, add_ec, multiply, rand, egcd, verify_dsa_signature, verify_ecdsa_signature
from .setup import DSASetup, ECDSASetup
from .network import Network, Client

class ThresholdSignature(Network):
    clients: List[Client]

    def __init__(self, N, C, setup=None, debug=False):

        self.debug = debug
        if setup is None:
            self.dsa = DSASetup.generate_dsa_setup()
            self.setup = DSASetup
            super().__init__(N, self.dsa.q, self.dsa.h)
        elif type(setup) == DSASetup:
            self.dsa = setup
            self.setup = DSASetup
            super().__init__(N, self.dsa.q, self.dsa.h)
        elif type(setup) == ECDSASetup:
            self.ecdsa = setup.generate_ecdsa_setup()
            self.setup = ECDSASetup
            super().__init__(N, self.ecdsa.q, self.ecdsa.h)
        else:
            raise TypeError("Invalid type provided. "
                            "Please use either 'DSASetup' or 'ECDSASetup' types."
                            )

        # Generate public and private keys for the paillier homomorphic encryption scheme
        for i in range(C):
            pub_key, priv_key = paillier.generate_paillier_keypair()
            self.clients[i].he_private_key = priv_key
            for node in self.nodes:
                node.he_public_keys[i] = pub_key
            for client in self.clients:
                client.he_public_keys[i] = pub_key


    def get_lambda(self, labels: list[str]) -> None:
        """
        Emulates the generation of LAMBDA pairs :math:`([h^{\gamma}], [\gamma])` between all nodes.

        Parameters:
            labels (list[str]): A list of labels for which lambda values will be generated
                and stored.

        Returns:
            None
        """

        n = len(labels)
        h = self.h
        q = self.q
        q_minus_one = q - 1
        for l in range(n):
            # Locally generate lambda
            alpha = rand(q_minus_one)
            h_alpha = pow(h, alpha, q)

            self.share(alpha, q_minus_one, labels[l]+"_lambda_sh_exp")
            self.share(h_alpha, q, labels[l]+"_lambda_sh_base")

    def rss_protocol(self, size: int, label: str) -> None:
        """
        Random Secret Sharing (RSS) Protocol.

        This function implements a one-round RSS protocol. The goal is to share a random
        secret value among a group of nodes using a specific label for the shares.

        Parameters:
            size (int): The maximum size of the random secret to be generated and shared.
            label (str): A label to identify the shared secrets and their associated operations.

        Returns:
            None
        """

        # Round 1
        for node in self.nodes:
            # Step 1: locally generate random secret
            random_element = rand(size)
            # Step 2: share random secret with all nodes
            self.share(random_element, size, label+"sh_node_"+str(node.id))
        # All local
        for node in self.nodes:
            # DB management
            list_of_shares = [
                node.get_share(label + "sh_node_" + str(other_node.id))
                for other_node in self.nodes
            ]
            # Step 3: add locally all shares
            random_sum = add(list_of_shares, size)
            # DB management
            sh_label = label+"_sh_exp"
            node.set_share(random_sum, sh_label)
            if not self.debug:
                [node.delete_share(label + "sh_node_" + str(other_node.id))
                 for other_node in self.nodes]

    def pow_share_protocol(self, base_type: str, get_label: str, save_label: str) -> None:
        """
        Compute a power-sharing protocol among a group of nodes.

        This function implements a one-round protocol to securely compute :math:`b^{s}` where 
        the exponent is a secret shared element between the nodes.
        
        Parameters:
            base_type (str): The type of base used: 'exp', when base to be used is self.h; 
                            'base', when the base to be used is self.dsa.g. Note: 'base' 
                            option can only be use for the DSA setup.
            get_label (str): The label to retrieve shares of 's' from nodes.
            save_label (str): The label to save the final result to.
        
        Returns:
            None
        """

        if base_type not in ["exp", "base"]:
            raise ValueError("{} is not one of the specified base types.\
                              Please choose one of the following:\n \
                             ['exp', 'base']".format(base_type))

        prime = self.q if base_type == "exp" else self.dsa.p

        # Round 1
        for node in self.nodes:
            # DB management
            exponent = node.get_share(get_label+"_sh_"+base_type)
            # Step 1: compute base^share
            if base_type == "exp":
                h_exp = pow(self.h, exponent, prime)
            else:
                h_exp = pow(self.dsa.g, exponent, prime)
            # Step 2: Broadcast base^share to nodes
            self.broadcast(h_exp, "pow_share_node_"+str(node.id))

        # All local
        for node in self.nodes:
            # DB management
            base_exps = [
                node.get_open("pow_share_node_"+str(other_node.id))
                for other_node in self.nodes
            ]
            # Step 3: multiply locally all powers of shares
            val = multiply(base_exps, prime)
            # DB management
            node.set_open(val, save_label)
            if not self.debug:
                [node.delete_open("pow_share_node_"+str(other_node.id))
                 for other_node in self.nodes]

    def ec_pow_share_protocol(self, get_label: str, save_label: str) -> None:
        """
        Execute an elliptic curve (EC) version of power-sharing protocol.

        This function implements a one-round protocol to securely compute 
        :math:`scalar\cdot G` where the scalar is a secret shared element between the nodes.

        Parameters:
            get_label (str): The label used to retrieve scalar shares from nodes.
            save_label (str): The label used to save the result of the power-sharing protocol.

        Returns:
        None
        """

        # Round 1
        for node in self.nodes:
            # DB management
            scalar_sh = node.get_share(get_label+"_sh_base")
            # Step 1:
            sh_G = scalar_sh * self.ecdsa.G
            # Step 2:
            self.broadcast(sh_G, "ec_pow_share_node_"+str(node.id))

        # All local
        for node in self.nodes:
            # DB management
            base_exps = [
                node.get_open("ec_pow_share_node_"+str(other_node.id))
                for other_node in self.nodes
            ]
            # Step 3: add locally all point shares
            val = add_ec(base_exps)
            # DB management
            node.set_open(val, save_label)
            if not self.debug:
                [node.delete_open("ec_pow_share_node_"+str(other_node.id))
                 for other_node in self.nodes]

    def subtract_exp_shares_local(self, label_a: str, label_b: str, label_r: str) -> None:
        """
        Subtract the shares of the exponent of two labels and store the result in another label.

        Parameters:
            label_a (str): The label for the first operand.
            label_b (str): The label for the second operand.
            label_r (str): The label where the result is stored.

        Returns:
            None
        """

        q_minus_one = self.q - 1

        for node in self.nodes:
            # DB management
            share_a = node.get_share(label_a+"_sh_exp")
            share_b = node.get_share(label_b+"_sh_exp")
            # Local operation: subtraction
            share_r = (share_a - share_b) % q_minus_one
            # DB management
            label = label_r+"_sh_exp"
            node.set_share(share_r, label)

    def pow_local(self, label_base: str, label_exponent: str, label_result: str) -> None:
        """
        Compute the power of a base saved in open database raised to an exponent and store the result.

        Parameters:
            label_base (str): The label for the base.
            label_exponent (str): The label for the exponent.
            label_result (str): The label for the element where the result is stored.

        Returns:
            None
        """

        for node in self.nodes:
            # DB management
            base = node.get_open(label_base)
            exponent = node.get_open(label_exponent)
            # Local operation: power
            result = pow(base, exponent, self.dsa.p)
            # DB management
            node.set_open(result, label_result)

    def key_agreement_protocol(self, label: str, delete=True) -> None:
        """
        Perform a key agreement protocol to derive a mask of the secret key and the
        corresponding public key.

        Parameters:
            label (str): The label of the pair associated with the secret key mask.
            delete (bool, optional): Whether to delete intermediate data after the protocol.
                Defaults to True.

        Returns:
            None
        """

        q_minus_one = self.q - 1

        # Round 1
        # Step 1:
        random_label = "random"
        self.rss_protocol(q_minus_one, random_label)

        # Round 2
        # Step 2:
        random_minus_label = random_label + "_minus_" + label
        self.subtract_exp_shares_local(random_label, label + "_lambda", random_minus_label)
        base_type_exp = "exp"
        self.pow_share_protocol(base_type_exp, random_minus_label, label + "_sk")

        if self.setup == DSASetup:
            # Step 3:
            base_type_base = "base"
            self.pow_share_protocol(base_type_base, label + "_lambda", label + "_pre_pk")
            # Step 4:
            self.pow_local(label + "_pre_pk", label + "_sk", label + "_pk")
        else:
            # Step 3:
            self.ec_pow_share_protocol(label + "_lambda", label + "_pre_pk")
            # Step 4:
            self.ec_mult_local(label + "_pre_pk", label + "_sk", label + "_pk")

        # DB management
        ## Option only for testing purposes
        if delete:
            [node.delete_share(random_minus_label+"_sh_exp") for node in self.nodes]
            [node.delete_share(random_label+"_sh_exp") for node in self.nodes]
            [node.delete_open(label + "_pre_pk") for node in self.nodes]

    def ec_mult_local(self, label_ec_point: str, label_scalar: str, label_result: str) -> None:
        """
        Compute the multiplication of a scalar value with an elliptic point curve 
        and store the result.

        Parameters:
            label_ec_point (str): The label for the elliptic curve point.
            label_scalar (str): The label for the scalar.
            label_result (str): The label for the element where the result is stored.

        Returns:
            None
        """

        for node in self.nodes:
            # DB management
            ec_point = node.get_open(label_ec_point)
            scalar = node.get_open(label_scalar)
            # Local operation: mult
            result = scalar * ec_point
            # DB management
            node.set_open(result, label_result)

    def encrypt_and_delete_exp_sh_local(self, label: str, client_id: int) -> None:
        """
        Encrypt the share of the exponent element of the LAMBDA pair and delete the original
        LAMBDA pair.

        Parameters:
            label (str): The label for LAMBDA pair.
            client_id (int): Client id.

        Returns:
            None
        """

        for node in self.nodes:
            # DB management
            clear_share = node.get_share(label+"_lambda_sh_exp")
            # Local operation:
            ## Encrypt share
            enc_sh_val = node.he_public_keys[client_id - 1].encrypt(clear_share)
            ## Delete lambda pair
            node.delete_share(label+"_lambda_sh_exp")
            node.delete_share(label+"_lambda_sh_base")
            # DB management
            sh_label = label+"_enc_sh_exp"
            node.set_share(enc_sh_val, sh_label)

    def send_public_key_to_client(self, label: str, client: Client) -> None:
        """
        Nodes send public key to client.

        Parameters:
            label (str): The label for LAMBDA pair.
            client_id (int): Client id.

        Returns:
            None
        """

        all_y = [node.get_open(label+"_pk") for node in self.nodes]
        # Check if all elements in the list are equal
        are_all_equal = all(y == all_y[0] for y in all_y)
        if are_all_equal:
            client.set_open(all_y[0], label+"_pk")
        else:
            raise PublicKeyDisagreement("Abort.")

    def distributed_key_generation_protocol(self, client_id: int, label=None) -> None:
        """
        Execute a distributed key generation protocol for a specific client.

        Parameters:
            client_id (int): The unique identifier for the client.
            label (str, optional): A custom label associated with the client. Defaults to None.

        Returns:
            None
        """

        # Check there exist a client
        client = next((client for client in self.clients if client.id == client_id), None)
        if client == None:
            raise TypeError(f"Client with id {client_id} is not part of the network.")
        label = str(client_id)+"th_client_"+str(label) if label else str(client_id)+"th_client_"+"x"
        delete = not self.debug
        # Step 1
        self.get_lambda([label])

        # Step 2
        self.key_agreement_protocol(label, delete=delete)

        # Step 3
        self.send_public_key_to_client(label, client)

        # Step 4
        self.encrypt_and_delete_exp_sh_local(label, client_id)


    def compute_r_local(self, label: str, client: Client, delete=True) -> None:
        """
        Compute r.

        Parameters:
            label (str): The label of the r element.
            client (Client): A client.

        Returns:
            None
        """

        for node in self.nodes:
            # DB management
            R = node.get_open(label + "_pk")
            # Local operation
            r = R % self.q if self.setup == DSASetup else int(R.x)
            # DB management
            node.set_open(r, label + "_r")
            node.delete_open(label + "_pk")
        client.set_open(r, label + "_r")

    def invert_masked_factor_local(self, label) -> None:
        """
        Invert a masked factor.

        Parameters:
            label (str): The label of the masked factor to be inverted.

        Returns:
            None
        """

        for node in self.nodes:
            # DB management
            masked_factor = node.get_open(label+"_sk")
            share = node.get_share(label+"_lambda_sh_exp")
            # Local operation
            ## Invert masked factor
            inv_masked_factor = egcd(masked_factor, self.q)
            ## Invert share
            inv_share = -share % (self.q - 1)
            # DB management
            node.set_open(inv_masked_factor, label+"_inv_sk")
            sh_inv_label = label+"_inv_lambda_sh_exp"
            node.set_share(inv_share, sh_inv_label)

    def step_4_encrypt_elements(
            self, 
            label_lambda_1: str, 
            label_lambda_2: str, 
            labdel_lambda_k_inv: str, 
            save_label_m: str,
            save_label_gap: str,
            save_label_lambda_1: str,
            save_label_lambda_2: str,
            client_id: int
        ) -> None:
        """
        Step 4 of the Threshold Signing protocol.

        Parameters:
            label (str): The label of the masked factor to be inverted.
            label_lambda_1 (str): The label of lambda 1.
            label_lambda_2 (str): The label of lambda 2.
            labdel_lambda_k_inv (str): The label of :math:`k^{-1}`.
            save_label_m (str): The label to save encrypted m.
            save_label_gap (str): The label to save :math:`\lambda_{\text{gap}}`.
            save_label_lambda_1 (str): The label to save lambda 1.
            save_label_lambda_2 (str): The label to save lambda 2.
            client_id: int

        Returns:
            None
        """
    
        q_minus_one = self.q - 1
        for node in self.nodes:
            # DB management
            sh_lambda_1_exp = node.get_share(label_lambda_1 +"_sh_exp")
            sh_lambda_2_exp = node.get_share(label_lambda_2 +"_sh_exp")
            sh_lambda_k_inv = node.get_share(labdel_lambda_k_inv +"_sh_exp")
            sh_lambda_1_base = node.get_share(label_lambda_1 +"_sh_base")
            sh_lambda_2_base = node.get_share(label_lambda_2 +"_sh_base")
            enc_lambda_sk = node.get_share(str(client_id)+"th_client_x_enc_sh_exp")
            # Local operation
            ## 4(a)
            sh_m = (sh_lambda_1_exp - sh_lambda_k_inv) % q_minus_one
            enc_sh_m = node.he_public_keys[client_id - 1].encrypt(sh_m)
            ## 4(b)
            sh_int_gap = (sh_lambda_k_inv - sh_lambda_2_exp) % q_minus_one
            enc_sh_int_gap = node.he_public_keys[client_id - 1].encrypt(sh_int_gap)
            enc_sh_gap = enc_sh_int_gap + enc_lambda_sk
            ## 4(c)
            enc_sh_lambda_1_base = node.he_public_keys[client_id - 1].encrypt(sh_lambda_1_base)
            enc_sh_lambda_2_base= node.he_public_keys[client_id - 1].encrypt(sh_lambda_2_base)
            # DB management
            node.set_share(enc_sh_m, save_label_m+"_sh_exp")
            node.set_share(enc_sh_gap, save_label_gap+"_sh_exp")
            node.set_share(enc_sh_lambda_1_base, save_label_lambda_1+"_sh_base")
            node.set_share(enc_sh_lambda_2_base, save_label_lambda_2+"_sh_base")


    def delete_shares(self, list: List) -> None:
        """
        Delete a set of shares.

        Parameters:
            list (List): List of shares to delete.

        Returns:
            None
        """

        for node in self.nodes:
            for element in list:
                node.delete_share(element)
    


    def decrypt_and_reconstruct_local(
            self, 
            get_label: str, 
            save_label: str, 
            client: Client
        ) -> None:
        """
        Decryption and reconstruction executed by the client.

        Parameters:
            get_label (str): The label of the shares to be dencrypted and reconstructed.
            save_label (str): The label used to save the result.
            client_id (int): The unique identifier for the client.

        Returns:
            None
        """


        # DB management
        enc_sh_per_node = [client.get_share(get_label+"_sh_exp_node_"+str(node.id)) for node in self.nodes]
        # Local operation
        ## Decrypt
        dec_sh_per_node = [client.he_private_key.decrypt(enc_sh) for enc_sh in enc_sh_per_node]
        q_minus_one = self.q - 1
        ## Reconstruct and take the symmetric value
        dec_val = add(dec_sh_per_node, q_minus_one)
        # DB management
        dec_label = save_label + "_exp"
        client.set_share(dec_val, dec_label)
        [client.delete_share(get_label+"_sh_exp_node_"+str(node.id)) for node in self.nodes] if not self.debug else None

   
    def ts_prep_protocol(self, client_id):
        """
        Execute the preprocessing phase of the threshold signature protocol for a specific client.

        Parameters:
            client_id (int): The unique identifier for the client.

        Returns:
            None

        Raises:
            TypeError: If the client with the provided 'client_id' is not part of the network.
            KeyError: If the public key is not complete for the specified client.
        """

        # Check there exist a client
        client = next((client for client in self.clients if client.id == client_id), None)
        if client == None:
            raise TypeError(f"Client with id {client_id} is not part of the network.")
        # Check there exist client public key triple (<x>, y, Enc([\lambda_x]))
        try: 
            for node in self.nodes:
                node.get_open(str(client_id)+"th_client_x_sk")
                node.get_open(str(client_id)+"th_client_x_pk")
                node.get_share(str(client_id)+"th_client_x_enc_sh_exp")
        except KeyError:
            print(f"Public key triple (<x>, y, Enc([\lambda_x])) from DKG is not complete for client {client_id}. Generate it first using 'distributed_key_generation_protocol({client_id})'")
        
        # Signers preprocessing
        # Step 1
        label_k = str(client_id)+"th_client_k"    
        label_lambda_1 = str(client_id)+"th_client_lambda_1"   
        label_lambda_2 = str(client_id)+"th_client_lambda_2"   
        self.get_lambda([label_k, label_lambda_1, label_lambda_2])
        # Step 2
        self.key_agreement_protocol(label_k)
        # Step 3(a): set r
        self.compute_r_local(label_k, client)
        # Step 3(b): invert k
        self.invert_masked_factor_local(label_k)
        # Step 4: encrypt 
        self.step_4_encrypt_elements(
            label_lambda_1 + "_lambda", 
            label_lambda_2 + "_lambda", 
            label_k + "_inv_lambda", 
            str(client_id)+"th_client_m_lambda_enc",
            str(client_id)+"th_client_gap_lambda_enc",
            str(client_id)+"th_client_lambda_1_enc" ,
            str(client_id)+"th_client_lambda_2_enc" ,
            client_id)
        # Step 5: delete
        self.delete_shares([
            str(client_id)+"th_client_k_lambda_sh_exp",
            str(client_id)+"th_client_k_lambda_sh_base",
            str(client_id)+"th_client_lambda_1_lambda_sh_exp",
            str(client_id)+"th_client_lambda_1_lambda_sh_base",
            str(client_id)+"th_client_lambda_2_lambda_sh_exp",
            str(client_id)+"th_client_lambda_2_lambda_sh_base",
            str(client_id)+"th_client_k_inv_lambda_sh_exp",
        ])

        # Client preprocessing

        # Step 6: send encryption
        label_gap = "gap_lambda"
        label_send_gap = str(client_id)+"th_client_"+ label_gap +"_enc"
        label_m = "m_lambda"
        label_send_m = str(client_id)+"th_client_"+ label_m +"_enc"
        type_share = "exp"
        self.send(type_share, label_send_gap, client, delete=True)
        self.send(type_share, label_send_m, client, delete=True)
        # Step 7: client decrypts and reconstructs
        self.decrypt_and_reconstruct_local(label_send_gap, label_gap, client)
        self.decrypt_and_reconstruct_local(label_send_m, label_m, client)




    def broadcast_masked_message_digest(self, message: str, client: Client) -> None:
        """
        Broadcasts a masked message digest to the client.

        Parameters:
            message (str): The input message to be hashed and masked.
            client (Client): An instance of the client participating in the protocol.

        Returns:
            None
        """
        
        # DB management
        m_lambda_exp = client.get_share("m_lambda_exp")
        gap_lambda_exp = client.get_share("gap_lambda_exp")
        # Local operation
        ## Compute message
        message_digest = SHA256.new(data=message.encode("utf-8"))
        m = int(message_digest.hexdigest(), 16) % self.q
        ## Compute gap particle
        minus_m_plus_gap = (-(m_lambda_exp + gap_lambda_exp)) % (self.q - 1)
        gap_particle = (m * pow(self.h, minus_m_plus_gap, self.q)) % self.q
        # Broadcast
        self.broadcast(gap_particle, str(client.id)+"th_client_gap_particle_m")

    def sign_local(self, client_id: int, delete=True):
        """
        Sign a message locally and optionally delete intermediate shares.

        Parameters:
            client_id (int): The unique identifier of the client.
            delete (bool, optional): A flag indicating whether to delete intermediate shares after signing (default is True).

        Returns:
            None
        """
        q = self.q
        
        for node in self.nodes:
            # DB management
            enc_sh_lambda_1 = node.get_share(str(client_id)+"th_client_lambda_1_enc_sh_base")
            enc_sh_lambda_2 = node.get_share(str(client_id)+"th_client_lambda_2_enc_sh_base")
            p_k_inv = node.get_open(str(client_id)+"th_client_k_inv_sk")
            p_x = node.get_open(str(client_id)+"th_client_x_sk")
            p_r = node.get_open(str(client_id)+"th_client_k_r")
            p_gap_m = node.get_open(str(client_id)+"th_client_gap_particle_m")
            # Local operation
            scalar_k_m = (p_k_inv * p_gap_m) % q
            scalar_k_r_x = (((p_k_inv * p_r) % q) * p_x) % q
            enc_sh_s_gap = enc_sh_lambda_1 * scalar_k_m + enc_sh_lambda_2 * scalar_k_r_x
            # DB management
            node.set_share(enc_sh_s_gap, str(client_id)+"th_client_enc_signature_sh_base")
            if delete:
                node.delete_open(str(client_id)+"th_client_k_sk")

    def reconstruct_and_verify_sig(self, message: str, get_label: str, client: Client, delete=True):
        """
        Reconstructs and verifies a client's digital signature for a given message.

        Parameters:
            message (str): The input message for which the signature is to be reconstructed and verified.
            get_label (str): The label used to retrieve the client's signature share from the database.
            client (Client): An instance of the client for which the signature is reconstructed and verified.
            delete (bool, optional): A flag indicating whether to delete intermediate shares after verification (default is True).

        Returns:
            None: This function doesn't return a value; it verifies the signature and potentially deletes intermediate shares.
        """
        q = self.q
        if self.setup == DSASetup:
            p = self.dsa.p
            g = self.dsa.g
        else: 
            G = self.ecdsa.G
        
        # DB management
        gap_lambda_exp = client.get_share("gap_lambda_exp")
        y = client.get_open(str(client.id)+"th_client_x_pk")
        r = client.get_open(str(client.id)+"th_client_k_r")
        s_h_gap = client.get_share(get_label)
        # Compute signature
        s = (s_h_gap * pow(self.h, gap_lambda_exp, self.q)) % self.q
        # Verify signature
        verify_dsa_signature(message, r, s, y, p, q, g) if self.setup == DSASetup else verify_ecdsa_signature(message, r, s, y, q, G)
        # DB management
        signature_label = str(client.id)+"th_client_s"
        client.set_open(s, signature_label)
        message_label = str(client.id)+"th_client_message"
        client.set_open(message, message_label)

    def decrypt_reconstruct_unmask_verify_sig_local(self, message: str, get_label: str, client: Client, delete=True):
        """
        Reconstructs and verifies a client's digital signature for a given message.

        Parameters:
            message (str): The input message for which the signature is to be reconstructed and verified.
            get_label (str): The label of the shares to be dencrypted and reconstructed.
            client (Client): An instance of the client for which the signature is reconstructed and verified.
            delete (bool, optional): A flag indicating whether to delete intermediate shares after verification (default is True).

        Returns:
            None: This function doesn't return a value; it verifies the signature and potentially deletes intermediate shares.
        """
        q = self.q
        if self.setup == DSASetup:
            p = self.dsa.p
            g = self.dsa.g
        else: 
            G = self.ecdsa.G


        # DB management
        enc_sh_per_node = [client.get_share(str(client.id)+"th_client_"+get_label+"_sh_base_node_"+str(node.id)) for node in self.nodes]
        gap_lambda_exp = client.get_share("gap_lambda_exp")
        y = client.get_open(str(client.id)+"th_client_x_pk")
        r = client.get_open(str(client.id)+"th_client_k_r")

        # Local operation
        ## Decrypt
        dec_sh_per_node = [client.he_private_key.decrypt(enc_sh) for enc_sh in enc_sh_per_node]
        q_minus_one = self.q - 1
        ## Reconstruct
        s_h_gap = add(dec_sh_per_node, q)
        ## Unmask
        s = (s_h_gap * pow(self.h, gap_lambda_exp, q)) % q
        # Verify signature
        verify_dsa_signature(message, r, s, y, p, q, g) if self.setup == DSASetup else verify_ecdsa_signature(message, r, s, y, q, G)
        # DB management
        signature_label = str(client.id)+"th_client_s"
        client.set_open(s, signature_label)
        message_label = str(client.id)+"th_client_message"
        client.set_open(message, message_label)

        

    def ts_online_protocol(self, message: str, client_id: int) -> None:
        """
        Executes the online phase of the threshold signature protocol for a specific client.

        Parameters:
            message (str): The message to be signed by the client.
            client_id (int): The unique identifier of the client participating in the protocol.

        Returns:
            None
        """
        
        # Check there exist a client
        client = next((client for client in self.clients if client.id == client_id), None)
        if client == None:
            raise TypeError(f"Client with id {client_id} is not part of the network.")
        # Check there 'ts_prep_protocol' was run
        try:
            for node in self.nodes:
                node.get_open(str(client_id)+"th_client_k_inv_sk")
                node.get_open(str(client_id)+"th_client_k_r")
                client.get_share("gap_lambda_exp")
                client.get_share("m_lambda_exp")
        except KeyError:
            print(f"The preprocessing phase was not run for client {client_id}.")
        

        # Step 8: compute digest, mask it, include gap and broadcast the result to all nodes
        self.broadcast_masked_message_digest(message, client)
 
        # Step 9a: all nodes compute locally the shares corresponding to clients 
        delete = not self.debug
        self.sign_local(client_id, delete=delete)

        # Step 9b: send encryption
        label_enc_sig = "enc_signature"
        label_send_enc_sig = str(client_id)+"th_client_" + label_enc_sig
        type_share = "base"
        self.send(type_share, label_send_enc_sig, client, delete=True)
        # Step 10: client decrypts, reconstructs, unmasks and verifies signature
        self.decrypt_reconstruct_unmask_verify_sig_local(message, label_enc_sig, client)

    def print_signature(self, client_id: int) -> None:

        # Check there exist a client
        client = next((client for client in self.clients if client.id == client_id), None)
        if client == None:
            raise TypeError(f"Client with id {client_id} is not part of the network.")
        # Check there exist client public key triple (<x>, y, Enc([\lambda_x]))
        try: 
            r = client.get_open(str(client.id)+"th_client_k_r")
            s = client.get_open(str(client.id)+"th_client_s")
            m = client.get_open(str(client.id)+"th_client_message")
        except KeyError:
            print(f"Signature not generated for client {client_id}.'")

        print(f"    Client(id={client_id},")
        print(f"      r={r},")
        print(f"      s={s},")
        print(f"      m={m},\n    )")


    def retrieve_signature(self, client_id: int) -> (int, int, str):

        # Check there exist a client
        client = next((client for client in self.clients if client.id == client_id), None)
        if client == None:
            raise TypeError(f"Client with id {client_id} is not part of the network.")
        # Check there exist client public key triple (<x>, y, Enc([\lambda_x]))
        try: 
            r = client.get_open(str(client.id)+"th_client_k_r")
            s = client.get_open(str(client.id)+"th_client_s")
            m = client.get_open(str(client.id)+"th_client_message")
        except KeyError:
            print(f"Signature not generated for client {client_id}.'")

        return r, s, m


class PublicKeyDisagreement(Exception):
    def __init__(self, message):
        self.message = f"Public keys are not consistent. {message}"
        super().__init__(self.message)

