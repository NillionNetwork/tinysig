from phe import paillier
from random import seed
import time

from tinysig.utils import add, verify_ecdsa_signature
from tinysig.setup import DSASetup, ECDSASetup
from tinysig.tecdsa import ThresholdSignature


import unittest


class TestSig(unittest.TestCase):
    

    def setUp(self):
        seed(0)
        N = 10; C = 1
        # DSA setup
        manual_dsa_setup = True
        if manual_dsa_setup:
            p = 16987220163402883416449356930313946536948708368250187300904484990592060034399925373558684845589122357155245527725130833676269318205326149268410610561367974110319706088695097181729621805806503895242356834473026604015120592348890617701675387428807728090415853765634415325555621648235338466349957683063948139664640253794461972428009207212678775162641560258829400418398089166048123240989061901894801714545511227607162820358567023001939860545346903340718565981921863209491363679301897076211852920953764568258713784702534591771430944194446014721504677270780731006777716425745362753111142293413901721847152726957943402872047 
            q = 18615201011907374064080708325380633467600489307695820739772219003499; 
            g = 1440750739647392583923353319762863205412412735463771135600354281498545556560554285032144083567469348458038821471561505478727536048946568600306333026876282227253717145726280535747755789389298351217147981114134445522434273687560094566805116079958307881112688486903459951003823567315217837479260063662350297462681218852749673559083125704211468000331391500202590446254295826681166987302499736009857926325072657165790463352645906484288271010829609728496608136458748019477999277575560554800692468233144862681997749241093911491601564874805253852956797072221469937174346581408575685518457073416604892562933677029344283366064
            h = 2
            dsa_setup = DSASetup(p, q, g, h)
            self.fnil = ThresholdSignature(N, C, setup=dsa_setup)
            self.fnil_debug = ThresholdSignature(N, C, setup=dsa_setup, debug=True)
        else:
            self.fnil = ThresholdSignature(N, C)
            self.fnil_debug = ThresholdSignature(N, C, debug=True)
        # ECDSA setup
        ecdsa_setup = ECDSASetup(curve="P-256")
        self.ecnil = ThresholdSignature(N, C, setup=ecdsa_setup)
        self.ecnil_debug = ThresholdSignature(N, C, setup=ecdsa_setup, debug=True)

    def test_generate_dsa_setup(self):
        if False:
            dsa_setup, h = DSASetup.generate_dsa_setup()

    def test_rss(self):
        size = self.fnil.q - 1
        self.fnil.rss_protocol(size, "ka_share")

    def test_pow_share_protocol(self):
        # setup
        vals = [23, 4839, 12341235234]
        for val in vals:
            q = self.fnil.q
            h_val = pow(self.fnil.h, val, q)
            # Share
            label = "ka_x"
            self.fnil.share(val, q - 1, label + "_sh_exp")
            
            # compute expint
            base_type = "exp"
            self.fnil.pow_share_protocol(base_type, label, label)
            
            # test
            ## check all nodes have the same expint value.
            results_gr = []
            for node in self.fnil.nodes:
                results_gr.append(node.open_db[label])
            first_result_gr = results_gr[0]
            self.assertTrue(all(element == first_result_gr for element in results_gr))
            ## check they are correct
            self.assertEqual(h_val, first_result_gr)

    def test_ec_pow_share_protocol(self):
        # setup
        vals = [23, 4839, 12341235234]
        for val in vals:
            q = self.ecnil.q
            G = self.ecnil.ecdsa.G
            val_G = val * G
            # Share
            label = "ka_x"
            self.ecnil.share(val, q, label + "_sh_base")
            
            self.ecnil.ec_pow_share_protocol(label, label)
            
            # test
            ## check all nodes have the same value.
            results_gr = []
            for node in self.ecnil.nodes:
                results_gr.append(node.open_db[label])
            first_result_gr = results_gr[0]
            self.assertTrue(all(element == first_result_gr for element in results_gr))
            ## check they are correct
            self.assertEqual(val_G, first_result_gr)

    def test_key_agreement(self):
        label = "x"
        self.fnil.get_lambda([label])
        self.fnil.key_agreement_protocol(label, delete=False)

        # Check that y == g^x
        ## Reconstruct r
        shares = [node.get_share("random"+"_sh_exp") for node in self.fnil.nodes]
        r = add(shares, self.fnil.q - 1)
        ## Compute x: x = h^r
        x = pow(self.fnil.h, r, self.fnil.q)
        # check y == g^x
        y = self.fnil.nodes[0].open_db[label + "_pk"]
        g_x = pow(self.fnil.dsa.g, x, self.fnil.dsa.p)
        self.assertEqual(y, g_x)

    def test_ec_key_agreement(self):
        label = "x"
        self.ecnil.get_lambda([label])
        self.ecnil.key_agreement_protocol(label, delete=False)

        # Check that y == x*G
        ## Reconstruct r
        shares = [node.get_share("random"+"_sh_exp") for node in self.ecnil.nodes]
        r = add(shares, self.ecnil.q - 1)
        ## Compute x: x = h^r
        x = pow(self.ecnil.h, r, self.ecnil.q)
        # check y == x*G
        y = self.ecnil.nodes[0].open_db[label + "_pk"]
        x_G = x * self.ecnil.ecdsa.G 
        self.assertEqual(y, x_G)

    def test_paillier_encryption_gf(self):
        vals = [12341247]
        for val in vals:
            q_minus_one = self.fnil.q - 1
            # Share
            label = "test_sh_exp"
            self.fnil.share(val, q_minus_one,label)
            # Collect shares
            shares = [node.get_share(label) for node in self.fnil.nodes]
            
            # Paillier
            pub_key, priv_key = paillier.generate_paillier_keypair()
            ## Testing sum of elements
            start_all = time.time()
            start_enc = time.time()
            enc_shares = [pub_key.encrypt(val) for val in shares]
            finish_enc = time.time()
            enc_sum = enc_shares[0]
            start_add = time.time()
            for enc_element in enc_shares[1:]:
                enc_sum = enc_sum + enc_element
            finish_add = time.time()
            start_dec = time.time()
            decrypted_final = priv_key.decrypt(enc_sum) % q_minus_one
            finish_dec = time.time()
            finish_all = time.time()
            enc_time = (finish_enc - start_enc)
            add_time = (finish_add - start_add)
            dec_time = (finish_dec - start_dec)
            all_time = (finish_all - start_all)
            n = len(self.fnil.nodes)

            print(f"Time taken to encrypt {n} shares:\n{enc_time} seconds")
            print(f"Time taken to add {n} encrypted shares:\n{add_time} seconds")
            print(f"Time taken for one decryption:\n{dec_time} seconds")
            print(f"Time evaluation for encrypted addition of {n} shares and one decryption (overall time):\n{all_time} seconds")

            final = add(shares, q_minus_one)
            self.assertEqual(final, decrypted_final)    

            ## Testing scalar multiplication
            enc_3 = pub_key.encrypt(3)
            enc_4 = pub_key.encrypt(4)
            start_multiply =  time.time()
            enc_42 = enc_3*10 + enc_4*3
            finish_multiply = time.time()
            scalar_multiplication_time = finish_multiply - start_multiply
            print(f"Scalar multiplication: {scalar_multiplication_time} seconds" )

            self.assertEqual(42, priv_key.decrypt(enc_42))

    def test_distributed_key_generation(self):
        start_time = time.time()
        self.fnil.distributed_key_generation_protocol(1)
        end_time = time.time()
        n = len(self.fnil.nodes)
        elapsed_time_per_party = (end_time - start_time)/n
        print(f"Time evaluation for DSA-DKG protocol (computation):\n{elapsed_time_per_party} seconds")

    def test_ec_distributed_key_generation(self):
        start_time = time.time()
        self.ecnil.distributed_key_generation_protocol(1)
        end_time = time.time()
        n = len(self.ecnil.nodes)
        elapsed_time_per_party = (end_time - start_time)/n
        print(f"Time evaluation for ECDSA-DKG protocol (computation):\n{elapsed_time_per_party} seconds")

    def test_error_client_missing_ts_prep_protocol(self):
        if False:
            self.fnil.ts_prep_protocol(2)

    def test_error_secret_key_missing_ts_prep_protocol(self):
        if False:
            self.fnil.ts_prep_protocol(1)

    def test_ts_prep_protocol(self):
        self.fnil.distributed_key_generation_protocol(1)
        start_time = time.time()
        self.fnil.ts_prep_protocol(1)
        end_time = time.time()
        n = len(self.fnil.nodes)
        elapsed_time_per_party = (end_time - start_time)/n
        print(f"Time evaluation for Prep DSA-Sign protocol (computation):\n{elapsed_time_per_party} seconds")

    def test_ec_ts_prep_protocol(self):
        self.ecnil.distributed_key_generation_protocol(1)
        start_time = time.time()
        self.ecnil.ts_prep_protocol(1)
        end_time = time.time()
        n = len(self.ecnil.nodes)
        elapsed_time_per_party = (end_time - start_time)/n
        print(f"Time evaluation for Prep ECDSA-Sign protocol (computation):\n{elapsed_time_per_party} seconds")

    def test_ts_online_protocol(self):
        self.fnil.distributed_key_generation_protocol(1)
        self.fnil.ts_prep_protocol(1)
        message = "Message to sign"
        start_time = time.time()
        self.fnil.ts_online_protocol(message, 1)
        end_time = time.time()
        n = len(self.fnil.nodes)
        elapsed_time_per_party = (end_time - start_time)/n
        print(f"Time evaluation for Online DSA-Sign protocol (computation):\n{elapsed_time_per_party} seconds")
        self.fnil.print()

    def test_ec_bs_online_protocol(self):
        self.ecnil.distributed_key_generation_protocol(1)
        self.ecnil.ts_prep_protocol(1)
        message = "Message to sign"
        start_time = time.time()
        self.ecnil.ts_online_protocol(message, 1)
        end_time = time.time()
        elapsed_time_per_party = (end_time - start_time)
        print(f"Time evaluation for Online ECDSA-Sign protocol (computation):\n{elapsed_time_per_party} seconds")
    
    def test_print_signature(self):
        client_id = 1
        self.fnil.distributed_key_generation_protocol(client_id)
        self.fnil.ts_prep_protocol(client_id)
        message = "Message to sign"
        self.fnil.ts_online_protocol(message, client_id)
        self.fnil.print_signature(client_id)
        self.fnil.print()

    def test_ec_print_signature(self):
        client_id = 1
        self.ecnil.distributed_key_generation_protocol(client_id)
        self.ecnil.ts_prep_protocol(client_id)
        message = "Message to sign"
        self.ecnil.ts_online_protocol(message, client_id)
        self.ecnil.print_signature(client_id)

    def test_debug(self):
        client_id = 1
        self.fnil_debug.distributed_key_generation_protocol(client_id)
        self.fnil_debug.ts_prep_protocol(client_id)
        message = "Message to sign"
        self.fnil_debug.ts_online_protocol(message, client_id)
        self.fnil_debug.print()

    def test_ec_debug(self):
        client_id = 1
        self.ecnil_debug.distributed_key_generation_protocol(client_id)
        self.ecnil_debug.ts_prep_protocol(client_id)
        message = "Message to sign"
        self.ecnil_debug.ts_online_protocol(message, client_id)

    def test_no_debug(self):
        client_id = 1
        self.fnil.distributed_key_generation_protocol(client_id)
        self.fnil.ts_prep_protocol(client_id)
        message = "Message to sign"
        self.fnil.ts_online_protocol(message, client_id)
        self.fnil.print_signature(1)

    def test_ec_no_debug(self):
        client_id = 1
        self.ecnil.distributed_key_generation_protocol(client_id)
        self.ecnil.ts_prep_protocol(client_id)
        message = "Message to sign"
        self.ecnil.ts_online_protocol(message, client_id)
        self.ecnil.print_signature(1)

    def test_ec_verify(self):
        client_id = 1
        self.ecnil.distributed_key_generation_protocol(client_id)
        self.ecnil.ts_prep_protocol(client_id)
        message = "Message to sign"
        self.ecnil.ts_online_protocol(message, client_id)
        r, s, m = self.ecnil.retrieve_signature(client_id)
        Y = self.ecnil.clients[client_id - 1].open_db[str(client_id)+"th_client_x_pk"]
        q = self.ecnil.q
        G = self.ecnil.ecdsa.G
        verify_ecdsa_signature(message, r, s, Y, q, G)



if __name__ == "__main__":
    unittest.main()