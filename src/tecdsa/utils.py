import unittest
import random
from Crypto.PublicKey.ECC import EccPoint
from Crypto.Hash import SHA256

rand = random.randrange

def add(values: list[int], size: int) -> int:
    """
    Calculate the sum of a list of integers modulo 'size'.

    Args:
        values (list[int]): A list of integers to be summed.
        size (int): The modulo value.

    Returns:
        int: The sum of the integers in 'values' modulo 'size'.

    Examples:
        >>> add([2, 4, 6], 5)
        2
        >>> add([3, 7, 10], 4)
        0
    """

    result = 0
    for v in values:
        result = (result + v) % size
    return result

def add_ec(points: list[EccPoint]) -> int:
    """
    Calculate the sum of a list of elliptic curve points.

    Args:
        points (list[EccPoint]): A list of elliptic curve points to be summed.

    Returns:
        EccPoint: The sum of the points.
    """

    result = points[0]
    for v in points[1:]:
        result = (result + v)
    return result


def generate_additive_shares(secret: int, n: int, size: int) -> list[int]:
    """
    Generates additive secret shares for a given secret value, using modular arithmetic.

    Args:
        secret (int): The secret value to be shared.
        n (int): The number of shares to generate.
        size (int): The modulus value for modular arithmetic.

    Returns:
        List[int]: A list of additive secret shares.

    Example:
        >>> random.seed(0)
        >>> generate_additive_shares(26, 3, 2**5)
        [8, 24, 26]
    """
    shares = [rand(size) for _ in range(n-1)]
    last_sh = (secret - add(shares, size)) % size
    shares = [last_sh] + shares

    return shares

def multiply(values: list[int], size: int) -> int:
    """
    Calculate the product of a list of values, taking the modulus 'size' at each step of multiplication.

    Args:
        values (list[int]): List of integers to be multiplied.
        size (int): Modulus value to prevent the result from growing too large.

    Returns:
        int: The product of the values, computed modulo 'size'.

    Example:
        >>> multiply([2, 4, 6], 5)
        3
    """

    result = 1
    for v in values:
        result = (result * v) % size
    return result

def egcd(a: int, p: int) -> int:
    """
    Calculate the modular multiplicative inverse of 'a' modulo 'p' using the extended Euclidean algorithm.

    Args:
        a (int): Integer for which the modular inverse is calculated.
        p (int): Modulus value for the modulo operation.

    Returns:
        int: Modular multiplicative inverse of 'a' modulo 'p'.
    """
    q = p
    x, last_x = 0, 1
    y, last_y = 1, 0
    while q != 0:
        quot = a // q
        a, q = q, a % q
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x % p

def hash(message: str, q: int):
    """
    Computes the hash of the mesage using SHA256.

    Parameters:
        message (str): The message to verify the signature for.
        q (int): Field size to embbed digest.

    Returns:
        m (int): hash of message.
    """

    message_digest = SHA256.new(data=message.encode("utf-8"))
    m = int(message_digest.hexdigest(), 16) % q

    return m

def verify_dsa_signature(message: int, r: int, s: int, y: int, p: int, q: int, g: int) -> None:
    """
    Verify a Digital Signature Algorithm (DSA) signature.

    Parameters:
        message (str): The message to verify the signature for.
        r (int): The 'r' component of the DSA signature.
        s (int): The 's' component of the DSA signature.
        y (int): The public key 'y' associated with the signer.
        p (int): The prime modulus used in DSA.
        q (int): A prime divisor of 'p'.
        g (int): The generator of the subgroup used in DSA.

    Returns:
        None: If the signature is valid, no exceptions are raised.

    Raises:
        VerifySignatureError: If the signature verification fails due to one of the following reasons:
            'r' or 's' is greater than or equal to 'q'; the calculated 'v' does not match 'r'.
    """
    
    if r >= q or s >= q:
        raise VerifySignatureError("Signature out of bound q. Abort.")
    m = hash(message, q)
    w = egcd(s, q)
    u1 = (m * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
    if v != r:
        raise VerifySignatureError("Signature mismatch. Abort.")
    
def verify_ecdsa_signature(message: int, r: int, s: int, Y: EccPoint, q: int, G: EccPoint) -> None:
    """
    Verify an Elliptic Curve Digital Signature Algorithm (ECDSA) signature.

    Parameters:
        message (str): The message to verify the signature for.
        r (int): The 'r' component of the DSA signature.
        s (int): The 's' component of the DSA signature.
        Y (EccPoint): The public key 'y' associated with the signer.
        q (int): Order of the Elliptic Curve group.
        G (EccPoint): The generator of the Elliptic Curve group.

    Returns:
        None: If the signature is valid, no exceptions are raised.

    Raises:
        VerifySignatureError: If the signature verification fails due to one of the following reasons:
            'r' or 's' is greater than or equal to 'q'; the calculated 'v' does not match 'r'.
    """
    
    if r >= q or s >= q:
        raise VerifySignatureError("Signature out of bound q. Abort.")
    m = hash(message, q)
    w = egcd(s, q)
    u1 = (m * w) % q
    u2 = (r * w) % q
    V = u1 * G + u2 * Y
    v = int(V.x)
    if v != r:
        raise VerifySignatureError("Signature mismatch. Abort.")
    

class VerifySignatureError(Exception):
    def __init__(self, message):
        self.message = f"Signature verification failed. {message}"
        super().__init__(self.message)


class TestUtils(unittest.TestCase):
    
    def setUp(self): 
        random.seed(0)

    def test_add(self):
        
        result = add([2,4,6], 5)
        self.assertEqual(result, 2)

    def test_generate_additive_shares(self):
        
        secret = 29
        nr_shares = 3
        size = 2**5
        shares = generate_additive_shares(secret, nr_shares, size)
        computed_secret = add(shares, size)
        self.assertEqual(secret, computed_secret)

    def test_multiply(self):
        
        result = multiply([2,4,6], 5)
        self.assertEqual(result, 3)    




if __name__ == "__main__":
    unittest.main()
