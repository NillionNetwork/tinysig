
from sympy.ntheory.residue_ntheory import primitive_root
from Crypto.PublicKey import DSA
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccPoint
from dataclasses import dataclass
from typing import Optional


def get_generator(q):
    """
    Get the generator (primitive root) for a given prime number q.

    Parameters:
        q (int): A prime number for which the generator is needed.

    Returns:
        int: The generator (primitive root) for the given prime number.

    Example:
        >>> get_generator(23)
        5
    """
    return int(primitive_root(q))

@dataclass
class DSASetup:
    """
    Dataclass representing a DSA (Digital Signature Algorithm) setup.

    Example:
        setup = DSASetup.generate_dsa_setup()
    """

    p: int
    """The DSA modulus."""
    q: int
    """The order of the subgroup."""
    g: int
    """A generator of the subgroup."""
    h: int
    """A generator of the field :math:`\mathbb{Z}_q`."""

    def generate_dsa_setup():
        """Generate a DSA setup based on system parameters."""
        key = DSA.generate(2048)
        g = int(key._key['g'])
        p = int(key._key['p'])
        q = int(key._key['q']) 
        h = get_generator(q)
        return DSASetup(p, q, g, h)
    
@dataclass
class ECDSASetup:
    """
    Dataclass representing an ECDSA (Elliptic Curve Digital Signature Algorithm) setup.

    Example:
        setup = ECDSASetup.generate_ecdsa_setup()
    """

    curve: str
    """The name of the elliptic curve."""
    p: Optional[int] = None
    """The finite field of the elliptic curve."""
    q: Optional[int] = None
    """The order of the elliptic curve group."""
    G: Optional[EccPoint] = None
    """A base point on the elliptic curve."""
    h: Optional[int] = None
    """A generator of field :math:`\mathbb{Z}_q`."""

    def generate_ecdsa_setup(self):
        """
        Generate an ECDSA setup for the specified elliptic curve.

        Returns:
            ECDSASetup: An instance of ECDSASetup with generated parameters.

        Raises:
            ValueError: If the specified curve is not supported.

        Example:
            >>> setup = ECDSASetup(curve='P-256').generate_ecdsa_setup()
        """

        supported_curves = self.supported_curves()
        curve = self.curve
        if curve not in supported_curves:
            raise ValueError("{} is not one of the specified curves. \
                             Please choose one of the following curves:\n \
                             ['P-192', 'P-224', 'P-256', 'P-384', 'P-521']".format(curve))
        p = int(ECC._curves[curve].p)
        q = int(ECC._curves[curve].order)
        G = ECC._curves[curve].G
        h = get_generator(int(q))
        return ECDSASetup(curve, p, q, G, h)
    
    @staticmethod
    def supported_curves():
        """
        Get a list of supported elliptic curves.

        Returns:
            List[str]: A list of supported elliptic curve names.

        Example:
            >>> supported_curves = ECDSASetup.supported_curves()
            >>> print(supported_curves)
            ['P-192', 'P-224', 'P-256', 'P-384', 'P-521']
        """
        
        return ['P-192', 'P-224', 'P-256', 'P-384', 'P-521']
    
    def print_supported_curves(self):
        """
        Print the list of supported elliptic curves.
        """

        supported_curves = self.supported_curves()
        print("Supported Elliptic Curves: ", supported_curves)


