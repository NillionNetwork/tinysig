from dataclasses import dataclass, field
from typing import Dict, List, Union

from .utils import add, generate_additive_shares

@dataclass
class Node:
    """ Represents a node in the network."""

    id: int
    """Identifier for the node."""
    shares_db: Dict[str, int] = field(default_factory=dict) 
    """Database for holding shares."""
    open_db: Dict[str, int] = field(default_factory=dict)
    """Database for holding open values."""
    he_public_keys: Dict[int, int] = field(default_factory=dict) 
    """Dictionary for holding homomorphic encryption public keys."""

    def get_share(self, label: str) -> None:
        """Retrieve a share from the 'shares_db'."""
        return self.shares_db[label]

    def get_open(self, label: str) -> None:
        """Retrieve an open value from the 'open_db'."""
        return self.open_db[label]

    def set_share(self, value, label: str) -> None:
        """Set a share in the 'shares_db'."""
        self.shares_db[label] = value

    def set_open(self, value,  label: str) -> None:
        """Set an open value in the 'open_db'."""
        self.open_db[label] = value
    
    def delete_share(self, label: str) -> None:
        """Delete a share from the 'shares_db'."""
        self.shares_db.pop(label)

    def delete_open(self, label: str) -> None:
        """Delete an open value from the 'open_db'."""
        self.open_db.pop(label)

@dataclass
class Client(Node):
    """Represents a client node in the network, inheriting from the 'Node' class."""
    he_private_key: int = field(default=0)

class Network:
    """Represents a network of nodes and clients.
    
    Manages the interactions and cryptographic operations within the network, 
    including sharing secrets, broadcasting values, and reconstructing shared values.
    """

    nodes: List[Node]
    """List of nodes in the network."""
    clients: List[Client]
    """List of clients in the network."""
    q: int
    """Prime field."""
    h: int  
    """Multiplicative field generator."""

    def __init__(self, N, q, h=2, C=1):
        """
        Initialize the network with 'N' nodes, prime field 'q', field generator 'h', and 'C' clients.
        
        Parameters:
            N (int): Number of nodes in the network.
            q (int): Prime field.
            h (int): Multiplicative field generator (default is 2).
            C (int): Number of clients in the network (default is 1).
        """
        self.nodes = [Node(i+1) for i in range(N)]
        self.clients = [Client(i+1) for i in range(C)]
        self.N = N
        self.q = q
        self.h = h

    def print(self):
        """Print a readable representation of the network, including nodes and clients with their databases."""
        print(f"Network(N={len(self.nodes)}, q={self.q},")
        print("  nodes=[")
        for node in self.nodes:
            print(f"    Node(id={node.id},")
            print("      shares_db={")
            for key, value in node.shares_db.items():
                print(f"        {key}: {value},")
            print("             },")
            print("      public_keys={")
            for key, value in node.he_public_keys.items():
                print(f"        {key}: {value},")
            print("             },")
            print("      open_db={")
            for key, value in node.open_db.items():
                print(f"        {key}: {value},")
            print("             }")
            print("    )")
        print("  ]\n)")
        print("  clients=[")
        for client in self.clients:
            print(f"    Client(id={client.id},")
            print("      shares_db={")
            for key, value in client.shares_db.items():
                print(f"        {key}: {value},")
            print("             },")
            print("      public_keys={")
            for key, value in client.he_public_keys.items():
                print(f"        {key}: {value},")
            print("             },")
            print(f"      private_keys={client.he_private_key},")
            print("      open_db={")
            for key, value in client.open_db.items():
                print(f"        {key}: {value},")
            print("             }")
            print("    )")
        print("  ]\n)")

    def reconstruct_local(self, type_share: str, get_label: str, save_label: str, party: Union[Client, Node]) -> None:
        """Locally reconstruct exponent share ('exp') or base ('base') shared value."""
        
        type_label = "_sh_exp" if type_share == "exp" else "_sh_base"
        p = (self.q - 1) if type_share == "exp" else self.q
        shares = [party.get_share(get_label+type_label+"_node_"+str(node.id)) for node in self.nodes]
        reconstructed = add(shares, p)
        party.set_share(reconstructed, save_label)

    def broadcast(self, element: int, label: str) -> None:
        """Send element to all nodes."""

        for node in self.nodes:
            node.open_db[label] = element

    def send(self, type_share: str, label: str, party: Union[Client, Node], delete=False) -> None:
        """Send exponent ('exp') or base ('base') share to party."""
        
        type_label = "_sh_exp" if type_share == "exp" else "_sh_base"
        for node in self.nodes:
            sh_node = node.get_share(label+type_label)
            sh_label = label+type_label+"_node_"+str(node.id)
            party.set_share(sh_node, sh_label)
            node.delete_share(label+type_label) if delete else None

    def share(self, secret: int, size: int, label: str) -> None:
        """Share secret value with all"""

        shares = generate_additive_shares(secret, self.N, size)
        for node in self.nodes:
            node.set_share(shares[node.id - 1], label)

    def reveal(self, type_share: str, get_label: str, save_label: str, party: Union[Client, Node]) -> None:
        """Send exponent ('exp') or base ('base') share to party."""      
        
        self.send(type_share, get_label, party)
        self.reconstruct_local(type_share, get_label, save_label, party)






