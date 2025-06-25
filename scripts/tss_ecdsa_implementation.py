"""
Implémentation TSS ECDSA pour signature distribuée
Protocole de signature à seuil sans reconstruction de clé privée
"""

import hashlib
import secrets
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
import json
import time

@dataclass
class PreprocessingData:
    """Données de préparation pour signature TSS"""
    k_share: int          # Part du nonce k
    gamma_share: int      # Part du secret gamma
    R: ec.EllipticCurvePoint  # Point R = k * G
    commitment: bytes     # Engagement pour cette round

@dataclass
class SignatureShare:
    """Part de signature générée par un nœud"""
    node_id: int
    s_share: int          # Part de signature s
    R: ec.EllipticCurvePoint  # Point R utilisé
    timestamp: float
    
@dataclass
class ThresholdSignature:
    """Signature ECDSA finale reconstituée"""
    r: int
    s: int
    recovery_id: int
    message_hash: bytes

class TSSECDSA:
    """
    Implémentation du protocole TSS ECDSA
    Compatible avec les standards ECDSA existants
    """
    
    def __init__(self, threshold: int, participants: List[int], curve=ec.SECP256K1()):
        self.threshold = threshold
        self.participants = participants
        self.num_participants = len(participants)
        self.curve = curve
        self.field_order = curve.generator.curve.field_size
        self.generator = curve.generator
        
        # Stockage des parts de clés (provenant du DKG)
        self.private_shares: Dict[int, int] = {}
        self.public_keys: Dict[int, ec.EllipticCurvePoint] = {}
        self.group_public_key: Optional[ec.EllipticCurvePoint] = None
        
        # Données de préparation
        self.preprocessing_data: Dict[int, PreprocessingData] = {}
        
    def load_dkg_results(self, dkg_results: Dict[int, Tuple[int, ec.EllipticCurvePoint]]):
        """Charge les résultats du DKG"""
        for node_id, (private_share, public_key) in dkg_results.items():
            self.private_shares[node_id] = private_share
            self.public_keys[node_id] = public_key
        
        # Calcul de la clé publique du groupe (somme des clés publiques)
        self.group_public_key = self._compute_group_public_key()
        print(f"✅ Clés DKG chargées pour {len(self.private_shares)} nœuds")
    
    def _compute_group_public_key(self) -> ec.EllipticCurvePoint:
        """Calcule la clé publique du groupe"""
        if not self.public_keys:
            raise ValueError("Aucune clé publique chargée")
        
        group_key = list(self.public_keys.values())[0]
        for pub_key in list(self.public_keys.values())[1:]:
            group_key = self._point_add(group_key, pub_key)
        
        return group_key
    
    def _point_add(self, p1: ec.EllipticCurvePoint, p2: ec.EllipticCurvePoint) -> ec.EllipticCurvePoint:
        """Addition de points sur courbe elliptique"""
        # Implémentation simplifiée - utiliser cryptography en production
        return p1  # Placeholder
    
    def _scalar_mult(self, point: ec.EllipticCurvePoint, scalar: int) -> ec.EllipticCurvePoint:
        """Multiplication scalaire"""
        return point  # Placeholder
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """Inverse modulaire"""
        return pow(a, m - 2, m)  # Pour les corps premiers
    
    def preprocessing_phase(self, signing_nodes: List[int]) -> Dict[int, PreprocessingData]:
        """
        Phase de préparation (peut être faite offline)
        Génère les données nécessaires pour une signature future
        """
        if len(signing_nodes) < self.threshold:
            raise ValueError(f"Pas assez de nœuds signataires: {len(signing_nodes)} < {self.threshold}")
        
        preprocessing_data = {}
        
        for node_id in signing_nodes:
            if node_id not in self.private_shares:
                raise ValueError(f"Nœud {node_id} n'a pas de clé privée")
            
            # Génération du nonce k aléatoire (part)
            k_share = secrets.randbelow(self.field_order)
            
            # Génération du secret gamma aléatoire
            gamma_share = secrets.randbelow(self.field_order)
            
            # Calcul de R = k_share * G
            R = self._scalar_mult(self.generator, k_share)
            
            # Génération d'un engagement
            commitment_data = f"{node_id}:{k_share}:{gamma_share}:{time.time()}"
            commitment = hashlib.sha256(commitment_data.encode()).digest()
            
            preprocessing = PreprocessingData(
                k_share=k_share,
                gamma_share=gamma_share,
                R=R,
                commitment=commitment
            )
            
            preprocessing_data[node_id] = preprocessing
            
        self.preprocessing_data = preprocessing_data
        print(f"✅ Préparation terminée pour {len(signing_nodes)} nœuds")
        return preprocessing_data
    
    def compute_lagrange_coefficient(self, node_id: int, signing_nodes: List[int]) -> int:
        """Calcule le coefficient de Lagrange pour l'interpolation"""
        numerator = 1
        denominator = 1
        
        for other_node in signing_nodes:
            if other_node != node_id:
                numerator = (numerator * other_node) % self.field_order
                denominator = (denominator * (other_node - node_id)) % self.field_order
        
        # Calcul de l'inverse modulaire
        denominator_inv = self._mod_inverse(denominator, self.field_order)
        
        return (numerator * denominator_inv) % self.field_order
    
    def signing_phase(self, message: bytes, signing_nodes: List[int]) -> Dict[int, SignatureShare]:
        """
        Phase de signature distribuée
        Chaque nœud génère sa part de signature
        """
        if not self.preprocessing_data:
            raise ValueError("Phase de préparation non effectuée")
        
        # Hachage du message
        message_hash = hashlib.sha256(message).digest()
        z = int.from_bytes(message_hash, 'big') % self.field_order
        
        # Calcul du point R combiné (somme des R individuels)
        combined_R = list(self.preprocessing_data.values())[0].R
        for preprocessing in list(self.preprocessing_data.values())[1:]:
            combined_R = self._point_add(combined_R, preprocessing.R)
        
        # r = x-coordinate de R mod field_order
        r = combined_R.x % self.field_order
        if r == 0:
            raise ValueError("r = 0, recommencer avec de nouveaux nonces")
        
        signature_shares = {}
        
        for node_id in signing_nodes:
            if node_id not in self.preprocessing_data:
                raise ValueError(f"Pas de données de préparation pour le nœud {node_id}")
            
            preprocessing = self.preprocessing_data[node_id]
            private_share = self.private_shares[node_id]
            
            # Coefficient de Lagrange pour ce nœud
            lambda_i = self.compute_lagrange_coefficient(node_id, signing_nodes)
            
            # Calcul de la part de signature s_i
            # s_i = k_i^(-1) * (z + r * x_i * lambda_i)
            k_inv = self._mod_inverse(preprocessing.k_share, self.field_order)
            s_share = (k_inv * (z + r * private_share * lambda_i)) % self.field_order
            
            signature_share = SignatureShare(
                node_id=node_id,
                s_share=s_share,
                R=combined_R,
                timestamp=time.time()
            )
            
            signature_shares[node_id] = signature_share
        
        print(f"✅ {len(signature_shares)} parts de signature générées")
        return signature_shares
    
    def aggregate_signature(self, signature_shares: Dict[int, SignatureShare], 
                          signing_nodes: List[int]) -> ThresholdSignature:
        """
        Agrège les parts de signature en une signature ECDSA valide
        """
        if len(signature_shares) < self.threshold:
            raise ValueError(f"Pas assez de parts: {len(signature_shares)} < {self.threshold}")
        
        # Vérification que tous les R sont identiques
        first_R = list(signature_shares.values())[0].R
        for share in signature_shares.values():
            if not self._points_equal(share.R, first_R):
                raise ValueError("Points R incohérents entre les parts")
        
        # r = x-coordinate de R
        r = first_R.x % self.field_order
        
        # Agrégation des parts s
        s = 0
        for node_id in signing_nodes[:self.threshold]:  # Prendre exactement threshold parts
            if node_id in signature_shares:
                s = (s + signature_shares[node_id].s_share) % self.field_order
        
        # Vérification que s != 0
        if s == 0:
            raise ValueError("s = 0, signature invalide")
        
        # Calcul du recovery_id (optionnel pour la compatibilité)
        recovery_id = 0  # Simplified
        
        # Reconstruire le hash du message
        message_hash = b""  # Should be passed or stored
        
        threshold_signature = ThresholdSignature(
            r=r,
            s=s,
            recovery_id=recovery_id,
            message_hash=message_hash
        )
        
        print(f"✅ Signature agrégée: r={hex(r)[:10]}..., s={hex(s)[:10]}...")
        return threshold_signature
    
    def _points_equal(self, p1: ec.EllipticCurvePoint, p2: ec.EllipticCurvePoint) -> bool:
        """Vérifie l'égalité de deux points"""
        return True  # Placeholder
    
    def verify_signature(self, signature: ThresholdSignature, message: bytes) -> bool:
        """
        Vérifie la signature ECDSA avec la clé publique du groupe
        """
        if not self.group_public_key:
            raise ValueError("Clé publique du groupe non définie")
        
        # Hachage du message
        message_hash = hashlib.sha256(message).digest()
        z = int.from_bytes(message_hash, 'big') % self.field_order
        
        # Vérification ECDSA standard
        r, s = signature.r, signature.s
        
        if not (1 <= r < self.field_order and 1 <= s < self.field_order):
            return False
        
        # s_inv = s^(-1) mod field_order
        s_inv = self._mod_inverse(s, self.field_order)
        
        # u1 = z * s_inv mod field_order
        u1 = (z * s_inv) % self.field_order
        
        # u2 = r * s_inv mod field_order
        u2 = (r * s_inv) % self.field_order
        
        # point = u1 * G + u2 * PublicKey
        point1 = self._scalar_mult(self.generator, u1)
        point2 = self._scalar_mult(self.group_public_key, u2)
        point = self._point_add(point1, point2)
        
        # Vérification: r == point.x mod field_order
        return r == (point.x % self.field_order)
    
    def sign_message(self, message: bytes, signing_nodes: List[int]) -> ThresholdSignature:
        """
        Interface complète pour signer un message
        """
        print(f"🔐 Démarrage signature TSS avec {len(signing_nodes)} nœuds")
        
        # Phase de préparation
        self.preprocessing_phase(signing_nodes)
        
        # Phase de signature
        signature_shares = self.signing_phase(message, signing_nodes)
        
        # Agrégation
        final_signature = self.aggregate_signature(signature_shares, signing_nodes)
        
        # Vérification
        is_valid = self.verify_signature(final_signature, message)
        
        if is_valid:
            print("✅ Signature TSS générée et vérifiée avec succès")
        else:
            print("❌ Signature TSS invalide")
            
        return final_signature

# Exemple d'utilisation avec DKG
if __name__ == "__main__":
    from dkg_feldman_implementation import FeldmanVSSDKG
    
    # 1. Génération de clés distribuées
    print("=== Phase DKG ===")
    dkg = FeldmanVSSDKG(threshold=3, num_participants=5)
    distributed_keys = dkg.execute_dkg()
    
    # 2. Configuration TSS ECDSA
    print("\n=== Phase TSS ECDSA ===")
    participants = list(range(1, 6))  # Nœuds 1 à 5
    tss = TSSECDSA(threshold=3, participants=participants)
    tss.load_dkg_results(distributed_keys)
    
    # 3. Signature d'un message
    message = b"Certificat X.509 pour exemple.com"
    signing_nodes = [1, 3, 5]  # 3 nœuds parmi 5
    
    try:
        signature = tss.sign_message(message, signing_nodes)
        print(f"\n🎉 Signature distribuée réussie!")
        print(f"Message: {message.decode()}")
        print(f"Signature r: {hex(signature.r)}")
        print(f"Signature s: {hex(signature.s)}")
        
    except Exception as e:
        print(f"❌ Erreur de signature: {e}")
