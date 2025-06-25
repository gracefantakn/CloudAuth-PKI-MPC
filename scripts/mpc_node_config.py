"""
Configuration et gestion d'un nœud MPC sans HSM physique
Simulation sécurisée des opérations cryptographiques distribuées
"""

import asyncio
import json
import time
import secrets
import hashlib
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import threading
from collections import defaultdict
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

class MPCNodeState(Enum):
    """États possibles d'un nœud MPC"""
    INITIALIZING = "initializing"
    READY = "ready"
    PARTICIPATING = "participating"
    RECOVERING = "recovering"
    OFFLINE = "offline"
    COMPROMISED = "compromised"

class OperationType(Enum):
    """Types d'opérations MPC supportées"""
    DKG = "distributed_key_generation"
    TSS_SIGNING = "threshold_signature_scheme"
    KEY_REFRESH = "key_refresh"
    PARTIAL_VERIFY = "partial_verification"
    EMERGENCY_RECOVERY = "emergency_recovery"

@dataclass
class SecretShare:
    """Part de secret sécurisée"""
    share_id: str
    participant_id: int
    share_value: bytes  # Chiffré
    metadata: Dict[str, Any]
    created_at: float
    last_used: float = 0.0
    use_count: int = 0
    
@dataclass
class MPCOperation:
    """Opération MPC en cours"""
    operation_id: str
    operation_type: OperationType
    participants: Set[int]
    threshold: int
    status: str
    created_at: float
    timeout: float
    parameters: Dict[str, Any] = field(default_factory=dict)
    contributions: Dict[int, Any] = field(default_factory=dict)
    result: Optional[Any] = None

@dataclass
class NodeSecurityConfig:
    """Configuration de sécurité du nœud"""
    encryption_key: bytes
    hmac_key: bytes
    node_identity: bytes
    attestation_enabled: bool = True
    auto_key_rotation: bool = True
    key_rotation_interval: int = 86400  # 24h
    max_operations_per_hour: int = 1000
    secure_deletion_passes: int = 3

class MPCSecureStorage:
    """
    Stockage sécurisé simulé pour les parts de clés
    Remplace le HSM physique avec chiffrement logiciel
    """
    
    def __init__(self, node_id: int):
        self.node_id = node_id
        self.storage_key = self._derive_storage_key()
        self.shares: Dict[str, SecretShare] = {}
        self.access_log: List[Dict] = []
        self.integrity_hashes: Dict[str, str] = {}
        
    def _derive_storage_key(self) -> bytes:
        """Dérive une clé de stockage unique par nœud"""
        # En production, utiliser un KDF avec salt unique
        seed = f"mpc_node_{self.node_id}_storage_key".encode()
        return hashlib.pbkdf2_hmac('sha256', seed, b'salt_demo', 100000)
    
    def store_share(self, share: SecretShare) -> bool:
        """Stocke une part de secret de manière sécurisée"""
        try:
            # Chiffrement de la part
            encrypted_share = self._encrypt_share_value(share.share_value)
            
            # Création de la copie chiffrée
            encrypted_share_obj = SecretShare(
                share_id=share.share_id,
                participant_id=share.participant_id,
                share_value=encrypted_share,
                metadata=share.metadata,
                created_at=share.created_at
            )
            
            # Calcul du hash d'intégrité
            integrity_data = f"{share.share_id}:{encrypted_share.hex()}:{share.created_at}"
            integrity_hash = hashlib.sha256(integrity_data.encode()).hexdigest()
            
            # Stockage
            self.shares[share.share_id] = encrypted_share_obj
            self.integrity_hashes[share.share_id] = integrity_hash
            
            # Log d'accès
            self._log_access("STORE", share.share_id, True)
            
            print(f"🔒 Part stockée: {share.share_id} (Nœud {self.node_id})")
            return True
            
        except Exception as e:
            self._log_access("STORE", share.share_id, False, str(e))
            print(f"❌ Erreur stockage part: {e}")
            return False
    
    def retrieve_share(self, share_id: str) -> Optional[SecretShare]:
        """Récupère et déchiffre une part de secret"""
        try:
            if share_id not in self.shares:
                self._log_access("RETRIEVE", share_id, False, "Share not found")
                return None
            
            # Vérification d'intégrité
            if not self._verify_integrity(share_id):
                self._log_access("RETRIEVE", share_id, False, "Integrity check failed")
                return None
            
            encrypted_share = self.shares[share_id]
            
            # Déchiffrement
            decrypted_value = self._decrypt_share_value(encrypted_share.share_value)
            
            # Reconstruction de la part déchiffrée
            decrypted_share = SecretShare(
                share_id=encrypted_share.share_id,
                participant_id=encrypted_share.participant_id,
                share_value=decrypted_value,
                metadata=encrypted_share.metadata,
                created_at=encrypted_share.created_at,
                last_used=time.time(),
                use_count=encrypted_share.use_count + 1
            )
            
            # Mise à jour des métadonnées
            encrypted_share.last_used = decrypted_share.last_used
            encrypted_share.use_count = decrypted_share.use_count
            
            self._log_access("RETRIEVE", share_id, True)
            
            return decrypted_share
            
        except Exception as e:
            self._log_access("RETRIEVE", share_id, False, str(e))
            print(f"❌ Erreur récupération part: {e}")
            return None
    
    def _encrypt_share_value(self, share_value: bytes) -> bytes:
        """Chiffre une valeur de part"""
        # AES-256-GCM
        iv = secrets.token_bytes(12)  # 96 bits pour GCM
        cipher = Cipher(algorithms.AES(self.storage_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(share_value) + encryptor.finalize()
        
        # Concaténation: IV + Tag + Ciphertext
        return iv + encryptor.tag + ciphertext
    
    def _decrypt_share_value(self, encrypted_data: bytes) -> bytes:
        """Déchiffre une valeur de part"""
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        cipher = Cipher(algorithms.AES(self.storage_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _verify_integrity(self, share_id: str) -> bool:
        """Vérifie l'intégrité d'une part stockée"""
        if share_id not in self.integrity_hashes:
            return False
        
        share = self.shares[share_id]
        integrity_data = f"{share.share_id}:{share.share_value.hex()}:{share.created_at}"
        computed_hash = hashlib.sha256(integrity_data.encode()).hexdigest()
        
        return computed_hash == self.integrity_hashes[share_id]
    
    def _log_access(self, operation: str, share_id: str, success: bool, error: str = None):
        """Enregistre un accès aux parts"""
        log_entry = {
            "timestamp": time.time(),
            "operation": operation,
            "share_id": share_id,
            "success": success,
            "error": error,
            "node_id": self.node_id
        }
        self.access_log.append(log_entry)
        
        # Limitation de la taille du log
        if len(self.access_log) > 1000:
            self.access_log = self.access_log[-500:]
    
    def secure_delete_share(self, share_id: str) -> bool:
        """Suppression sécurisée d'une part"""
        if share_id not in self.shares:
            return False
        
        try:
            # Écrasement sécurisé (simulation)
            share = self.shares[share_id]
            for _ in range(3):  # 3 passes d'écrasement
                share.share_value = secrets.token_bytes(len(share.share_value))
            
            # Suppression définitive
            del self.shares[share_id]
            del self.integrity_hashes[share_id]
            
            self._log_access("DELETE", share_id, True)
            print(f"🗑️  Part supprimée de manière sécurisée: {share_id}")
            
            return True
            
        except Exception as e:
            self._log_access("DELETE", share_id, False, str(e))
            return False

class MPCNode:
    """
    Nœud MPC avec simulation de sécurité matérielle
    Remplace les fonctionnalités HSM par des implémentations logicielles sécurisées
    """
    
    def __init__(self, node_id: int, total_nodes: int, threshold: int):
        self.node_id = node_id
        self.total_nodes = total_nodes
        self.threshold = threshold
        self.state = MPCNodeState.INITIALIZING
        
        # Configuration de sécurité
        self.security_config = self._initialize_security_config()
        
        # Stockage sécurisé
        self.secure_storage = MPCSecureStorage(node_id)
        
        # Opérations en cours
        self.active_operations: Dict[str, MPCOperation] = {}
        self.operation_history: List[str] = []
        
        # Interfaces réseau et consensus
        self.network_interface: Optional[Any] = None
        self.consensus_interface: Optional[Any] = None
        self.zkp_interface: Optional[Any] = None
        
        # Métriques et monitoring
        self.metrics = {
            "operations_completed": 0,
            "operations_failed": 0,
            "signatures_generated": 0,
            "keys_generated": 0,
            "uptime_start": time.time(),
            "last_heartbeat": time.time()
        }
        
        # Sécurité opérationnelle
        self.rate_limiter = defaultdict(list)  # Anti-DoS
        self.trusted_peers: Set[int] = set(range(total_nodes)) - {node_id}
        self.session_keys: Dict[int, bytes] = {}
        
        print(f"🟢 Nœud MPC {node_id} initialisé (seuil: {threshold}/{total_nodes})")
    
    def _initialize_security_config(self) -> NodeSecurityConfig:
        """Initialise la configuration de sécurité"""
        # Génération de clés cryptographiques fortes
        encryption_key = secrets.token_bytes(32)  # AES-256
        hmac_key = secrets.token_bytes(32)        # HMAC-SHA256
        node_identity = hashlib.sha256(f"mpc_node_{self.node_id}".encode()).digest()
        
        return NodeSecurityConfig(
            encryption_key=encryption_key,
            hmac_key=hmac_key,
            node_identity=node_identity,
            attestation_enabled=True,
            auto_key_rotation=True
        )
    
    async def start_node(self):
        """Démarre le nœud MPC"""
        print(f"🚀 Démarrage nœud MPC {self.node_id}")
        
        self.state = MPCNodeState.READY
        
        # Démarrage des tâches de surveillance
        heartbeat_task = asyncio.create_task(self._heartbeat_routine())
        security_task = asyncio.create_task(self._security_monitoring())
        cleanup_task = asyncio.create_task(self._cleanup_routine())
        
        await asyncio.gather(heartbeat_task, security_task, cleanup_task)
    
    async def participate_in_dkg(self, operation_id: str, participants: List[int]) -> bool:
        """
        Participe à une génération de clé distribuée
        """
        if len(participants) < self.threshold:
            print(f"❌ Pas assez de participants pour DKG: {len(participants)} < {self.threshold}")
            return False
        
        if self.node_id not in participants:
            print(f"❌ Nœud {self.node_id} non inclus dans les participants DKG")
            return False
        
        print(f"🔑 Nœud {self.node_id}: Participation DKG {operation_id}")
        
        try:
            # Création de l'opération MPC
            operation = MPCOperation(
                operation_id=operation_id,
                operation_type=OperationType.DKG,
                participants=set(participants),
                threshold=self.threshold,
                status="in_progress",
                created_at=time.time(),
                timeout=300.0  # 5 minutes
            )
            
            self.active_operations[operation_id] = operation
            self.state = MPCNodeState.PARTICIPATING
            
            # Phase 1: Génération du polynôme secret local
            local_polynomial = self._generate_secret_polynomial()
            
            # Phase 2: Calcul des parts pour les autres participants
            shares_to_distribute = {}
            for participant_id in participants:
                if participant_id != self.node_id:
                    share_value = self._evaluate_polynomial(local_polynomial, participant_id)
                    shares_to_distribute[participant_id] = share_value
            
            # Phase 3: Distribution sécurisée des parts
            await self._distribute_shares_securely(operation_id, shares_to_distribute)
            
            # Phase 4: Collecte des parts des autres participants
            await self._collect_dkg_shares(operation_id, participants)
            
            # Phase 5: Validation et finalisation
            final_share = await self._finalize_dkg(operation_id, local_polynomial[0])
            
            if final_share:
                # Stockage sécurisé de la part finale
                share_obj = SecretShare(
                    share_id=f"dkg_{operation_id}_{self.node_id}",
                    participant_id=self.node_id,
                    share_value=final_share,
                    metadata={
                        "operation_id": operation_id,
                        "participants": list(participants),
                        "threshold": self.threshold,
                        "key_type": "secp256k1"
                    },
                    created_at=time.time()
                )
                
                success = self.secure_storage.store_share(share_obj)
                
                if success:
                    operation.status = "completed"
                    operation.result = {"share_id": share_obj.share_id}
                    self.metrics["keys_generated"] += 1
                    self.metrics["operations_completed"] += 1
                    
                    print(f"✅ DKG terminé: {operation_id}")
                    return True
            
            # Échec
            operation.status = "failed"
            self.metrics["operations_failed"] += 1
            return False
            
        except Exception as e:
            print(f"❌ Erreur DKG: {e}")
            if operation_id in self.active_operations:
                self.active_operations[operation_id].status = "failed"
            self.metrics["operations_failed"] += 1
            return False
        
        finally:
            self.state = MPCNodeState.READY
            # Nettoyage des données temporaires
            await self._cleanup_operation_data(operation_id)
    
    def _generate_secret_polynomial(self) -> List[int]:
        """Génère un polynôme secret aléatoire"""
        field_order = 2**256 - 2**32 - 977  # Ordre du corps pour secp256k1
        
        polynomial = []
        for i in range(self.threshold):
            coeff = secrets.randbelow(field_order)
            polynomial.append(coeff)
        
        return polynomial
    
    def _evaluate_polynomial(self, polynomial: List[int], x: int) -> bytes:
        """Évalue le polynôme en x et retourne le résultat chiffré"""
        field_order = 2**256 - 2**32 - 977
        
        result = 0
        for i, coeff in enumerate(polynomial):
            result = (result + coeff * pow(x, i, field_order)) % field_order
        
        # Conversion en bytes sécurisés
        return result.to_bytes(32, 'big')
    
    async def _distribute_shares_securely(self, operation_id: str, shares: Dict[int, bytes]):
        """Distribue les parts de manière sécurisée aux autres nœuds"""
        # Simulation de la distribution chiffrée
        for participant_id, share_value in shares.items():
            # En production, chiffrement avec la clé publique du destinataire
            encrypted_share = self._encrypt_for_peer(share_value, participant_id)
            
            # Envoi via le réseau sécurisé
            await self._send_to_peer(participant_id, {
                "type": "dkg_share",
                "operation_id": operation_id,
                "from_node": self.node_id,
                "encrypted_share": encrypted_share.hex()
            })
    
    def _encrypt_for_peer(self, data: bytes, peer_id: int) -> bytes:
        """Chiffre des données pour un pair spécifique"""
        # Simulation du chiffrement asymétrique
        session_key = self.session_keys.get(peer_id, secrets.token_bytes(32))
        self.session_keys[peer_id] = session_key
        
        # AES-GCM avec la clé de session
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return iv + encryptor.tag + ciphertext
    
    async def _send_to_peer(self, peer_id: int, message: Dict):
        """Envoie un message à un pair"""
        # Simulation de l'envoi réseau
        if self.network_interface:
            await self.network_interface.send_message(peer_id, message)
        else:
            print(f"📤 {self.node_id} → {peer_id}: {message['type']}")
    
    async def _collect_dkg_shares(self, operation_id: str, participants: List[int]):
        """Collecte les parts DKG des autres participants"""
        # Simulation de la collecte
        await asyncio.sleep(1.0)  # Attente réseau simulée
        
        # En production, implémenter la logique de collecte réelle
        print(f"📥 Nœud {self.node_id}: Collecte des parts DKG pour {operation_id}")
    
    async def _finalize_dkg(self, operation_id: str, secret_term: int) -> Optional[bytes]:
        """Finalise la DKG et calcule la part finale"""
        # Simulation de la finalisation
        # En production, combiner toutes les parts reçues
        
        final_share_value = secret_term  # Simplification pour la démo
        return final_share_value.to_bytes(32, 'big')
    
    async def participate_in_signature(self, operation_id: str, message_hash: bytes, 
                                     share_id: str, participants: List[int]) -> Optional[Dict]:
        """
        Participe à une signature à seuil
        """
        if self.node_id not in participants:
            return None
        
        print(f"✍️  Nœud {self.node_id}: Signature TSS {operation_id}")
        
        try:
            # Récupération de la part de clé
            share = self.secure_storage.retrieve_share(share_id)
            if not share:
                print(f"❌ Part introuvable: {share_id}")
                return None
            
            # Création de l'opération
            operation = MPCOperation(
                operation_id=operation_id,
                operation_type=OperationType.TSS_SIGNING,
                participants=set(participants),
                threshold=self.threshold,
                status="in_progress",
                created_at=time.time(),
                timeout=60.0,
                parameters={"message_hash": message_hash.hex(), "share_id": share_id}
            )
            
            self.active_operations[operation_id] = operation
            self.state = MPCNodeState.PARTICIPATING
            
            # Génération de la contribution de signature
            signature_contribution = await self._generate_signature_contribution(
                share, message_hash, participants
            )
            
            if signature_contribution:
                # Génération ZKP de validité
                zkp_proof = await self._generate_contribution_proof(
                    signature_contribution, share_id
                )
                
                result = {
                    "node_id": self.node_id,
                    "contribution": signature_contribution,
                    "zkp_proof": zkp_proof,
                    "timestamp": time.time()
                }
                
                operation.status = "completed"
                operation.result = result
                self.metrics["signatures_generated"] += 1
                self.metrics["operations_completed"] += 1
                
                print(f"✅ Contribution signature générée: {operation_id}")
                return result
            
            return None
            
        except Exception as e:
            print(f"❌ Erreur signature TSS: {e}")
            if operation_id in self.active_operations:
                self.active_operations[operation_id].status = "failed"
            self.metrics["operations_failed"] += 1
            return None
        
        finally:
            self.state = MPCNodeState.READY
    
    async def _generate_signature_contribution(self, share: SecretShare, 
                                             message_hash: bytes, participants: List[int]) -> Optional[Dict]:
        """Génère la contribution de signature à seuil"""
        try:
            # Conversion de la part en entier
            share_value = int.from_bytes(share.share_value, 'big')
            message_int = int.from_bytes(message_hash, 'big')
            
            # Simulation de l'ECDSA à seuil
            # En production, utiliser un vrai protocole TSS
            
            # Génération du nonce local
            k_local = secrets.randbelow(2**256)
            
            # Calcul de la contribution (simplifié)
            r_contribution = pow(k_local, 1, 2**256 - 2**32 - 977)  # Point R partiel
            s_contribution = (k_local + message_int * share_value) % (2**256 - 2**32 - 977)
            
            return {
                "r_part": r_contribution,
                "s_part": s_contribution,
                "participant_id": self.node_id
            }
            
        except Exception as e:
            print(f"❌ Erreur génération contribution: {e}")
            return None
    
    async def _generate_contribution_proof(self, contribution: Dict, share_id: str) -> Optional[Dict]:
        """Génère une preuve ZKP de validité de la contribution"""
        if not self.zkp_interface:
            return {"proof_type": "simulated", "valid": True}
        
        try:
            # Simulation de la génération de preuve ZKP
            proof_data = {
                "proof_type": "contribution_validity",
                "node_id": self.node_id,
                "share_id": share_id,
                "contribution_hash": hashlib.sha256(
                    json.dumps(contribution, sort_keys=True).encode()
                ).hexdigest(),
                "timestamp": time.time()
            }
            
            return proof_data
            
        except Exception as e:
            print(f"❌ Erreur génération preuve ZKP: {e}")
            return None
    
    async def _heartbeat_routine(self):
        """Routine de heartbeat pour surveillance de santé"""
        while self.state != MPCNodeState.OFFLINE:
            try:
                self.metrics["last_heartbeat"] = time.time()
                
                # Vérification de la santé du nœud
                health_status = self._check_node_health()
                
                if not health_status["healthy"]:
                    print(f"⚠️  Nœud {self.node_id}: Problème de santé détecté")
                    if health_status["critical"]:
                        self.state = MPCNodeState.RECOVERING
                
                await asyncio.sleep(30)  # Heartbeat toutes les 30 secondes
                
            except Exception as e:
                print(f"❌ Erreur heartbeat: {e}")
                await asyncio.sleep(5)
    
    def _check_node_health(self) -> Dict[str, Any]:
        """Vérifie la santé du nœud"""
        # Vérifications de base
        memory_usage = len(self.active_operations)
        storage_health = len(self.secure_storage.shares) < 10000  # Limite arbitraire
        
        # Vérification des opérations qui traînent
        current_time = time.time()
        stuck_operations = [
            op for op in self.active_operations.values()
            if current_time - op.created_at > op.timeout
        ]
        
        healthy = memory_usage < 100 and storage_health and len(stuck_operations) == 0
        critical = memory_usage > 500 or len(stuck_operations) > 10
        
        return {
            "healthy": healthy,
            "critical": critical,
            "memory_usage": memory_usage,
            "storage_health": storage_health,
            "stuck_operations": len(stuck_operations)
        }
    
    async def _security_monitoring(self):
        """Surveillance de sécurité continue"""
        while self.state != MPCNodeState.OFFLINE:
            try:
                # Vérification de l'intégrité des parts stockées
                integrity_check = await self._verify_storage_integrity()
                
                # Détection d'activité suspecte
                suspicious_activity = self._detect_suspicious_activity()
                
                # Rotation automatique des clés de session
                if self.security_config.auto_key_rotation:
                    await self._rotate_session_keys()
                
                if not integrity_check or suspicious_activity:
                    print(f"🚨 Nœud {self.node_id}: Alerte de sécurité")
                    # En production, déclencher des mesures de sécurité
                
                await asyncio.sleep(300)  # Vérification toutes les 5 minutes
                
            except Exception as e:
                print(f"❌ Erreur surveillance sécurité: {e}")
                await asyncio.sleep(30)
    
    async def _verify_storage_integrity(self) -> bool:
        """Vérifie l'intégrité du stockage sécurisé"""
        try:
            # Vérification de quelques parts au hasard
            share_ids = list(self.secure_storage.shares.keys())
            if not share_ids:
                return True
            
            # Test sur 10% des parts ou minimum 1
            test_count = max(1, len(share_ids) // 10)
            test_shares = secrets.SystemRandom().sample(share_ids, min(test_count, len(share_ids)))
            
            for share_id in test_shares:
                if not self.secure_storage._verify_integrity(share_id):
                    print(f"❌ Intégrité compromise: {share_id}")
                    return False
            
            return True
            
        except Exception as e:
            print(f"❌ Erreur vérification intégrité: {e}")
            return False
    
    def _detect_suspicious_activity(self) -> bool:
        """Détecte une activité suspecte"""
        current_time = time.time()
        
        # Vérification du rate limiting
        for operation_type, timestamps in self.rate_limiter.items():
            # Nettoyage des anciens timestamps
            recent_timestamps = [t for t in timestamps if current_time - t < 3600]  # 1 heure
            self.rate_limiter[operation_type] = recent_timestamps
            
            # Détection de surcharge
            if len(recent_timestamps) > self.security_config.max_operations_per_hour:
                print(f"⚠️  Taux d'opérations suspect pour {operation_type}")
                return True
        
        return False
    
    async def _rotate_session_keys(self):
        """Rotation des clés de session"""
        try:
            # Rotation seulement si nécessaire
            current_time = time.time()
            last_rotation = getattr(self, '_last_key_rotation', 0)
            
            if current_time - last_rotation > self.security_config.key_rotation_interval:
                # Génération de nouvelles clés de session
                new_session_keys = {}
                for peer_id in self.trusted_peers:
                    new_session_keys[peer_id] = secrets.token_bytes(32)
                
                self.session_keys = new_session_keys
                self._last_key_rotation = current_time
                
                print(f"🔄 Nœud {self.node_id}: Rotation des clés de session")
                
        except Exception as e:
            print(f"❌ Erreur rotation clés: {e}")
    
    async def _cleanup_routine(self):
        """Routine de nettoyage périodique"""
        while self.state != MPCNodeState.OFFLINE:
            try:
                await asyncio.sleep(1800)  # Toutes les 30 minutes
                
                # Nettoyage des opérations terminées anciennes
                current_time = time.time()
                old_operations = [
                    op_id for op_id, op in self.active_operations.items()
                    if op.status in ["completed", "failed"] and current_time - op.created_at > 3600
                ]
                
                for op_id in old_operations:
                    await self._cleanup_operation_data(op_id)
                    del self.active_operations[op_id]
                
                # Limitation de l'historique
                if len(self.operation_history) > 1000:
                    self.operation_history = self.operation_history[-500:]
                
                print(f"🧹 Nœud {self.node_id}: Nettoyage - {len(old_operations)} opérations supprimées")
                
            except Exception as e:
                print(f"❌ Erreur nettoyage: {e}")
    
    async def _cleanup_operation_data(self, operation_id: str):
        """Nettoie les données temporaires d'une opération"""
        # Ajout à l'historique
        if operation_id not in self.operation_history:
            self.operation_history.append(operation_id)
        
        # Nettoyage sécurisé des données sensibles temporaires
        # En production, écrasement sécurisé de la mémoire
    
    def get_node_status(self) -> Dict[str, Any]:
        """Retourne le statut complet du nœud"""
        current_time = time.time()
        uptime = current_time - self.metrics["uptime_start"]
        
        return {
            "node_id": self.node_id,
            "state": self.state.value,
            "uptime_seconds": uptime,
            "metrics": self.metrics.copy(),
            "active_operations": len(self.active_operations),
            "stored_shares": len(self.secure_storage.shares),
            "trusted_peers": len(self.trusted_peers),
            "last_heartbeat": self.metrics["last_heartbeat"],
            "security_config": {
                "attestation_enabled": self.security_config.attestation_enabled,
                "auto_key_rotation": self.security_config.auto_key_rotation,
                "max_operations_per_hour": self.security_config.max_operations_per_hour
            }
        }

# Exemple d'utilisation
if __name__ == "__main__":
    async def test_mpc_node():
        # Création de 5 nœuds MPC
        nodes = []
        for i in range(5):
            node = MPCNode(i, total_nodes=5, threshold=3)
            nodes.append(node)
        
        print("🧪 Test des nœuds MPC")
        
        # Simulation d'une DKG
        participants = [0, 1, 2, 3]  # 4 participants
        operation_id = "dkg_test_001"
        
        try:
            # Démarrage simultané de la DKG sur tous les nœuds participants
            dkg_tasks = []
            for node in nodes[:4]:  # Seulement les 4 premiers
                task = asyncio.create_task(
                    node.participate_in_dkg(operation_id, participants)
                )
                dkg_tasks.append(task)
            
            # Attendre que tous terminent
            results = await asyncio.gather(*dkg_tasks, return_exceptions=True)
            
            successful_nodes = sum(1 for r in results if r is True)
            print(f"DKG réussie sur {successful_nodes}/{len(participants)} nœuds")
            
            # Affichage des statuts
            for i, node in enumerate(nodes[:4]):
                status = node.get_node_status()
                print(f"  Nœud {i}: {status['state']}, "
                      f"Parts: {status['stored_shares']}, "
                      f"Opérations: {status['metrics']['operations_completed']}")
                
        except Exception as e:
            print(f"❌ Erreur test: {e}")
    
    # Exécution du test
    asyncio.run(test_mpc_node())
