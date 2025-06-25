"""
Implémentation du protocole PBFT (Practical Byzantine Fault Tolerance)
pour la coordination des nœuds MPC dans l'architecture PKI-MPC-ZKP
"""

import json
import time
import hashlib
import threading
from typing import Dict, List, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
import socket
import asyncio
from collections import defaultdict

class MessageType(Enum):
    """Types de messages PBFT"""
    PRE_PREPARE = "pre_prepare"
    PREPARE = "prepare"
    COMMIT = "commit"
    VIEW_CHANGE = "view_change"
    NEW_VIEW = "new_view"
    CHECKPOINT = "checkpoint"

class NodeState(Enum):
    """États possibles d'un nœud PBFT"""
    NORMAL = "normal"
    VIEW_CHANGE = "view_change"
    PREPARING = "preparing"
    COMMITTING = "committing"
    FAULTY = "faulty"

@dataclass
class PBFTMessage:
    """Message PBFT standard"""
    msg_type: MessageType
    view: int
    sequence: int
    digest: str
    node_id: int
    timestamp: float
    payload: Dict = field(default_factory=dict)
    signature: Optional[str] = None

@dataclass
class ClientRequest:
    """Requête client à traiter par consensus"""
    client_id: str
    operation: str
    timestamp: float
    params: Dict = field(default_factory=dict)
    
    def digest(self) -> str:
        """Calcule le digest de la requête"""
        content = f"{self.client_id}:{self.operation}:{self.timestamp}:{json.dumps(self.params, sort_keys=True)}"
        return hashlib.sha256(content.encode()).hexdigest()

@dataclass
class ConsensusLog:
    """Log des décisions de consensus"""
    sequence: int
    request: ClientRequest
    view: int
    committed: bool = False
    prepare_votes: Set[int] = field(default_factory=set)
    commit_votes: Set[int] = field(default_factory=set)

class PBFTNode:
    """
    Nœud PBFT pour le consensus distribué
    Adapté pour les opérations MPC
    """
    
    def __init__(self, node_id: int, total_nodes: int, f: int = None):
        self.node_id = node_id
        self.total_nodes = total_nodes
        self.f = f if f is not None else (total_nodes - 1) // 3  # Tolérance byzantine
        
        # État du consensus
        self.view = 0
        self.sequence = 0
        self.state = NodeState.NORMAL
        
        # Log et stockage
        self.log: Dict[int, ConsensusLog] = {}
        self.pending_requests: List[ClientRequest] = []
        self.executed_requests: Set[str] = set()
        
        # Messages reçus
        self.prepare_messages: Dict[int, Dict[int, PBFTMessage]] = defaultdict(dict)
        self.commit_messages: Dict[int, Dict[int, PBFTMessage]] = defaultdict(dict)
        self.view_change_messages: Dict[int, Dict[int, PBFTMessage]] = defaultdict(dict)
        
        # Timers
        self.last_checkpoint = 0
        self.checkpoint_interval = 100
        self.view_change_timeout = 5.0
        self.view_change_timer: Optional[asyncio.Task] = None
        
        # Callbacks pour intégration MPC
        self.on_request_executed: Optional[Callable] = None
        self.on_view_change: Optional[Callable] = None
        
        # Réseau (simulation)
        self.network_delay = 0.1  # 100ms de latence réseau simulée
        self.message_handlers = {
            MessageType.PRE_PREPARE: self._handle_pre_prepare,
            MessageType.PREPARE: self._handle_prepare,
            MessageType.COMMIT: self._handle_commit,
            MessageType.VIEW_CHANGE: self._handle_view_change,
            MessageType.NEW_VIEW: self._handle_new_view
        }
        
        print(f"🟢 Nœud PBFT {node_id} initialisé (tolérance: {self.f} nœuds)")
    
    def is_primary(self, view: int = None) -> bool:
        """Détermine si ce nœud est le primaire pour la vue donnée"""
        current_view = view if view is not None else self.view
        return (current_view % self.total_nodes) == self.node_id
    
    def get_primary(self, view: int = None) -> int:
        """Retourne l'ID du nœud primaire pour la vue"""
        current_view = view if view is not None else self.view
        return current_view % self.total_nodes
    
    async def submit_request(self, request: ClientRequest) -> bool:
        """
        Soumet une nouvelle requête au consensus
        Utilisé pour les opérations MPC (signature, DKG, etc.)
        """
        print(f"📝 Nœud {self.node_id}: Nouvelle requête {request.operation}")
        
        # Vérification des doublons
        if request.digest() in self.executed_requests:
            print(f"⚠️  Requête déjà exécutée: {request.digest()[:8]}...")
            return False
        
        self.pending_requests.append(request)
        
        # Si ce nœud est le primaire, démarrer le consensus
        if self.is_primary():
            await self._start_consensus(request)
        
        return True
    
    async def _start_consensus(self, request: ClientRequest):
        """Démarre le processus de consensus (nœud primaire)"""
        self.sequence += 1
        seq = self.sequence
        
        print(f"🔄 Primaire {self.node_id}: Démarrage consensus seq={seq}")
        
        # Création de l'entrée de log
        log_entry = ConsensusLog(
            sequence=seq,
            request=request,
            view=self.view
        )
        self.log[seq] = log_entry
        
        # Envoi du PRE-PREPARE
        pre_prepare_msg = PBFTMessage(
            msg_type=MessageType.PRE_PREPARE,
            view=self.view,
            sequence=seq,
            digest=request.digest(),
            node_id=self.node_id,
            timestamp=time.time(),
            payload={"request": request.__dict__}
        )
        
        await self._broadcast_message(pre_prepare_msg)
    
    async def _handle_pre_prepare(self, msg: PBFTMessage):
        """Traite un message PRE-PREPARE"""
        print(f"📨 Nœud {self.node_id}: PRE-PREPARE reçu seq={msg.sequence} de {msg.node_id}")
        
        # Vérifications de base
        if msg.view != self.view:
            print(f"⚠️  Vue incorrecte: {msg.view} != {self.view}")
            return
        
        if not self._verify_primary(msg.node_id, msg.view):
            print(f"⚠️  Nœud {msg.node_id} n'est pas le primaire")
            return
        
        if msg.sequence in self.log:
            print(f"⚠️  Séquence {msg.sequence} déjà dans le log")
            return
        
        # Reconstruction de la requête
        request_data = msg.payload.get("request", {})
        request = ClientRequest(**request_data)
        
        # Vérification du digest
        if msg.digest != request.digest():
            print(f"⚠️  Digest incorrect")
            return
        
        # Ajout au log
        log_entry = ConsensusLog(
            sequence=msg.sequence,
            request=request,
            view=msg.view
        )
        self.log[msg.sequence] = log_entry
        
        # Envoi du PREPARE
        prepare_msg = PBFTMessage(
            msg_type=MessageType.PREPARE,
            view=self.view,
            sequence=msg.sequence,
            digest=msg.digest,
            node_id=self.node_id,
            timestamp=time.time()
        )
        
        await self._broadcast_message(prepare_msg)
    
    async def _handle_prepare(self, msg: PBFTMessage):
        """Traite un message PREPARE"""
        print(f"📨 Nœud {self.node_id}: PREPARE reçu seq={msg.sequence} de {msg.node_id}")
        
        if msg.view != self.view or msg.sequence not in self.log:
            return
        
        # Stockage du vote PREPARE
        self.prepare_messages[msg.sequence][msg.node_id] = msg
        log_entry = self.log[msg.sequence]
        log_entry.prepare_votes.add(msg.node_id)
        
        # Vérification si on a assez de votes PREPARE (2f+1)
        if len(log_entry.prepare_votes) >= 2 * self.f + 1 and not log_entry.committed:
            print(f"✅ Nœud {self.node_id}: Seuil PREPARE atteint pour seq={msg.sequence}")
            
            # Envoi du COMMIT
            commit_msg = PBFTMessage(
                msg_type=MessageType.COMMIT,
                view=self.view,
                sequence=msg.sequence,
                digest=msg.digest,
                node_id=self.node_id,
                timestamp=time.time()
            )
            
            await self._broadcast_message(commit_msg)
    
    async def _handle_commit(self, msg: PBFTMessage):
        """Traite un message COMMIT"""
        print(f"📨 Nœud {self.node_id}: COMMIT reçu seq={msg.sequence} de {msg.node_id}")
        
        if msg.view != self.view or msg.sequence not in self.log:
            return
        
        # Stockage du vote COMMIT
        self.commit_messages[msg.sequence][msg.node_id] = msg
        log_entry = self.log[msg.sequence]
        log_entry.commit_votes.add(msg.node_id)
        
        # Vérification si on a assez de votes COMMIT (2f+1)
        if len(log_entry.commit_votes) >= 2 * self.f + 1 and not log_entry.committed:
            print(f"🎉 Nœud {self.node_id}: Consensus atteint pour seq={msg.sequence}")
            
            # Exécution de la requête
            await self._execute_request(log_entry)
    
    async def _execute_request(self, log_entry: ConsensusLog):
        """Exécute une requête une fois le consensus atteint"""
        log_entry.committed = True
        request = log_entry.request
        
        print(f"⚡ Nœud {self.node_id}: Exécution {request.operation}")
        
        # Marquer comme exécuté
        self.executed_requests.add(request.digest())
        
        # Callback pour intégration MPC
        if self.on_request_executed:
            try:
                await self.on_request_executed(request, log_entry.sequence)
            except Exception as e:
                print(f"❌ Erreur callback: {e}")
        
        # Checkpoint périodique
        if log_entry.sequence % self.checkpoint_interval == 0:
            await self._create_checkpoint(log_entry.sequence)
    
    async def _create_checkpoint(self, sequence: int):
        """Crée un point de contrôle"""
        print(f"📍 Nœud {self.node_id}: Checkpoint seq={sequence}")
        self.last_checkpoint = sequence
        
        # Nettoyage des anciens messages
        old_sequences = [seq for seq in self.log.keys() if seq <= sequence - self.checkpoint_interval]
        for seq in old_sequences:
            if seq in self.log and self.log[seq].committed:
                del self.log[seq]
                self.prepare_messages.pop(seq, None)
                self.commit_messages.pop(seq, None)
    
    def _verify_primary(self, node_id: int, view: int) -> bool:
        """Vérifie qu'un nœud est bien le primaire pour une vue"""
        return (view % self.total_nodes) == node_id
    
    async def _start_view_change(self):
        """Démarre un changement de vue (en cas de timeout)"""
        print(f"🔄 Nœud {self.node_id}: Changement de vue {self.view} -> {self.view + 1}")
        
        self.state = NodeState.VIEW_CHANGE
        self.view += 1
        
        # Message VIEW-CHANGE
        view_change_msg = PBFTMessage(
            msg_type=MessageType.VIEW_CHANGE,
            view=self.view,
            sequence=self.sequence,
            digest="",
            node_id=self.node_id,
            timestamp=time.time(),
            payload={
                "last_checkpoint": self.last_checkpoint,
                "log_entries": [entry.__dict__ for entry in self.log.values()]
            }
        )
        
        await self._broadcast_message(view_change_msg)
        
        # Callback pour changement de vue
        if self.on_view_change:
            await self.on_view_change(self.view)
    
    async def _handle_view_change(self, msg: PBFTMessage):
        """Traite un message VIEW-CHANGE"""
        print(f"📨 Nœud {self.node_id}: VIEW-CHANGE reçu pour vue {msg.view} de {msg.node_id}")
        
        self.view_change_messages[msg.view][msg.node_id] = msg
        
        # Si on a 2f+1 messages VIEW-CHANGE et qu'on est le nouveau primaire
        if (len(self.view_change_messages[msg.view]) >= 2 * self.f + 1 and 
            self.is_primary(msg.view)):
            
            await self._send_new_view(msg.view)
    
    async def _send_new_view(self, view: int):
        """Envoie NEW-VIEW en tant que nouveau primaire"""
        print(f"👑 Nœud {self.node_id}: Nouveau primaire pour vue {view}")
        
        new_view_msg = PBFTMessage(
            msg_type=MessageType.NEW_VIEW,
            view=view,
            sequence=0,
            digest="",
            node_id=self.node_id,
            timestamp=time.time(),
            payload={
                "view_change_messages": {
                    k: v.__dict__ for k, v in self.view_change_messages[view].items()
                }
            }
        )
        
        await self._broadcast_message(new_view_msg)
        self.state = NodeState.NORMAL
    
    async def _handle_new_view(self, msg: PBFTMessage):
        """Traite un message NEW-VIEW"""
        print(f"📨 Nœud {self.node_id}: NEW-VIEW reçu pour vue {msg.view}")
        
        if self._verify_primary(msg.node_id, msg.view):
            self.view = msg.view
            self.state = NodeState.NORMAL
            print(f"✅ Nœud {self.node_id}: Vue mise à jour vers {self.view}")
    
    async def _broadcast_message(self, message: PBFTMessage):
        """Diffuse un message à tous les autres nœuds"""
        # Simulation de l'envoi réseau
        await asyncio.sleep(self.network_delay)
        
        # Auto-traitement (simulation)
        if hasattr(self, '_network_handler'):
            await self._network_handler(message)
    
    def set_network_handler(self, handler: Callable):
        """Configure le gestionnaire réseau pour la simulation"""
        self._network_handler = handler
    
    async def process_message(self, message: PBFTMessage):
        """Traite un message reçu du réseau"""
        if message.node_id == self.node_id:
            return  # Ignorer ses propres messages
        
        handler = self.message_handlers.get(message.msg_type)
        if handler:
            await handler(message)
    
    def get_status(self) -> Dict:
        """Retourne le statut actuel du nœud"""
        return {
            "node_id": self.node_id,
            "view": self.view,
            "sequence": self.sequence,
            "state": self.state.value,
            "log_size": len(self.log),
            "executed_requests": len(self.executed_requests),
            "is_primary": self.is_primary()
        }

# Classe utilitaire pour simuler un réseau PBFT
class PBFTNetwork:
    """Simulation d'un réseau de nœuds PBFT"""
    
    def __init__(self, num_nodes: int):
        self.num_nodes = num_nodes
        self.nodes: Dict[int, PBFTNode] = {}
        self.message_queue: asyncio.Queue = asyncio.Queue()
        
        # Création des nœuds
        for i in range(num_nodes):
            node = PBFTNode(i, num_nodes)
            node.set_network_handler(self._handle_network_message)
            self.nodes[i] = node
        
        print(f"🌐 Réseau PBFT créé avec {num_nodes} nœuds")
    
    async def _handle_network_message(self, message: PBFTMessage):
        """Gère la diffusion des messages dans le réseau"""
        # Diffusion à tous les autres nœuds
        for node_id, node in self.nodes.items():
            if node_id != message.node_id:
                await node.process_message(message)
    
    async def submit_to_primary(self, request: ClientRequest) -> bool:
        """Soumet une requête au nœud primaire"""
        primary_id = 0  # Vue 0 = nœud 0 primaire
        primary_node = self.nodes[primary_id]
        return await primary_node.submit_request(request)
    
    def get_network_status(self) -> Dict:
        """Retourne le statut de tous les nœuds"""
        return {
            node_id: node.get_status() 
            for node_id, node in self.nodes.items()
        }

# Exemple d'utilisation pour les opérations MPC
if __name__ == "__main__":
    async def test_pbft_mpc():
        # Création d'un réseau de 4 nœuds (tolérance f=1)
        network = PBFTNetwork(4)
        
        # Configuration des callbacks MPC
        async def mpc_operation_callback(request: ClientRequest, sequence: int):
            print(f"🔐 Opération MPC exécutée: {request.operation} (seq={sequence})")
            
            if request.operation == "tss_signature":
                print(f"   📝 Signature TSS pour: {request.params.get('message', 'N/A')}")
            elif request.operation == "dkg_key_generation":
                print(f"   🔑 Génération de clé distribuée")
            elif request.operation == "key_refresh":
                print(f"   🔄 Rafraîchissement de clé")
        
        # Configuration des callbacks pour tous les nœuds
        for node in network.nodes.values():
            node.on_request_executed = mpc_operation_callback
        
        # Test de différentes opérations MPC
        requests = [
            ClientRequest(
                client_id="ca_authority",
                operation="tss_signature",
                timestamp=time.time(),
                params={"message": "certificat_client_001.pem", "algorithm": "ECDSA"}
            ),
            ClientRequest(
                client_id="admin",
                operation="dkg_key_generation",
                timestamp=time.time(),
                params={"threshold": 3, "participants": 4, "key_type": "secp256k1"}
            ),
            ClientRequest(
                client_id="ca_authority",
                operation="tss_signature",
                timestamp=time.time(),
                params={"message": "crl_update_2024.pem", "algorithm": "ECDSA"}
            )
        ]
        
        print("🚀 Test du consensus PBFT pour opérations MPC")
        
        # Soumission des requêtes
        for i, request in enumerate(requests):
            print(f"\n--- Requête {i+1} ---")
            success = await network.submit_to_primary(request)
            print(f"Soumission: {'✅' if success else '❌'}")
            
            # Attendre un peu pour voir le consensus
            await asyncio.sleep(1.0)
        
        # Statut final
        await asyncio.sleep(2.0)
        print("\n📊 Statut final du réseau:")
        status = network.get_network_status()
        for node_id, node_status in status.items():
            print(f"  Nœud {node_id}: Vue={node_status['view']}, "
                  f"Log={node_status['log_size']}, "
                  f"Exécutées={node_status['executed_requests']}, "
                  f"Primaire={'✅' if node_status['is_primary'] else '❌'}")
    
    # Exécution du test
    asyncio.run(test_pbft_mpc())
