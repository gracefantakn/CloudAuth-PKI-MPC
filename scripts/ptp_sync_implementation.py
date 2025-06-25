"""
Implémentation de la synchronisation temporelle PTP (Precision Time Protocol)
pour assurer la cohérence temporelle entre les nœuds MPC
"""

import asyncio
import time
import socket
import struct
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import statistics
import json

class PTPMessageType(Enum):
    """Types de messages PTP"""
    SYNC = 0x00
    DELAY_REQ = 0x01
    PDELAY_REQ = 0x02
    PDELAY_RESP = 0x03
    FOLLOW_UP = 0x08
    DELAY_RESP = 0x09
    PDELAY_RESP_FOLLOW_UP = 0x0A
    ANNOUNCE = 0x0B
    SIGNALING = 0x0C
    MANAGEMENT = 0x0D

class ClockType(Enum):
    """Types d'horloge PTP"""
    ORDINARY_CLOCK = "ordinary"
    BOUNDARY_CLOCK = "boundary"
    TRANSPARENT_CLOCK = "transparent"
    GRANDMASTER = "grandmaster"

@dataclass
class PTPTimestamp:
    """Timestamp PTP haute précision"""
    seconds: int
    nanoseconds: int
    
    @classmethod
    def now(cls) -> 'PTPTimestamp':
        """Crée un timestamp PTP à partir de l'heure actuelle"""
        current = time.time_ns()
        seconds = current // 1_000_000_000
        nanoseconds = current % 1_000_000_000
        return cls(seconds, nanoseconds)
    
    def to_float(self) -> float:
        """Convertit en timestamp float"""
        return self.seconds + self.nanoseconds / 1_000_000_000
    
    def __sub__(self, other: 'PTPTimestamp') -> float:
        """Calcule la différence en secondes"""
        return self.to_float() - other.to_float()
    
    def __add__(self, offset: float) -> 'PTPTimestamp':
        """Ajoute un offset en secondes"""
        total_ns = self.seconds * 1_000_000_000 + self.nanoseconds + int(offset * 1_000_000_000)
        return PTPTimestamp(
            seconds=total_ns // 1_000_000_000,
            nanoseconds=total_ns % 1_000_000_000
        )

@dataclass
class PTPMessage:
    """Message PTP standard"""
    message_type: PTPMessageType
    version: int = 2
    domain: int = 0
    flags: int = 0
    correction: int = 0
    port_identity: bytes = b'\x00' * 10
    sequence_id: int = 0
    control: int = 0
    log_message_interval: int = 0
    origin_timestamp: Optional[PTPTimestamp] = None
    receive_timestamp: Optional[PTPTimestamp] = None
    
    def to_bytes(self) -> bytes:
        """Sérialise le message en bytes"""
        # Format simplifié pour la simulation
        header = struct.pack(
            '!BBHH8sHBB',
            (self.message_type.value << 4) | 0x2,  # Message type + version
            self.domain,
            0,  # Message length (à calculer)
            self.flags,
            self.correction.to_bytes(8, 'big'),
            0,  # Reserved
            self.port_identity[:8],
            self.sequence_id,
            self.control,
            self.log_message_interval
        )
        
        # Timestamps
        if self.origin_timestamp:
            timestamp_data = struct.pack(
                '!QI',
                self.origin_timestamp.seconds,
                self.origin_timestamp.nanoseconds
            )
            header += timestamp_data
        
        return header

@dataclass
class ClockProperties:
    """Propriétés d'une horloge PTP"""
    clock_id: bytes
    priority1: int = 128
    priority2: int = 128
    clock_quality: int = 0xFE
    accuracy: int = 0xFE
    variance: int = 0xFFFF
    steps_removed: int = 0
    time_source: int = 0xA0

@dataclass
class SyncMeasurement:
    """Mesure de synchronisation"""
    master_to_slave_delay: float
    slave_to_master_delay: float
    offset: float
    timestamp: float
    
class PTPClock:
    """
    Implémentation d'une horloge PTP pour synchronisation des nœuds MPC
    """
    
    def __init__(self, node_id: int, clock_type: ClockType = ClockType.ORDINARY_CLOCK):
        self.node_id = node_id
        self.clock_type = clock_type
        self.clock_id = f"MPC-{node_id:04d}".encode('ascii').ljust(8, b'\x00')
        
        # État de l'horloge
        self.properties = ClockProperties(clock_id=self.clock_id)
        self.local_offset = 0.0  # Offset par rapport au maître
        self.is_grandmaster = (clock_type == ClockType.GRANDMASTER)
        self.master_clock_id: Optional[bytes] = None
        
        # Configuration PTP
        self.domain = 0
        self.sync_interval = 1.0  # 1 seconde
        self.announce_interval = 2.0  # 2 secondes
        self.sequence_id = 0
        
        # Mesures de synchronisation
        self.sync_measurements: List[SyncMeasurement] = []
        self.max_measurements = 10
        
        # Network simulation
        self.network_delay = 0.001  # 1ms de délai réseau simulé
        self.clock_drift = 0.0  # Dérive d'horloge (ppm)
        
        # État du protocole
        self.is_synchronized = False
        self.sync_accuracy = float('inf')
        self.last_sync_time = 0.0
        
        # Callbacks
        self.on_sync_update: Optional[callable] = None
        self.on_time_jump: Optional[callable] = None
        
        print(f"🕒 Horloge PTP {node_id} initialisée ({clock_type.value})")
    
    def get_time(self) -> PTPTimestamp:
        """
        Retourne l'heure locale corrigée par l'offset PTP
        """
        local_time = time.time() + self.local_offset
        
        # Application de la dérive d'horloge
        if self.clock_drift != 0:
            elapsed = time.time() - self.last_sync_time
            drift_offset = elapsed * self.clock_drift / 1_000_000  # ppm to seconds
            local_time += drift_offset
        
        ns_total = int(local_time * 1_000_000_000)
        return PTPTimestamp(
            seconds=ns_total // 1_000_000_000,
            nanoseconds=ns_total % 1_000_000_000
        )
    
    def set_time(self, timestamp: PTPTimestamp):
        """
        Ajuste l'heure locale
        """
        current_time = time.time()
        target_time = timestamp.to_float()
        
        old_offset = self.local_offset
        self.local_offset = target_time - current_time
        
        # Détection de saut temporel significatif
        time_jump = abs(self.local_offset - old_offset)
        if time_jump > 0.1:  # Saut > 100ms
            print(f"⚠️  Saut temporel détecté: {time_jump*1000:.2f}ms")
            if self.on_time_jump:
                self.on_time_jump(time_jump)
        
        self.last_sync_time = current_time
        print(f"🕒 Horloge {self.node_id}: Offset ajusté à {self.local_offset*1000:.3f}ms")
    
    async def start_grandmaster(self):
        """
        Démarre en mode Grandmaster (source de temps de référence)
        """
        if not self.is_grandmaster:
            print(f"❌ Nœud {self.node_id} n'est pas configuré comme Grandmaster")
            return
        
        print(f"👑 Démarrage Grandmaster {self.node_id}")
        
        # Tâches périodiques
        sync_task = asyncio.create_task(self._send_sync_messages())
        announce_task = asyncio.create_task(self._send_announce_messages())
        
        await asyncio.gather(sync_task, announce_task)
    
    async def _send_sync_messages(self):
        """Envoi périodique de messages SYNC (Grandmaster uniquement)"""
        while True:
            await asyncio.sleep(self.sync_interval)
            
            if not self.is_grandmaster:
                break
            
            # Message SYNC
            sync_msg = PTPMessage(
                message_type=PTPMessageType.SYNC,
                domain=self.domain,
                sequence_id=self.sequence_id,
                origin_timestamp=self.get_time()
            )
            
            # Simulation de l'envoi réseau
            await self._broadcast_message(sync_msg)
            
            self.sequence_id += 1
    
    async def _send_announce_messages(self):
        """Envoi périodique de messages ANNOUNCE (Grandmaster uniquement)"""
        while True:
            await asyncio.sleep(self.announce_interval)
            
            if not self.is_grandmaster:
                break
            
            # Message ANNOUNCE pour l'élection du maître
            announce_msg = PTPMessage(
                message_type=PTPMessageType.ANNOUNCE,
                domain=self.domain,
                sequence_id=self.sequence_id,
                origin_timestamp=self.get_time()
            )
            
            await self._broadcast_message(announce_msg)
    
    async def handle_sync_message(self, msg: PTPMessage, receive_time: PTPTimestamp):
        """
        Traite un message SYNC reçu du maître
        """
        if self.is_grandmaster:
            return  # Le Grandmaster ne se synchronise pas
        
        print(f"📨 Nœud {self.node_id}: SYNC reçu à {receive_time.to_float():.6f}")
        
        # Envoie d'une requête DELAY_REQ
        delay_req = PTPMessage(
            message_type=PTPMessageType.DELAY_REQ,
            domain=self.domain,
            sequence_id=self.sequence_id,
            origin_timestamp=self.get_time()
        )
        
        # Simulation de l'envoi avec délai réseau
        await asyncio.sleep(self.network_delay)
        await self._send_delay_request(delay_req, msg, receive_time)
        
        self.sequence_id += 1
    
    async def _send_delay_request(self, delay_req: PTPMessage, 
                                sync_msg: PTPMessage, sync_receive_time: PTPTimestamp):
        """Simule l'envoi d'une requête DELAY_REQ"""
        
        # Le maître répond avec DELAY_RESP
        delay_resp_time = self.get_time() + self.network_delay
        
        # Calcul des métriques de synchronisation
        t1 = sync_msg.origin_timestamp.to_float()  # Envoi SYNC par le maître
        t2 = sync_receive_time.to_float()           # Réception SYNC par l'esclave
        t3 = delay_req.origin_timestamp.to_float()  # Envoi DELAY_REQ par l'esclave
        t4 = delay_resp_time.to_float()             # Réception DELAY_REQ par le maître
        
        # Calcul de l'offset et du délai
        offset = ((t2 - t1) - (t4 - t3)) / 2
        delay = ((t2 - t1) + (t4 - t3)) / 2
        
        measurement = SyncMeasurement(
            master_to_slave_delay=t2 - t1,
            slave_to_master_delay=t4 - t3,
            offset=offset,
            timestamp=time.time()
        )
        
        self.sync_measurements.append(measurement)
        if len(self.sync_measurements) > self.max_measurements:
            self.sync_measurements.pop(0)
        
        # Mise à jour de l'offset avec filtrage
        filtered_offset = self._filter_offset_measurements()
        
        if abs(filtered_offset) > 1e-6:  # Seuil de 1µs
            old_time = self.get_time()
            self.local_offset -= filtered_offset
            
            print(f"🔄 Nœud {self.node_id}: Synchronisation - Offset: {filtered_offset*1000:.3f}ms, "
                  f"Délai: {delay*1000:.3f}ms")
            
            # Marquer comme synchronisé
            self.is_synchronized = True
            self.sync_accuracy = abs(filtered_offset)
            
            if self.on_sync_update:
                self.on_sync_update(filtered_offset, delay)
    
    def _filter_offset_measurements(self) -> float:
        """
        Filtre les mesures d'offset pour réduire le bruit
        """
        if not self.sync_measurements:
            return 0.0
        
        # Utilisation de la médiane pour filtrer les valeurs aberrantes
        recent_offsets = [m.offset for m in self.sync_measurements[-5:]]
        return statistics.median(recent_offsets)
    
    async def _broadcast_message(self, message: PTPMessage):
        """Simule la diffusion d'un message PTP"""
        # En production, ceci utiliserait UDP multicast
        if hasattr(self, '_network_handler'):
            await self._network_handler(message, self.node_id)
    
    def set_network_handler(self, handler):
        """Configure le gestionnaire réseau pour la simulation"""
        self._network_handler = handler
    
    def get_sync_status(self) -> Dict:
        """Retourne le statut de synchronisation"""
        return {
            "node_id": self.node_id,
            "is_synchronized": self.is_synchronized,
            "is_grandmaster": self.is_grandmaster,
            "local_offset_ms": self.local_offset * 1000,
            "sync_accuracy_us": self.sync_accuracy * 1_000_000,
            "measurements_count": len(self.sync_measurements),
            "clock_type": self.clock_type.value,
            "current_time": self.get_time().to_float()
        }

class PTPNetwork:
    """
    Simulation d'un réseau PTP pour synchronisation des nœuds MPC
    """
    
    def __init__(self, num_nodes: int, grandmaster_id: int = 0):
        self.num_nodes = num_nodes
        self.grandmaster_id = grandmaster_id
        self.clocks: Dict[int, PTPClock] = {}
        
        # Création des horloges
        for i in range(num_nodes):
            clock_type = ClockType.GRANDMASTER if i == grandmaster_id else ClockType.ORDINARY_CLOCK
            clock = PTPClock(i, clock_type)
            clock.set_network_handler(self._handle_network_message)
            self.clocks[i] = clock
        
        # Configuration des callbacks
        for clock in self.clocks.values():
            clock.on_sync_update = self._on_sync_update
            clock.on_time_jump = self._on_time_jump
        
        print(f"🌐 Réseau PTP créé avec {num_nodes} nœuds (GM: {grandmaster_id})")
    
    async def _handle_network_message(self, message: PTPMessage, sender_id: int):
        """Gère la distribution des messages PTP"""
        # Simulation du délai réseau variable
        base_delay = 0.001  # 1ms
        jitter = 0.0002     # 0.2ms de gigue
        
        for node_id, clock in self.clocks.items():
            if node_id != sender_id:
                # Délai réseau simulé
                network_delay = base_delay + (jitter * (0.5 - hash(f"{sender_id}-{node_id}") % 100 / 100))
                await asyncio.sleep(network_delay)
                
                # Timestamp de réception
                receive_time = clock.get_time()
                
                # Traitement selon le type de message
                if message.message_type == PTPMessageType.SYNC:
                    await clock.handle_sync_message(message, receive_time)
    
    async def _on_sync_update(self, offset: float, delay: float):
        """Callback lors d'une mise à jour de synchronisation"""
        pass  # Logging ou métriques si nécessaire
    
    async def _on_time_jump(self, jump: float):
        """Callback lors d'un saut temporel significatif"""
        print(f"⚠️  Saut temporel détecté dans le réseau: {jump*1000:.2f}ms")
    
    async def start_synchronization(self):
        """Démarre la synchronisation du réseau"""
        print("🚀 Démarrage de la synchronisation PTP")
        
        # Démarrage du Grandmaster
        grandmaster = self.clocks[self.grandmaster_id]
        gm_task = asyncio.create_task(grandmaster.start_grandmaster())
        
        # Attente pour stabilisation
        await asyncio.sleep(5.0)
        
        return gm_task
    
    def get_network_sync_status(self) -> Dict:
        """Retourne le statut de synchronisation de tout le réseau"""
        statuses = {}
        sync_times = []
        
        for node_id, clock in self.clocks.items():
            status = clock.get_sync_status()
            statuses[node_id] = status
            
            if clock.is_synchronized:
                sync_times.append(status["current_time"])
        
        # Calcul de la dispersion temporelle
        if len(sync_times) > 1:
            time_spread = max(sync_times) - min(sync_times)
        else:
            time_spread = 0.0
        
        return {
            "nodes": statuses,
            "synchronized_nodes": sum(1 for s in statuses.values() if s["is_synchronized"]),
            "total_nodes": self.num_nodes,
            "time_spread_us": time_spread * 1_000_000,
            "network_synchronized": len(sync_times) >= self.num_nodes - 1
        }

# Exemple d'utilisation pour les nœuds MPC
if __name__ == "__main__":
    async def test_ptp_sync():
        # Création d'un réseau PTP avec 5 nœuds MPC
        network = PTPNetwork(5, grandmaster_id=0)
        
        # Démarrage de la synchronisation
        await network.start_synchronization()
        
        # Monitoring périodique
        for i in range(10):
            await asyncio.sleep(2.0)
            
            status = network.get_network_sync_status()
            
            print(f"\n📊 État de synchronisation (T+{(i+1)*2}s):")
            print(f"  Nœuds synchronisés: {status['synchronized_nodes']}/{status['total_nodes']}")
            print(f"  Dispersion temporelle: {status['time_spread_us']:.1f}µs")
            print(f"  Réseau synchronisé: {'✅' if status['network_synchronized'] else '❌'}")
            
            # Détail par nœud
            for node_id, node_status in status['nodes'].items():
                sync_indicator = "👑" if node_status['is_grandmaster'] else ("✅" if node_status['is_synchronized'] else "⏳")
                print(f"    Nœud {node_id}: {sync_indicator} "
                      f"Offset: {node_status['local_offset_ms']:+.3f}ms, "
                      f"Précision: {node_status['sync_accuracy_us']:.1f}µs")
        
        print("\n🎉 Test de synchronisation PTP terminé")
    
    # Exécution du test
    asyncio.run(test_ptp_sync())
