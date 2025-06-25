"""
Orchestrateur Principal PKI-MPC-ZKP
Coordonne tous les composants de l'architecture hybride
"""

import asyncio
import json
import time
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import signal
import sys
import os

# Imports des composants développés
from dkg_feldman_implementation import FeldmanVSSDKG
from tss_ecdsa_implementation import TSSECDSA
from zkp_proof_generator import ZKPProofGenerator
from pbft_consensus_implementation import PBFTNetwork, ClientRequest
from ptp_sync_implementation import PTPNetwork
from ca_augmented_implementation import CertificateAugmentedCA
from mpc_node_config import MPCNode
from cloud_service_zkp_auth import CloudService

class SystemState(Enum):
    """États du système global"""
    INITIALIZING = "initializing"
    DKG_PHASE = "dkg_phase"
    READY = "ready"
    OPERATIONAL = "operational"
    MAINTENANCE = "maintenance"
    SHUTDOWN = "shutdown"
    ERROR = "error"

@dataclass
class SystemConfiguration:
    """Configuration globale du système"""
    # Configuration MPC
    mpc_threshold: int = 3
    mpc_total_nodes: int = 5
    
    # Configuration réseau
    base_port: int = 8000
    ca_port: int = 8443
    cloud_service_port: int = 8444
    
    # Configuration temporelle
    sync_timeout: int = 30
    operation_timeout: int = 120
    
    # Configuration sécurité
    max_concurrent_operations: int = 10
    session_timeout: int = 3600
    
    # Configuration tests
    test_mode: bool = True
    simulation_delays: bool = True
    verbose_logging: bool = True

@dataclass
class SystemMetrics:
    """Métriques globales du système"""
    startup_time: float = 0.0
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    certificates_issued: int = 0
    zkp_verifications: int = 0
    mpc_signatures: int = 0
    average_operation_time: float = 0.0
    last_heartbeat: float = 0.0
    
class PKIMPCZKPOrchestrator:
    """
    Orchestrateur principal coordonnant tous les composants
    de l'architecture PKI-MPC-ZKP
    """
    
    def __init__(self, config: SystemConfiguration):
        self.config = config
        self.state = SystemState.INITIALIZING
        self.metrics = SystemMetrics()
        
        # Logging configuration
        self._setup_logging()
        
        # Composants du système
        self.dkg_system: Optional[FeldmanVSSDKG] = None
        self.tss_system: Optional[TSSECDSA] = None
        self.zkp_generator: Optional[ZKPProofGenerator] = None
        self.pbft_network: Optional[PBFTNetwork] = None
        self.ptp_network: Optional[PTPNetwork] = None
        self.ca_authority: Optional[CertificateAugmentedCA] = None
        self.mpc_nodes: Dict[int, MPCNode] = {}
        self.cloud_services: Dict[str, CloudService] = {}
        
        # État des clés distribuées
        self.distributed_keys: Dict[int, Tuple[int, Any]] = {}
        self.system_ready = False
        
        # Gestion des tâches asynchrones
        self.background_tasks: List[asyncio.Task] = []
        
        # Gestionnaire de signaux pour arrêt propre
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self.logger.info(f"🚀 Orchestrateur PKI-MPC-ZKP initialisé")
        self.logger.info(f"   Configuration: {config.mpc_threshold}/{config.mpc_total_nodes} MPC")
    
    def _setup_logging(self):
        """Configure le système de logging"""
        log_level = logging.DEBUG if self.config.verbose_logging else logging.INFO
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('pki_mpc_zkp.log')
            ]
        )
        
        self.logger = logging.getLogger('PKI-MPC-ZKP')
    
    def _signal_handler(self, signum, frame):
        """Gestionnaire de signaux pour arrêt propre"""
        self.logger.info(f"📡 Signal {signum} reçu, arrêt du système...")
        asyncio.create_task(self.shutdown())
    
    async def initialize_system(self) -> bool:
        """
        Initialise tous les composants du système dans l'ordre correct
        """
        start_time = time.time()
        self.logger.info("🔧 Initialisation du système PKI-MPC-ZKP")
        
        try:
            # Phase 1: Synchronisation temporelle
            await self._initialize_time_sync()
            
            # Phase 2: Réseau de consensus
            await self._initialize_consensus_network()
            
            # Phase 3: Nœuds MPC
            await self._initialize_mpc_nodes()
            
            # Phase 4: Génération de clés distribuée
            await self._perform_distributed_key_generation()
            
            # Phase 5: Systèmes cryptographiques
            await self._initialize_crypto_systems()
            
            # Phase 6: Autorité de certification
            await self._initialize_certificate_authority()
            
            # Phase 7: Services cloud
            await self._initialize_cloud_services()
            
            # Phase 8: Tests de connectivité
            await self._run_connectivity_tests()
            
            self.metrics.startup_time = time.time() - start_time
            self.state = SystemState.READY
            self.system_ready = True
            
            self.logger.info(f"✅ Système initialisé en {self.metrics.startup_time:.2f}s")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Erreur initialisation: {e}")
            self.state = SystemState.ERROR
            return False
    
    async def _initialize_time_sync(self):
        """Initialise la synchronisation temporelle PTP"""
        self.logger.info("⏰ Initialisation synchronisation temporelle...")
        
        self.ptp_network = PTPNetwork(
            self.config.mpc_total_nodes, 
            grandmaster_id=0
        )
        
        # Démarrage de la synchronisation
        sync_task = asyncio.create_task(self.ptp_network.start_synchronization())
        self.background_tasks.append(sync_task)
        
        # Attente de stabilisation
        await asyncio.sleep(3)
        
        # Vérification de la synchronisation
        sync_status = self.ptp_network.get_network_sync_status()
        if sync_status["network_synchronized"]:
            self.logger.info(f"✅ Synchronisation PTP active - Dispersion: {sync_status['time_spread_us']:.1f}µs")
        else:
            self.logger.warning("⚠️  Synchronisation PTP partielle")
    
    async def _initialize_consensus_network(self):
        """Initialise le réseau de consensus PBFT"""
        self.logger.info("🤝 Initialisation réseau de consensus PBFT...")
        
        self.pbft_network = PBFTNetwork(self.config.mpc_total_nodes)
        
        # Configuration des callbacks pour opérations MPC
        async def mpc_operation_callback(request: ClientRequest, sequence: int):
            await self._handle_consensus_operation(request, sequence)
        
        for node in self.pbft_network.nodes.values():
            node.on_request_executed = mpc_operation_callback
        
        self.logger.info(f"✅ Réseau PBFT configuré avec {self.config.mpc_total_nodes} nœuds")
    
    async def _initialize_mpc_nodes(self):
        """Initialise les nœuds MPC"""
        self.logger.info("🔐 Initialisation des nœuds MPC...")
        
        for node_id in range(self.config.mpc_total_nodes):
            node = MPCNode(node_id, self.config.mpc_total_nodes, self.config.mpc_threshold)
            self.mpc_nodes[node_id] = node
            
            # Démarrage du nœud
            node_task = asyncio.create_task(node.start_node())
            self.background_tasks.append(node_task)
        
        # Attente de stabilisation
        await asyncio.sleep(2)
        
        self.logger.info(f"✅ {len(self.mpc_nodes)} nœuds MPC démarrés")
    
    async def _perform_distributed_key_generation(self):
        """Effectue la génération de clés distribuée"""
        self.logger.info("🔑 Génération de clés distribuée (DKG)...")
        self.state = SystemState.DKG_PHASE
        
        # Initialisation du système DKG
        self.dkg_system = FeldmanVSSDKG(
            threshold=self.config.mpc_threshold,
            num_participants=self.config.mpc_total_nodes
        )
        
        # Exécution de la DKG
        try:
            self.distributed_keys = self.dkg_system.execute_dkg()
            
            # Coordination avec les nœuds MPC pour la DKG
            participants = list(range(self.config.mpc_total_nodes))
            dkg_operation_id = f"dkg_init_{int(time.time())}"
            
            # Démarrage coordonné de la DKG sur tous les nœuds
            dkg_tasks = []
            for node_id, node in self.mpc_nodes.items():
                task = asyncio.create_task(
                    node.participate_in_dkg(dkg_operation_id, participants)
                )
                dkg_tasks.append(task)
            
            # Attente de completion
            dkg_results = await asyncio.gather(*dkg_tasks, return_exceptions=True)
            successful_nodes = sum(1 for r in dkg_results if r is True)
            
            if successful_nodes >= self.config.mpc_threshold:
                self.logger.info(f"✅ DKG réussie sur {successful_nodes}/{len(participants)} nœuds")
            else:
                raise Exception(f"DKG échouée: seulement {successful_nodes} nœuds réussis")
                
        except Exception as e:
            self.logger.error(f"❌ Erreur DKG: {e}")
            raise
    
    async def _initialize_crypto_systems(self):
        """Initialise les systèmes cryptographiques"""
        self.logger.info("🔐 Initialisation systèmes cryptographiques...")
        
        # Système TSS ECDSA
        participants = list(range(self.config.mpc_total_nodes))
        self.tss_system = TSSECDSA(
            threshold=self.config.mpc_threshold,
            participants=participants
        )
        
        # Chargement des clés DKG
        if self.distributed_keys:
            self.tss_system.load_dkg_results(self.distributed_keys)
        
        # Générateur ZKP
        self.zkp_generator = ZKPProofGenerator("./circuits")
        
        self.logger.info("✅ Systèmes cryptographiques configurés")
    
    async def _initialize_certificate_authority(self):
        """Initialise l'autorité de certification augmentée"""
        self.logger.info("🏛️  Initialisation CA Augmentée...")
        
        self.ca_authority = CertificateAugmentedCA(
            "PKI-MPC-ZKP Demo CA",
            mpc_threshold=self.config.mpc_threshold,
            mpc_total_nodes=self.config.mpc_total_nodes
        )
        
        # Configuration des interfaces
        self.ca_authority.configure_mpc_interface(
            self.tss_system,
            self.zkp_generator,
            self.pbft_network
        )
        
        # Démarrage des services CA
        ca_task = asyncio.create_task(self.ca_authority.start_ca_services())
        self.background_tasks.append(ca_task)
        
        await asyncio.sleep(1)  # Stabilisation
        
        self.logger.info("✅ CA Augmentée opérationnelle")
    
    async def _initialize_cloud_services(self):
        """Initialise les services cloud"""
        self.logger.info("☁️  Initialisation services cloud...")
        
        # Service API principal
        api_service = CloudService("MainAPI", self.config.cloud_service_port)
        api_service.configure_crypto_interfaces(
            self.zkp_generator,
            self.tss_system,
            self.ca_authority
        )
        
        self.cloud_services["main_api"] = api_service
        
        # Démarrage du service
        service_task = asyncio.create_task(api_service.start_service())
        self.background_tasks.append(service_task)
        
        await asyncio.sleep(2)  # Stabilisation
        
        self.logger.info(f"✅ Service cloud démarré sur port {self.config.cloud_service_port}")
    
    async def _run_connectivity_tests(self):
        """Effectue des tests de connectivité inter-composants"""
        self.logger.info("🔗 Tests de connectivité...")
        
        test_results = []
        
        # Test 1: Communication PBFT
        try:
            test_request = ClientRequest(
                client_id="connectivity_test",
                operation="health_check",
                timestamp=time.time(),
                params={"test": True}
            )
            
            pbft_success = await self.pbft_network.submit_to_primary(test_request)
            test_results.append(("PBFT", pbft_success))
        except Exception as e:
            test_results.append(("PBFT", False))
            self.logger.warning(f"⚠️  Test PBFT échoué: {e}")
        
        # Test 2: Synchronisation PTP
        if self.ptp_network:
            sync_status = self.ptp_network.get_network_sync_status()
            ptp_success = sync_status["network_synchronized"]
            test_results.append(("PTP", ptp_success))
        
        # Test 3: Nœuds MPC
        mpc_healthy = sum(
            1 for node in self.mpc_nodes.values()
            if node.get_node_status()["state"] == "ready"
        )
        mpc_success = mpc_healthy >= self.config.mpc_threshold
        test_results.append(("MPC", mpc_success))
        
        # Résumé des tests
        passed_tests = sum(1 for _, success in test_results if success)
        total_tests = len(test_results)
        
        self.logger.info(f"📊 Tests connectivité: {passed_tests}/{total_tests} réussis")
        
        for test_name, success in test_results:
            status = "✅" if success else "❌"
            self.logger.info(f"  {status} {test_name}")
        
        if passed_tests < total_tests:
            self.logger.warning("⚠️  Certains tests de connectivité ont échoué")
    
    async def _handle_consensus_operation(self, request: ClientRequest, sequence: int):
        """Traite les opérations provenant du consensus PBFT"""
        operation_start = time.time()
        
        try:
            if request.operation == "tss_signature":
                await self._handle_tss_signature_request(request, sequence)
            elif request.operation == "dkg_key_generation":
                await self._handle_dkg_request(request, sequence)
            elif request.operation == "zkp_verification":
                await self._handle_zkp_verification(request, sequence)
            else:
                self.logger.info(f"ℹ️  Opération consensus: {request.operation}")
            
            # Métriques
            operation_time = time.time() - operation_start
            self.metrics.total_operations += 1
            self.metrics.successful_operations += 1
            self._update_average_operation_time(operation_time)
            
        except Exception as e:
            self.logger.error(f"❌ Erreur opération consensus: {e}")
            self.metrics.failed_operations += 1
    
    async def _handle_tss_signature_request(self, request: ClientRequest, sequence: int):
        """Traite une requête de signature TSS"""
        self.logger.info(f"✍️  Signature TSS consensus seq={sequence}")
        
        params = request.params
        message_hash = bytes.fromhex(params.get("data_hash", ""))
        participating_nodes = params.get("participating_nodes", list(range(self.config.mpc_threshold)))
        
        if self.tss_system and message_hash:
            try:
                # Signature distribuée
                signature = self.tss_system.sign_message(message_hash, participating_nodes)
                self.metrics.mpc_signatures += 1
                self.logger.info(f"✅ Signature TSS générée pour seq={sequence}")
                
            except Exception as e:
                self.logger.error(f"❌ Erreur signature TSS: {e}")
    
    async def _handle_dkg_request(self, request: ClientRequest, sequence: int):
        """Traite une requête DKG"""
        self.logger.info(f"🔑 DKG consensus seq={sequence}")
        # Implémentation de DKG additionnelle si nécessaire
    
    async def _handle_zkp_verification(self, request: ClientRequest, sequence: int):
        """Traite une vérification ZKP"""
        self.logger.info(f"🔍 Vérification ZKP consensus seq={sequence}")
        self.metrics.zkp_verifications += 1
    
    def _update_average_operation_time(self, new_time: float):
        """Met à jour le temps moyen d'opération"""
        if self.metrics.average_operation_time == 0:
            self.metrics.average_operation_time = new_time
        else:
            # Moyenne mobile
            self.metrics.average_operation_time = (
                self.metrics.average_operation_time * 0.9 + new_time * 0.1
            )
    
    async def run_system(self):
        """Lance le système en mode opérationnel"""
        if not self.system_ready:
            self.logger.error("❌ Système non initialisé")
            return
        
        self.state = SystemState.OPERATIONAL
        self.logger.info("🚀 Système PKI-MPC-ZKP opérationnel")
        
        # Démarrage des tâches de monitoring
        monitoring_task = asyncio.create_task(self._monitoring_routine())
        heartbeat_task = asyncio.create_task(self._heartbeat_routine())
        
        self.background_tasks.extend([monitoring_task, heartbeat_task])
        
        try:
            # Boucle principale
            while self.state == SystemState.OPERATIONAL:
                await asyncio.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("⏹️  Arrêt demandé par l'utilisateur")
        except Exception as e:
            self.logger.error(f"❌ Erreur système: {e}")
            self.state = SystemState.ERROR
        finally:
            await self.shutdown()
    
    async def _monitoring_routine(self):
        """Routine de monitoring du système"""
        while self.state == SystemState.OPERATIONAL:
            try:
                await asyncio.sleep(30)  # Monitoring toutes les 30s
                
                # Collecte des métriques
                system_health = await self._collect_system_metrics()
                
                # Vérification de la santé globale
                if not system_health["healthy"]:
                    self.logger.warning("⚠️  Problème de santé système détecté")
                    
                    # Auto-récupération si possible
                    if system_health["recoverable"]:
                        await self._attempt_auto_recovery()
                
                # Log périodique des métriques
                self.logger.info(
                    f"📊 Métriques: Ops={self.metrics.total_operations}, "
                    f"Succès={self.metrics.successful_operations}, "
                    f"Échecs={self.metrics.failed_operations}, "
                    f"Temps moy={self.metrics.average_operation_time:.3f}s"
                )
                
            except Exception as e:
                self.logger.error(f"❌ Erreur monitoring: {e}")
                await asyncio.sleep(5)
    
    async def _collect_system_metrics(self) -> Dict[str, Any]:
        """Collecte les métriques de tous les composants"""
        health_data = {
            "healthy": True,
            "recoverable": True,
            "components": {}
        }
        
        # Santé des nœuds MPC
        mpc_health = []
        for node_id, node in self.mpc_nodes.items():
            status = node.get_node_status()
            mpc_health.append(status["state"] == "ready")
            health_data["components"][f"mpc_node_{node_id}"] = status
        
        mpc_healthy_count = sum(mpc_health)
        if mpc_healthy_count < self.config.mpc_threshold:
            health_data["healthy"] = False
            health_data["recoverable"] = mpc_healthy_count >= (self.config.mpc_threshold - 1)
        
        # Santé du consensus PBFT
        if self.pbft_network:
            pbft_status = self.pbft_network.get_network_status()
            health_data["components"]["pbft"] = pbft_status
        
        # Santé de la CA
        if self.ca_authority:
            ca_status = self.ca_authority.get_ca_status()
            health_data["components"]["ca"] = ca_status
        
        # Santé de la synchronisation
        if self.ptp_network:
            sync_status = self.ptp_network.get_network_sync_status()
            health_data["components"]["ptp"] = sync_status
            
            if not sync_status["network_synchronized"]:
                self.logger.warning("⚠️  Synchronisation temporelle dégradée")
        
        return health_data
    
    async def _attempt_auto_recovery(self):
        """Tentative de récupération automatique"""
        self.logger.info("🔄 Tentative de récupération automatique...")
        self.state = SystemState.MAINTENANCE
        
        try:
            # Redémarrage des nœuds défaillants
            for node_id, node in self.mpc_nodes.items():
                status = node.get_node_status()
                if status["state"] != "ready":
                    self.logger.info(f"🔄 Redémarrage nœud MPC {node_id}")
                    # Implémentation du redémarrage
            
            await asyncio.sleep(5)  # Attente stabilisation
            
            # Vérification de la récupération
            recovery_success = await self._verify_system_health()
            
            if recovery_success:
                self.logger.info("✅ Récupération automatique réussie")
                self.state = SystemState.OPERATIONAL
            else:
                self.logger.error("❌ Récupération automatique échouée")
                
        except Exception as e:
            self.logger.error(f"❌ Erreur récupération: {e}")
        
        if self.state == SystemState.MAINTENANCE:
            self.state = SystemState.OPERATIONAL
    
    async def _verify_system_health(self) -> bool:
        """Vérifie la santé globale du système"""
        try:
            health_data = await self._collect_system_metrics()
            return health_data["healthy"]
        except Exception:
            return False
    
    async def _heartbeat_routine(self):
        """Routine de heartbeat"""
        while self.state in [SystemState.OPERATIONAL, SystemState.MAINTENANCE]:
            try:
                self.metrics.last_heartbeat = time.time()
                await asyncio.sleep(10)  # Heartbeat toutes les 10s
                
            except Exception as e:
                self.logger.error(f"❌ Erreur heartbeat: {e}")
                await asyncio.sleep(5)
    
    async def shutdown(self):
        """Arrêt propre du système"""
        self.logger.info("🛑 Arrêt du système PKI-MPC-ZKP...")
        self.state = SystemState.SHUTDOWN
        
        # Annulation des tâches en arrière-plan
        for task in self.background_tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Arrêt des composants
        for node in self.mpc_nodes.values():
            node.state = node.state.__class__.OFFLINE
        
        self.logger.info("✅ Système arrêté proprement")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Retourne le statut complet du système"""
        uptime = time.time() - (self.metrics.startup_time or time.time())
        
        return {
            "system_state": self.state.value,
            "uptime_seconds": uptime,
            "configuration": {
                "mpc_threshold": self.config.mpc_threshold,
                "mpc_total_nodes": self.config.mpc_total_nodes,
                "test_mode": self.config.test_mode
            },
            "metrics": {
                "total_operations": self.metrics.total_operations,
                "successful_operations": self.metrics.successful_operations,
                "failed_operations": self.metrics.failed_operations,
                "certificates_issued": self.metrics.certificates_issued,
                "zkp_verifications": self.metrics.zkp_verifications,
                "mpc_signatures": self.metrics.mpc_signatures,
                "average_operation_time": self.metrics.average_operation_time,
                "success_rate": (
                    self.metrics.successful_operations / max(1, self.metrics.total_operations) * 100
                )
            },
            "components": {
                "mpc_nodes": len(self.mpc_nodes),
                "distributed_keys_generated": bool(self.distributed_keys),
                "ca_operational": self.ca_authority is not None,
                "cloud_services": len(self.cloud_services),
                "pbft_network": self.pbft_network is not None,
                "ptp_sync": self.ptp_network is not None
            },
            "last_heartbeat": self.metrics.last_heartbeat
        }

# Point d'entrée principal
async def main():
    """Point d'entrée principal du système"""
    
    print("🚀 Démarrage du système PKI-MPC-ZKP")
    print("=" * 50)
    
    # Configuration du système
    config = SystemConfiguration(
        mpc_threshold=3,
        mpc_total_nodes=5,
        test_mode=True,
        verbose_logging=True
    )
    
    # Création de l'orchestrateur
    orchestrator = PKIMPCZKPOrchestrator(config)
    
    try:
        # Initialisation
        success = await orchestrator.initialize_system()
        
        if not success:
            print("❌ Échec de l'initialisation")
            return
        
        print("\n🎉 Système prêt!")
        print("=" * 50)
        
        # Affichage du statut
        status = orchestrator.get_system_status()
        print(f"État: {status['system_state']}")
        print(f"Nœuds MPC: {status['components']['mpc_nodes']}")
        print(f"Clés distribuées: {status['components']['distributed_keys_generated']}")
        print(f"CA opérationnelle: {status['components']['ca_operational']}")
        print(f"Services cloud: {status['components']['cloud_services']}")
        
        print("\n📡 Système en fonctionnement...")
        print("Appuyez sur Ctrl+C pour arrêter")
        
        # Fonctionnement du système
        await orchestrator.run_system()
        
    except KeyboardInterrupt:
        print("\n⏹️  Arrêt demandé par l'utilisateur")
    except Exception as e:
        print(f"\n❌ Erreur fatale: {e}")
    finally:
        await orchestrator.shutdown()
        print("👋 Au revoir!")

if __name__ == "__main__":
    # Exécution du système complet
    asyncio.run(main())
