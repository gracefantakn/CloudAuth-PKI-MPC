"""
Implémentation de l'Autorité de Certification Augmentée
Intègre la délégation MPC pour les opérations de signature
"""

import asyncio
import json
import time
import hashlib
import secrets
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta
import ipaddress

class CertificateType(Enum):
    """Types de certificats supportés"""
    SERVER_AUTH = "server_auth"
    CLIENT_AUTH = "client_auth" 
    CODE_SIGNING = "code_signing"
    EMAIL = "email"
    CA_INTERMEDIATE = "ca_intermediate"

class CertificateStatus(Enum):
    """Statuts des certificats"""
    PENDING = "pending"
    ISSUED = "issued"
    REVOKED = "revoked"
    EXPIRED = "expired"

@dataclass
class CertificateRequest:
    """Requête de certificat (CSR augmentée)"""
    request_id: str
    subject_dn: Dict[str, str]
    public_key: bytes
    san_list: List[str] = field(default_factory=list)
    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)
    validity_days: int = 365
    cert_type: CertificateType = CertificateType.SERVER_AUTH
    requester_id: str = ""
    timestamp: float = field(default_factory=time.time)
    verification_data: Dict = field(default_factory=dict)

@dataclass
class IssuedCertificate:
    """Certificat émis"""
    certificate_id: str
    serial_number: int
    certificate_pem: str
    subject_dn: str
    issuer_dn: str
    not_before: datetime
    not_after: datetime
    status: CertificateStatus
    revocation_reason: Optional[str] = None
    revocation_time: Optional[datetime] = None
    issued_by_mpc: bool = True

@dataclass
class MPCSigningRequest:
    """Requête de signature vers le cluster MPC"""
    operation_id: str
    operation_type: str  # "certificate_signing", "crl_signing"
    data_to_sign: bytes
    algorithm: str = "ECDSA_SHA256"
    participating_nodes: List[int] = field(default_factory=list)
    timeout: float = 30.0
    priority: int = 1

class CertificateAugmentedCA:
    """
    Autorité de Certification Augmentée avec délégation MPC
    Maintient les fonctions PKI traditionnelles tout en déléguant la signature
    """
    
    def __init__(self, ca_name: str, mpc_threshold: int = 3, mpc_total_nodes: int = 5):
        self.ca_name = ca_name
        self.ca_dn = f"CN={ca_name} Enhanced CA,O=PKI-MPC-ZKP Demo,C=FR"
        
        # Configuration MPC
        self.mpc_threshold = mpc_threshold
        self.mpc_total_nodes = mpc_total_nodes
        self.mpc_available_nodes: Set[int] = set(range(mpc_total_nodes))
        
        # État de la CA
        self.certificates: Dict[str, IssuedCertificate] = {}
        self.revoked_certificates: Dict[str, IssuedCertificate] = {}
        self.serial_counter = 1000
        self.crl_number = 1
        
        # Configuration des politiques
        self.default_validity_days = 365
        self.max_validity_days = 3650
        self.supported_algorithms = ["ECDSA_SHA256", "RSA_SHA256"]
        self.auto_renewal_threshold_days = 30
        
        # Interfaces MPC et ZKP
        self.mpc_interface: Optional[Any] = None
        self.zkp_interface: Optional[Any] = None
        self.pbft_interface: Optional[Any] = None
        
        # Métriques et logs
        self.metrics = {
            "certificates_issued": 0,
            "certificates_revoked": 0,
            "mpc_operations": 0,
            "failed_operations": 0,
            "average_signing_time": 0.0
        }
        
        # File d'attente des requêtes
        self.pending_requests: asyncio.Queue = asyncio.Queue()
        self.signing_queue: asyncio.Queue = asyncio.Queue()
        
        print(f"🏛️  CA Augmentée '{ca_name}' initialisée")
        print(f"   MPC: Seuil {mpc_threshold}/{mpc_total_nodes}")
    
    def configure_mpc_interface(self, mpc_interface, zkp_interface, pbft_interface):
        """Configure les interfaces cryptographiques"""
        self.mpc_interface = mpc_interface
        self.zkp_interface = zkp_interface
        self.pbft_interface = pbft_interface
        print("✅ Interfaces MPC/ZKP/PBFT configurées")
    
    async def start_ca_services(self):
        """Démarre les services de la CA"""
        print("🚀 Démarrage des services CA Augmentée")
        
        # Tâches asynchrones
        request_processor = asyncio.create_task(self._process_certificate_requests())
        signing_processor = asyncio.create_task(self._process_mpc_signing_queue())
        maintenance_task = asyncio.create_task(self._maintenance_routine())
        
        await asyncio.gather(request_processor, signing_processor, maintenance_task)
    
    async def submit_certificate_request(self, csr_data: Dict) -> str:
        """
        Soumet une nouvelle requête de certificat
        """
        # Validation et parsing de la CSR
        cert_request = self._parse_certificate_request(csr_data)
        
        # Vérifications de politique
        validation_result = await self._validate_certificate_request(cert_request)
        if not validation_result["valid"]:
            raise ValueError(f"Requête invalide: {validation_result['reason']}")
        
        # Ajout à la file d'attente
        await self.pending_requests.put(cert_request)
        
        print(f"📝 Requête de certificat soumise: {cert_request.request_id}")
        return cert_request.request_id
    
    def _parse_certificate_request(self, csr_data: Dict) -> CertificateRequest:
        """Parse et valide une requête de certificat"""
        request_id = f"csr_{int(time.time())}_{secrets.token_hex(4)}"
        
        # Extraction des données obligatoires
        subject_dn = csr_data.get("subject", {})
        if not subject_dn.get("common_name"):
            raise ValueError("Common Name requis")
        
        # Clé publique (format PEM)
        public_key_pem = csr_data.get("public_key", "")
        if not public_key_pem:
            raise ValueError("Clé publique requise")
        
        public_key_bytes = public_key_pem.encode('utf-8')
        
        # Construction de la requête
        cert_request = CertificateRequest(
            request_id=request_id,
            subject_dn=subject_dn,
            public_key=public_key_bytes,
            san_list=csr_data.get("san", []),
            key_usage=csr_data.get("key_usage", ["digital_signature", "key_encipherment"]),
            extended_key_usage=csr_data.get("extended_key_usage", ["server_auth"]),
            validity_days=csr_data.get("validity_days", self.default_validity_days),
            cert_type=CertificateType(csr_data.get("cert_type", "server_auth")),
            requester_id=csr_data.get("requester_id", "unknown"),
            verification_data=csr_data.get("verification", {})
        )
        
        return cert_request
    
    async def _validate_certificate_request(self, request: CertificateRequest) -> Dict[str, Any]:
        """
        Valide une requête de certificat selon les politiques CA
        """
        validation_errors = []
        
        # Vérification de la validité
        if request.validity_days > self.max_validity_days:
            validation_errors.append(f"Validité trop longue: {request.validity_days} > {self.max_validity_days}")
        
        # Vérification du Common Name
        cn = request.subject_dn.get("common_name", "")
        if not cn or len(cn) < 3:
            validation_errors.append("Common Name invalide")
        
        # Vérification des SAN pour les certificats serveur
        if request.cert_type == CertificateType.SERVER_AUTH:
            if not request.san_list:
                validation_errors.append("SAN requis pour les certificats serveur")
            
            # Validation des SAN
            for san in request.san_list:
                if not self._validate_san_entry(san):
                    validation_errors.append(f"SAN invalide: {san}")
        
        # Vérification de la clé publique
        try:
            # Tentative de parsing de la clé publique
            public_key = serialization.load_pem_public_key(request.public_key)
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                if public_key.curve.name not in ["secp256r1", "secp384r1", "secp256k1"]:
                    validation_errors.append(f"Courbe non supportée: {public_key.curve.name}")
        except Exception as e:
            validation_errors.append(f"Clé publique invalide: {str(e)}")
        
        # Vérification de l'autorisation du demandeur
        auth_result = await self._verify_requester_authorization(request)
        if not auth_result:
            validation_errors.append("Demandeur non autorisé")
        
        return {
            "valid": len(validation_errors) == 0,
            "reason": "; ".join(validation_errors) if validation_errors else None,
            "warnings": []
        }
    
    def _validate_san_entry(self, san: str) -> bool:
        """Valide une entrée SAN"""
        try:
            # Test IP address
            ipaddress.ip_address(san)
            return True
        except ValueError:
            pass
        
        # Test DNS name (simplifiée)
        if "." in san and len(san) > 3 and not san.startswith("."):
            return True
        
        return False
    
    async def _verify_requester_authorization(self, request: CertificateRequest) -> bool:
        """
        Vérifie l'autorisation du demandeur
        Dans un environnement réel, ceci interrogerait un système d'autorisation
        """
        # Implémentation simplifiée pour la démo
        if request.cert_type == CertificateType.CA_INTERMEDIATE:
            # Seuls les administrateurs peuvent demander des certificats CA
            return request.requester_id in ["admin", "ca_operator"]
        
        return True  # Autorisation basique pour la démo
    
    async def _process_certificate_requests(self):
        """
        Processeur principal des requêtes de certificats
        """
        print("🔄 Processeur de requêtes démarré")
        
        while True:
            try:
                # Attente d'une nouvelle requête
                request = await self.pending_requests.get()
                
                print(f"🏭 Traitement de la requête {request.request_id}")
                
                # Génération du certificat
                certificate = await self._generate_certificate(request)
                
                # Requête de signature MPC
                signing_request = MPCSigningRequest(
                    operation_id=f"sign_{request.request_id}",
                    operation_type="certificate_signing",
                    data_to_sign=certificate["tbs_certificate"],
                    participating_nodes=list(range(self.mpc_threshold))
                )
                
                # Envoi vers la file de signature MPC
                await self.signing_queue.put((signing_request, certificate, request))
                
                self.pending_requests.task_done()
                
            except Exception as e:
                print(f"❌ Erreur traitement requête: {e}")
                await asyncio.sleep(1)
    
    async def _generate_certificate(self, request: CertificateRequest) -> Dict[str, Any]:
        """
        Génère la structure du certificat (sans signature)
        """
        # Assignation du numéro de série
        serial_number = self.serial_counter
        self.serial_counter += 1
        
        # Dates de validité
        not_before = datetime.utcnow()
        not_after = not_before + timedelta(days=request.validity_days)
        
        # Construction du certificat X.509 (structure simplifiée)
        cert_template = {
            "version": 3,
            "serial_number": serial_number,
            "issuer": self.ca_dn,
            "subject": self._build_subject_dn(request.subject_dn),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "public_key": base64.b64encode(request.public_key).decode(),
            "extensions": self._build_extensions(request),
            "signature_algorithm": "ecdsa_with_sha256"
        }
        
        # Calcul du TBS (To Be Signed)
        tbs_data = json.dumps(cert_template, sort_keys=True).encode('utf-8')
        tbs_hash = hashlib.sha256(tbs_data).digest()
        
        return {
            "template": cert_template,
            "tbs_certificate": tbs_hash,
            "serial_number": serial_number,
            "not_before": not_before,
            "not_after": not_after
        }
    
    def _build_subject_dn(self, subject_data: Dict[str, str]) -> str:
        """Construit le DN du sujet"""
        components = []
        
        if "common_name" in subject_data:
            components.append(f"CN={subject_data['common_name']}")
        if "organization" in subject_data:
            components.append(f"O={subject_data['organization']}")
        if "organizational_unit" in subject_data:
            components.append(f"OU={subject_data['organizational_unit']}")
        if "country" in subject_data:
            components.append(f"C={subject_data['country']}")
        if "locality" in subject_data:
            components.append(f"L={subject_data['locality']}")
        if "state" in subject_data:
            components.append(f"ST={subject_data['state']}")
        
        return ",".join(components)
    
    def _build_extensions(self, request: CertificateRequest) -> Dict[str, Any]:
        """Construit les extensions X.509"""
        extensions = {}
        
        # Key Usage
        if request.key_usage:
            extensions["key_usage"] = {
                "critical": True,
                "usage": request.key_usage
            }
        
        # Extended Key Usage
        if request.extended_key_usage:
            extensions["extended_key_usage"] = {
                "critical": False,
                "usage": request.extended_key_usage
            }
        
        # Subject Alternative Names
        if request.san_list:
            extensions["subject_alt_name"] = {
                "critical": False,
                "names": request.san_list
            }
        
        # Authority Key Identifier (référence à la CA)
        extensions["authority_key_identifier"] = {
            "critical": False,
            "key_identifier": hashlib.sha1(self.ca_name.encode()).hexdigest()
        }
        
        # Basic Constraints
        is_ca = request.cert_type == CertificateType.CA_INTERMEDIATE
        extensions["basic_constraints"] = {
            "critical": True,
            "ca": is_ca,
            "path_length": 0 if is_ca else None
        }
        
        return extensions
    
    async def _process_mpc_signing_queue(self):
        """
        Processeur de la file de signature MPC
        """
        print("🔐 Processeur de signature MPC démarré")
        
        while True:
            try:
                # Attente d'une requête de signature
                signing_request, certificate_data, cert_request = await self.signing_queue.get()
                
                print(f"🔑 Signature MPC: {signing_request.operation_id}")
                
                # Mesure du temps de signature
                start_time = time.time()
                
                # Délégation à l'interface MPC via PBFT
                signature_result = await self._delegate_to_mpc_cluster(signing_request)
                
                signing_time = time.time() - start_time
                
                if signature_result["success"]:
                    # Finalisation du certificat
                    final_certificate = await self._finalize_certificate(
                        certificate_data, signature_result["signature"], cert_request
                    )
                    
                    # Stockage
                    self.certificates[final_certificate.certificate_id] = final_certificate
                    
                    # Métriques
                    self.metrics["certificates_issued"] += 1
                    self.metrics["mpc_operations"] += 1
                    self._update_average_signing_time(signing_time)
                    
                    print(f"✅ Certificat émis: {final_certificate.certificate_id} "
                          f"(Signature en {signing_time:.3f}s)")
                
                else:
                    print(f"❌ Échec signature MPC: {signature_result['error']}")
                    self.metrics["failed_operations"] += 1
                
                self.signing_queue.task_done()
                
            except Exception as e:
                print(f"❌ Erreur processeur signature: {e}")
                await asyncio.sleep(1)
    
    async def _delegate_to_mpc_cluster(self, signing_request: MPCSigningRequest) -> Dict[str, Any]:
        """
        Délègue la signature au cluster MPC via PBFT
        """
        if not self.pbft_interface:
            return {"success": False, "error": "Interface PBFT non configurée"}
        
        try:
            # Création d'une requête PBFT pour la signature distribuée
            from pbft_consensus_implementation import ClientRequest
            
            pbft_request = ClientRequest(
                client_id="ca_authority",
                operation="tss_signature",
                timestamp=time.time(),
                params={
                    "operation_id": signing_request.operation_id,
                    "data_hash": signing_request.data_to_sign.hex(),
                    "algorithm": signing_request.algorithm,
                    "participating_nodes": signing_request.participating_nodes
                }
            )
            
            # Soumission au consensus PBFT
            success = await self.pbft_interface.submit_to_primary(pbft_request)
            
            if success:
                # Simulation de la signature (en production, récupérer le résultat)
                signature_r = secrets.randbelow(2**256)
                signature_s = secrets.randbelow(2**256)
                
                return {
                    "success": True,
                    "signature": {
                        "r": signature_r,
                        "s": signature_s,
                        "algorithm": signing_request.algorithm,
                        "participating_nodes": signing_request.participating_nodes
                    }
                }
            else:
                return {"success": False, "error": "Consensus PBFT échoué"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _finalize_certificate(self, cert_data: Dict, signature: Dict, 
                                   request: CertificateRequest) -> IssuedCertificate:
        """
        Finalise le certificat avec la signature MPC
        """
        # Construction du certificat final
        final_cert_template = cert_data["template"].copy()
        final_cert_template["signature"] = {
            "algorithm": signature["algorithm"],
            "value": f"{signature['r']:064x}{signature['s']:064x}",
            "signed_by_mpc": True,
            "mpc_nodes": signature["participating_nodes"]
        }
        
        # Sérialisation en PEM (simulée)
        cert_pem = self._serialize_certificate_to_pem(final_cert_template)
        
        # Création de l'objet certificat émis
        certificate_id = f"cert_{cert_data['serial_number']:08d}"
        
        issued_cert = IssuedCertificate(
            certificate_id=certificate_id,
            serial_number=cert_data["serial_number"],
            certificate_pem=cert_pem,
            subject_dn=final_cert_template["subject"],
            issuer_dn=final_cert_template["issuer"],
            not_before=cert_data["not_before"],
            not_after=cert_data["not_after"],
            status=CertificateStatus.ISSUED,
            issued_by_mpc=True
        )
        
        return issued_cert
    
    def _serialize_certificate_to_pem(self, cert_template: Dict) -> str:
        """
        Sérialise le certificat en format PEM (implémentation simplifiée)
        """
        # En production, utiliser cryptography pour générer un vrai certificat X.509
        cert_data = json.dumps(cert_template, indent=2)
        cert_b64 = base64.b64encode(cert_data.encode()).decode()
        
        # Format PEM simulé
        pem_lines = []
        pem_lines.append("-----BEGIN CERTIFICATE-----")
        
        # Découpage en lignes de 64 caractères
        for i in range(0, len(cert_b64), 64):
            pem_lines.append(cert_b64[i:i+64])
        
        pem_lines.append("-----END CERTIFICATE-----")
        
        return "\n".join(pem_lines)
    
    def _update_average_signing_time(self, new_time: float):
        """Met à jour le temps moyen de signature"""
        if self.metrics["average_signing_time"] == 0:
            self.metrics["average_signing_time"] = new_time
        else:
            # Moyenne mobile
            self.metrics["average_signing_time"] = (
                self.metrics["average_signing_time"] * 0.9 + new_time * 0.1
            )
    
    async def revoke_certificate(self, certificate_id: str, reason: str = "unspecified") -> bool:
        """
        Révoque un certificat et met à jour la CRL
        """
        if certificate_id not in self.certificates:
            return False
        
        certificate = self.certificates[certificate_id]
        certificate.status = CertificateStatus.REVOKED
        certificate.revocation_reason = reason
        certificate.revocation_time = datetime.utcnow()
        
        # Déplacement vers la liste des révoqués
        self.revoked_certificates[certificate_id] = certificate
        del self.certificates[certificate_id]
        
        # Mise à jour de la CRL (signature MPC requise)
        await self._update_crl()
        
        self.metrics["certificates_revoked"] += 1
        print(f"🚫 Certificat révoqué: {certificate_id} (Raison: {reason})")
        
        return True
    
    async def _update_crl(self):
        """
        Met à jour la liste de révocation (CRL) avec signature MPC
        """
        crl_data = {
            "version": 2,
            "issuer": self.ca_dn,
            "this_update": datetime.utcnow().isoformat(),
            "next_update": (datetime.utcnow() + timedelta(days=7)).isoformat(),
            "crl_number": self.crl_number,
            "revoked_certificates": [
                {
                    "serial_number": cert.serial_number,
                    "revocation_date": cert.revocation_time.isoformat(),
                    "reason": cert.revocation_reason
                }
                for cert in self.revoked_certificates.values()
            ]
        }
        
        # Signature MPC de la CRL
        crl_tbs = json.dumps(crl_data, sort_keys=True).encode('utf-8')
        crl_hash = hashlib.sha256(crl_tbs).digest()
        
        signing_request = MPCSigningRequest(
            operation_id=f"crl_{self.crl_number}",
            operation_type="crl_signing",
            data_to_sign=crl_hash
        )
        
        await self.signing_queue.put((signing_request, {"crl_data": crl_data}, None))
        self.crl_number += 1
    
    async def _maintenance_routine(self):
        """
        Routine de maintenance périodique
        """
        while True:
            await asyncio.sleep(3600)  # Toutes les heures
            
            try:
                # Nettoyage des certificats expirés
                expired_count = await self._cleanup_expired_certificates()
                
                # Vérification de la santé du cluster MPC
                mpc_health = await self._check_mpc_cluster_health()
                
                # Rotation automatique de la CRL
                if len(self.revoked_certificates) > 0:
                    await self._update_crl()
                
                print(f"🧹 Maintenance: {expired_count} certificats expirés nettoyés, "
                      f"MPC santé: {mpc_health['available_nodes']}/{self.mpc_total_nodes}")
                
            except Exception as e:
                print(f"❌ Erreur maintenance: {e}")
    
    async def _cleanup_expired_certificates(self) -> int:
        """Nettoie les certificats expirés"""
        now = datetime.utcnow()
        expired_certs = []
        
        for cert_id, cert in self.certificates.items():
            if cert.not_after < now:
                expired_certs.append(cert_id)
        
        for cert_id in expired_certs:
            cert = self.certificates[cert_id]
            cert.status = CertificateStatus.EXPIRED
            del self.certificates[cert_id]
            print(f"⏰ Certificat expiré: {cert_id}")
        
        return len(expired_certs)
    
    async def _check_mpc_cluster_health(self) -> Dict[str, Any]:
        """Vérifie la santé du cluster MPC"""
        # Simulation de vérification de santé
        available_nodes = len(self.mpc_available_nodes)
        
        return {
            "available_nodes": available_nodes,
            "required_threshold": self.mpc_threshold,
            "healthy": available_nodes >= self.mpc_threshold,
            "last_check": time.time()
        }
    
    def get_ca_status(self) -> Dict[str, Any]:
        """Retourne le statut complet de la CA"""
        return {
            "ca_name": self.ca_name,
            "ca_dn": self.ca_dn,
            "mpc_config": {
                "threshold": self.mpc_threshold,
                "total_nodes": self.mpc_total_nodes,
                "available_nodes": len(self.mpc_available_nodes)
            },
            "certificate_stats": {
                "active_certificates": len(self.certificates),
                "revoked_certificates": len(self.revoked_certificates),
                "total_issued": self.metrics["certificates_issued"]
            },
            "operational_metrics": self.metrics,
            "queue_status": {
                "pending_requests": self.pending_requests.qsize(),
                "signing_queue": self.signing_queue.qsize()
            },
            "last_serial": self.serial_counter - 1,
            "crl_number": self.crl_number
        }

# Interface pour les clients de la CA
class CAClient:
    """Client pour interagir avec la CA Augmentée"""
    
    def __init__(self, ca_url: str = "https://ca.example.com"):
        self.ca_url = ca_url
        self.session_id = secrets.token_hex(16)
    
    async def request_certificate(self, subject_data: Dict, san_list: List[str] = None) -> str:
        """Demande un nouveau certificat"""
        
        # Génération d'une clé privée (simulation)
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Construction de la requête
        csr_request = {
            "subject": subject_data,
            "public_key": public_key_pem,
            "san": san_list or [],
            "key_usage": ["digital_signature", "key_encipherment"],
            "extended_key_usage": ["server_auth"],
            "validity_days": 365,
            "cert_type": "server_auth",
            "requester_id": self.session_id
        }
        
        # Simulation de l'envoi HTTP
        print(f"📤 Envoi CSR pour {subject_data.get('common_name', 'Unknown')}")
        
        return f"request_{int(time.time())}"

# Exemple d'utilisation
if __name__ == "__main__":
    async def test_ca_augmented():
        # Initialisation de la CA
        ca = CertificateAugmentedCA("Demo Enhanced CA")
        
        # Simulation des interfaces (normalement injectées)
        ca.mpc_interface = "MPC_INTERFACE_MOCK"
        ca.zkp_interface = "ZKP_INTERFACE_MOCK"
        
        # Simulation d'un réseau PBFT pour les tests
        from pbft_consensus_implementation import PBFTNetwork
        pbft_network = PBFTNetwork(5)
        ca.pbft_interface = pbft_network
        
        # Test de soumission de requêtes
        test_requests = [
            {
                "subject": {
                    "common_name": "api.example.com",
                    "organization": "Example Corp",
                    "country": "FR"
                },
                "san": ["api.example.com", "www.api.example.com"],
                "validity_days": 365,
                "requester_id": "admin"
            },
            {
                "subject": {
                    "common_name": "client001.example.com",
                    "organization": "Example Corp",
                    "country": "FR"
                },
                "cert_type": "client_auth",
                "key_usage": ["digital_signature"],
                "extended_key_usage": ["client_auth"],
                "validity_days": 180,
                "requester_id": "client001"
            }
        ]
        
        print("🧪 Test de la CA Augmentée")
        
        # Démarrage des services CA (simulation limitée)
        try:
            # Soumission des requêtes de test
            for req in test_requests:
                req["public_key"] = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----"
                request_id = await ca.submit_certificate_request(req)
                print(f"✅ Requête soumise: {request_id}")
            
            # Simulation de traitement (normalement asynchrone)
            await asyncio.sleep(2)
            
            # Affichage du statut
            status = ca.get_ca_status()
            print(f"\n📊 Statut CA:")
            print(f"  Certificats actifs: {status['certificate_stats']['active_certificates']}")
            print(f"  Requêtes en attente: {status['queue_status']['pending_requests']}")
            print(f"  File signature: {status['queue_status']['signing_queue']}")
            
        except Exception as e:
            print(f"❌ Erreur test: {e}")
    
    # Exécution du test
    asyncio.run(test_ca_augmented())
