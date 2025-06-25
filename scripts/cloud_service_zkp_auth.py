"""
Services Cloud avec Authentification ZKP
Intégration complète de l'authentification préservant la vie privée
"""

import asyncio
import json
import time
import secrets
import hashlib
import jwt
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import aiohttp
from aiohttp import web, ClientSession
import ssl
from datetime import datetime, timedelta
import base64

class AuthenticationMethod(Enum):
    """Méthodes d'authentification supportées"""
    ZKP_ONLY = "zkp_only"
    CERTIFICATE_TRADITIONAL = "cert_traditional"
    HYBRID_ZKP_CERT = "hybrid_zkp_cert"
    MPC_DISTRIBUTED = "mpc_distributed"

class AccessLevel(Enum):
    """Niveaux d'accès aux ressources"""
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    PRIVILEGED = "privileged"
    ADMIN = "admin"

@dataclass
class AuthenticationChallenge:
    """Challenge d'authentification"""
    challenge_id: str
    challenge_data: str
    issued_at: float
    expires_at: float
    method: AuthenticationMethod
    required_attributes: List[str] = field(default_factory=list)
    client_context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AuthenticatedSession:
    """Session authentifiée"""
    session_id: str
    client_id: str
    authentication_method: AuthenticationMethod
    access_level: AccessLevel
    attributes: Dict[str, Any]
    created_at: float
    expires_at: float
    last_activity: float
    request_count: int = 0

@dataclass
class ZKPAuthenticationRequest:
    """Requête d'authentification ZKP"""
    challenge_id: str
    client_id: str
    zkp_proof: Dict[str, Any]
    public_key_x: str
    public_key_y: str
    nonce_commitment: str
    timestamp: float

@dataclass
class CloudResource:
    """Ressource cloud protégée"""
    resource_id: str
    resource_type: str
    access_level: AccessLevel
    required_attributes: List[str] = field(default_factory=list)
    rate_limit: int = 100  # requêtes par heure
    metadata: Dict[str, Any] = field(default_factory=dict)

class CloudService:
    """
    Service Cloud avec authentification ZKP intégrée
    Supporte multiple méthodes d'authentification et validation PKI-MPC
    """
    
    def __init__(self, service_name: str, service_port: int = 8443):
        self.service_name = service_name
        self.service_port = service_port
        self.service_id = f"cloud_service_{service_name}_{int(time.time())}"
        
        # Configuration d'authentification
        self.supported_auth_methods = [
            AuthenticationMethod.ZKP_ONLY,
            AuthenticationMethod.CERTIFICATE_TRADITIONAL,
            AuthenticationMethod.HYBRID_ZKP_CERT
        ]
        
        # Gestion des sessions et challenges
        self.active_challenges: Dict[str, AuthenticationChallenge] = {}
        self.authenticated_sessions: Dict[str, AuthenticatedSession] = {}
        self.failed_attempts: Dict[str, List[float]] = {}
        
        # Ressources protégées
        self.protected_resources: Dict[str, CloudResource] = {}
        self._initialize_demo_resources()
        
        # Interfaces cryptographiques
        self.zkp_interface: Optional[Any] = None
        self.mpc_interface: Optional[Any] = None
        self.certificate_validator: Optional[Any] = None
        
        # Configuration SSL/TLS
        self.ssl_context = self._create_ssl_context()
        
        # Métriques de sécurité
        self.security_metrics = {
            "authentication_attempts": 0,
            "successful_authentications": 0,
            "failed_authentications": 0,
            "zkp_verifications": 0,
            "certificate_validations": 0,
            "blocked_attempts": 0,
            "active_sessions": 0
        }
        
        # Rate limiting
        self.rate_limits: Dict[str, List[float]] = {}
        self.max_requests_per_hour = 1000
        self.max_failed_attempts = 5
        
        print(f"☁️  Service Cloud '{service_name}' initialisé sur port {service_port}")
    
    def _initialize_demo_resources(self):
        """Initialise les ressources de démonstration"""
        demo_resources = [
            CloudResource(
                resource_id="api_user_data",
                resource_type="api_endpoint",
                access_level=AccessLevel.AUTHENTICATED,
                required_attributes=["valid_certificate"],
                rate_limit=100
            ),
            CloudResource(
                resource_id="admin_panel",
                resource_type="web_interface",
                access_level=AccessLevel.ADMIN,
                required_attributes=["admin_role", "mfa_verified"],
                rate_limit=50
            ),
            CloudResource(
                resource_id="file_storage",
                resource_type="storage_service",
                access_level=AccessLevel.PRIVILEGED,
                required_attributes=["file_access_permission"],
                rate_limit=200
            ),
            CloudResource(
                resource_id="public_info",
                resource_type="api_endpoint",
                access_level=AccessLevel.PUBLIC,
                rate_limit=1000
            )
        ]
        
        for resource in demo_resources:
            self.protected_resources[resource.resource_id] = resource
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Crée le contexte SSL pour HTTPS"""
        # En production, utiliser de vrais certificats
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Pour la démo
        return context
    
    def configure_crypto_interfaces(self, zkp_interface, mpc_interface, cert_validator):
        """Configure les interfaces cryptographiques"""
        self.zkp_interface = zkp_interface
        self.mpc_interface = mpc_interface
        self.certificate_validator = cert_validator
        print("✅ Interfaces cryptographiques configurées")
    
    async def start_service(self):
        """Démarre le service cloud"""
        print(f"🚀 Démarrage du service cloud {self.service_name}")
        
        # Configuration des routes HTTP
        app = web.Application()
        
        # Routes d'authentification
        app.router.add_post('/auth/challenge', self.handle_auth_challenge)
        app.router.add_post('/auth/zkp-verify', self.handle_zkp_authentication)
        app.router.add_post('/auth/certificate', self.handle_certificate_authentication)
        app.router.add_post('/auth/hybrid', self.handle_hybrid_authentication)
        app.router.add_post('/auth/logout', self.handle_logout)
        
        # Routes de ressources protégées
        app.router.add_get('/api/user-data', self.handle_user_data_api)
        app.router.add_get('/api/admin', self.handle_admin_api)
        app.router.add_get('/storage/{file_id}', self.handle_file_storage)
        app.router.add_get('/public/info', self.handle_public_info)
        
        # Routes de monitoring
        app.router.add_get('/health', self.handle_health_check)
        app.router.add_get('/metrics', self.handle_metrics)
        
        # Middleware de sécurité
        app.middlewares.append(self.security_middleware)
        app.middlewares.append(self.rate_limiting_middleware)
        
        # Tâches de maintenance
        cleanup_task = asyncio.create_task(self._cleanup_routine())
        
        # Démarrage du serveur
        runner = web.AppRunner(app)
        await runner.setup()
        
        site = web.TCPSite(runner, 'localhost', self.service_port, ssl_context=self.ssl_context)
        await site.start()
        
        print(f"✅ Service cloud démarré sur https://localhost:{self.service_port}")
        
        # Attendre la tâche de cleanup
        await cleanup_task
    
    @web.middleware
    async def security_middleware(self, request: web.Request, handler):
        """Middleware de sécurité générale"""
        start_time = time.time()
        
        # Headers de sécurité
        response = await handler(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        
        # Logging de sécurité
        processing_time = time.time() - start_time
        client_ip = request.remote
        
        print(f"🔍 {request.method} {request.path} - {client_ip} - {processing_time:.3f}s")
        
        return response
    
    @web.middleware
    async def rate_limiting_middleware(self, request: web.Request, handler):
        """Middleware de limitation de taux"""
        client_ip = request.remote
        current_time = time.time()
        
        # Nettoyage des anciens accès
        if client_ip in self.rate_limits:
            self.rate_limits[client_ip] = [
                t for t in self.rate_limits[client_ip] 
                if current_time - t < 3600  # 1 heure
            ]
        else:
            self.rate_limits[client_ip] = []
        
        # Vérification du rate limit
        if len(self.rate_limits[client_ip]) >= self.max_requests_per_hour:
            self.security_metrics["blocked_attempts"] += 1
            return web.json_response(
                {"error": "Rate limit exceeded"}, 
                status=429
            )
        
        # Enregistrement de la requête
        self.rate_limits[client_ip].append(current_time)
        
        return await handler(request)
    
    async def handle_auth_challenge(self, request: web.Request) -> web.Response:
        """Génère un challenge d'authentification"""
        try:
            data = await request.json()
            client_id = data.get("client_id", "anonymous")
            auth_method = AuthenticationMethod(data.get("method", "zkp_only"))
            
            if auth_method not in self.supported_auth_methods:
                return web.json_response(
                    {"error": "Authentication method not supported"}, 
                    status=400
                )
            
            # Génération du challenge
            challenge_id = f"chal_{int(time.time())}_{secrets.token_hex(8)}"
            challenge_data = secrets.token_hex(32)
            
            challenge = AuthenticationChallenge(
                challenge_id=challenge_id,
                challenge_data=challenge_data,
                issued_at=time.time(),
                expires_at=time.time() + 300,  # 5 minutes
                method=auth_method,
                client_context={"client_id": client_id, "ip": request.remote}
            )
            
            self.active_challenges[challenge_id] = challenge
            
            print(f"🎯 Challenge généré: {challenge_id} pour {client_id} ({auth_method.value})")
            
            return web.json_response({
                "challenge_id": challenge_id,
                "challenge": challenge_data,
                "expires_at": challenge.expires_at,
                "method": auth_method.value
            })
            
        except Exception as e:
            print(f"❌ Erreur génération challenge: {e}")
            return web.json_response(
                {"error": "Challenge generation failed"}, 
                status=500
            )
    
    async def handle_zkp_authentication(self, request: web.Request) -> web.Response:
        """Traite une authentification ZKP"""
        try:
            data = await request.json()
            
            # Parsing de la requête
            auth_request = ZKPAuthenticationRequest(
                challenge_id=data.get("challenge_id"),
                client_id=data.get("client_id"),
                zkp_proof=data.get("zkp_proof", {}),
                public_key_x=data.get("public_key_x"),
                public_key_y=data.get("public_key_y"),
                nonce_commitment=data.get("nonce_commitment"),
                timestamp=time.time()
            )
            
            # Vérification du challenge
            if auth_request.challenge_id not in self.active_challenges:
                return web.json_response(
                    {"error": "Invalid or expired challenge"}, 
                    status=401
                )
            
            challenge = self.active_challenges[auth_request.challenge_id]
            
            # Vérification de l'expiration
            if time.time() > challenge.expires_at:
                del self.active_challenges[auth_request.challenge_id]
                return web.json_response(
                    {"error": "Challenge expired"}, 
                    status=401
                )
            
            # Vérification ZKP
            zkp_valid = await self._verify_zkp_proof(auth_request, challenge)
            
            self.security_metrics["authentication_attempts"] += 1
            self.security_metrics["zkp_verifications"] += 1
            
            if zkp_valid:
                # Création de la session authentifiée
                session = await self._create_authenticated_session(
                    auth_request.client_id,
                    AuthenticationMethod.ZKP_ONLY,
                    AccessLevel.AUTHENTICATED,
                    {
                        "public_key_x": auth_request.public_key_x,
                        "public_key_y": auth_request.public_key_y,
                        "verified_via_zkp": True
                    }
                )
                
                # Nettoyage du challenge
                del self.active_challenges[auth_request.challenge_id]
                
                self.security_metrics["successful_authentications"] += 1
                
                print(f"✅ Authentification ZKP réussie: {auth_request.client_id}")
                
                return web.json_response({
                    "status": "authenticated",
                    "session_token": session.session_id,
                    "expires_at": session.expires_at,
                    "access_level": session.access_level.value
                })
            
            else:
                self.security_metrics["failed_authentications"] += 1
                self._record_failed_attempt(auth_request.client_id)
                
                print(f"❌ Authentification ZKP échouée: {auth_request.client_id}")
                
                return web.json_response(
                    {"error": "ZKP verification failed"}, 
                    status=401
                )
                
        except Exception as e:
            print(f"❌ Erreur authentification ZKP: {e}")
            return web.json_response(
                {"error": "Authentication processing failed"}, 
                status=500
            )
    
    async def _verify_zkp_proof(self, auth_request: ZKPAuthenticationRequest, 
                               challenge: AuthenticationChallenge) -> bool:
        """Vérifie une preuve ZKP"""
        if not self.zkp_interface:
            print("⚠️  Interface ZKP non configurée, simulation de vérification")
            # Simulation de vérification pour la démo
            return auth_request.zkp_proof.get("valid", True)
        
        try:
            # Reconstruction de la preuve ZKP
            from zkp_proof_generator import ZKProof
            
            zkp_proof = ZKProof(
                proof=auth_request.zkp_proof.get("proof", {}),
                public_signals=auth_request.zkp_proof.get("public_signals", []),
                verification_key=auth_request.zkp_proof.get("verification_key", {}),
                proof_type="key_possession",
                timestamp=auth_request.timestamp
            )
            
            # Vérification via l'interface ZKP
            is_valid = self.zkp_interface.verify_proof(zkp_proof)
            
            print(f"🔍 Vérification ZKP: {'✅ Valide' if is_valid else '❌ Invalide'}")
            
            return is_valid
            
        except Exception as e:
            print(f"❌ Erreur vérification ZKP: {e}")
            return False
    
    async def handle_certificate_authentication(self, request: web.Request) -> web.Response:
        """Traite une authentification par certificat traditionnel"""
        try:
            data = await request.json()
            
            challenge_id = data.get("challenge_id")
            client_certificate = data.get("certificate")
            signature = data.get("signature")
            
            # Vérification du challenge
            if challenge_id not in self.active_challenges:
                return web.json_response(
                    {"error": "Invalid challenge"}, 
                    status=401
                )
            
            challenge = self.active_challenges[challenge_id]
            
            # Validation du certificat via MPC
            cert_valid = await self._validate_certificate_mpc(client_certificate)
            
            # Vérification de la signature du challenge
            signature_valid = await self._verify_challenge_signature(
                challenge.challenge_data, signature, client_certificate
            )
            
            self.security_metrics["authentication_attempts"] += 1
            self.security_metrics["certificate_validations"] += 1
            
            if cert_valid and signature_valid:
                # Extraction des informations du certificat
                cert_info = self._extract_certificate_info(client_certificate)
                
                session = await self._create_authenticated_session(
                    cert_info.get("subject", "unknown"),
                    AuthenticationMethod.CERTIFICATE_TRADITIONAL,
                    self._determine_access_level(cert_info),
                    cert_info
                )
                
                del self.active_challenges[challenge_id]
                self.security_metrics["successful_authentications"] += 1
                
                print(f"✅ Authentification certificat réussie: {cert_info.get('subject')}")
                
                return web.json_response({
                    "status": "authenticated",
                    "session_token": session.session_id,
                    "expires_at": session.expires_at,
                    "access_level": session.access_level.value
                })
            
            else:
                self.security_metrics["failed_authentications"] += 1
                return web.json_response(
                    {"error": "Certificate validation failed"}, 
                    status=401
                )
                
        except Exception as e:
            print(f"❌ Erreur authentification certificat: {e}")
            return web.json_response(
                {"error": "Certificate authentication failed"}, 
                status=500
            )
    
    async def _validate_certificate_mpc(self, certificate: str) -> bool:
        """Valide un certificat via le cluster MPC"""
        if not self.mpc_interface:
            print("⚠️  Interface MPC non configurée, validation simulée")
            return True  # Simulation pour la démo
        
        try:
            # En production, déléguer au cluster MPC pour validation distribuée
            # Vérification de la signature du certificat
            # Vérification du statut de révocation (CRL/OCSP distribué)
            # Validation de la chaîne de certification
            
            print("🔍 Validation certificat via cluster MPC")
            return True  # Simulation
            
        except Exception as e:
            print(f"❌ Erreur validation MPC: {e}")
            return False
    
    async def _verify_challenge_signature(self, challenge: str, signature: str, certificate: str) -> bool:
        """Vérifie la signature du challenge"""
        try:
            # En production, extraire la clé publique du certificat
            # et vérifier la signature ECDSA du challenge
            
            print(f"🔍 Vérification signature du challenge")
            return True  # Simulation pour la démo
            
        except Exception as e:
            print(f"❌ Erreur vérification signature: {e}")
            return False
    
    def _extract_certificate_info(self, certificate: str) -> Dict[str, Any]:
        """Extrait les informations d'un certificat"""
        # Simulation d'extraction d'informations
        return {
            "subject": "CN=client.example.com,O=Example Corp",
            "issuer": "CN=Demo Enhanced CA,O=PKI-MPC-ZKP Demo",
            "serial_number": "12345678",
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2025-01-01T00:00:00Z",
            "key_usage": ["digital_signature", "key_encipherment"],
            "extended_key_usage": ["client_auth"]
        }
    
    def _determine_access_level(self, cert_info: Dict[str, Any]) -> AccessLevel:
        """Détermine le niveau d'accès basé sur le certificat"""
        subject = cert_info.get("subject", "")
        extended_key_usage = cert_info.get("extended_key_usage", [])
        
        if "admin" in subject.lower():
            return AccessLevel.ADMIN
        elif "client_auth" in extended_key_usage:
            return AccessLevel.AUTHENTICATED
        else:
            return AccessLevel.PUBLIC
    
    async def _create_authenticated_session(self, client_id: str, auth_method: AuthenticationMethod,
                                          access_level: AccessLevel, attributes: Dict[str, Any]) -> AuthenticatedSession:
        """Crée une session authentifiée"""
        session_id = f"sess_{int(time.time())}_{secrets.token_hex(16)}"
        
        session = AuthenticatedSession(
            session_id=session_id,
            client_id=client_id,
            authentication_method=auth_method,
            access_level=access_level,
            attributes=attributes,
            created_at=time.time(),
            expires_at=time.time() + 3600,  # 1 heure
            last_activity=time.time()
        )
        
        self.authenticated_sessions[session_id] = session
        self.security_metrics["active_sessions"] = len(self.authenticated_sessions)
        
        return session
    
    def _record_failed_attempt(self, client_id: str):
        """Enregistre une tentative d'authentification échouée"""
        current_time = time.time()
        
        if client_id not in self.failed_attempts:
            self.failed_attempts[client_id] = []
        
        self.failed_attempts[client_id].append(current_time)
        
        # Nettoyage des anciennes tentatives
        self.failed_attempts[client_id] = [
            t for t in self.failed_attempts[client_id]
            if current_time - t < 3600  # 1 heure
        ]
        
        # Blocage temporaire si trop d'échecs
        if len(self.failed_attempts[client_id]) >= self.max_failed_attempts:
            print(f"🚨 Client bloqué temporairement: {client_id}")
    
    async def handle_user_data_api(self, request: web.Request) -> web.Response:
        """API protégée pour données utilisateur"""
        session = await self._validate_session(request)
        if not session:
            return web.json_response({"error": "Authentication required"}, status=401)
        
        # Vérification des permissions
        resource = self.protected_resources["api_user_data"]
        if not self._check_access_permission(session, resource):
            return web.json_response({"error": "Insufficient permissions"}, status=403)
        
        # Données simulées
        user_data = {
            "user_id": session.client_id,
            "profile": {
                "name": "User Demo",
                "email": "user@example.com",
                "last_login": session.created_at
            },
            "permissions": session.attributes,
            "session_info": {
                "auth_method": session.authentication_method.value,
                "access_level": session.access_level.value
            }
        }
        
        session.request_count += 1
        session.last_activity = time.time()
        
        return web.json_response(user_data)
    
    async def handle_admin_api(self, request: web.Request) -> web.Response:
        """API d'administration protégée"""
        session = await self._validate_session(request)
        if not session:
            return web.json_response({"error": "Authentication required"}, status=401)
        
        resource = self.protected_resources["admin_panel"]
        if not self._check_access_permission(session, resource):
            return web.json_response({"error": "Admin access required"}, status=403)
        
        admin_data = {
            "service_metrics": self.security_metrics,
            "active_sessions": len(self.authenticated_sessions),
            "resources": list(self.protected_resources.keys()),
            "security_status": "operational"
        }
        
        return web.json_response(admin_data)
    
    async def _validate_session(self, request: web.Request) -> Optional[AuthenticatedSession]:
        """Valide une session à partir de la requête"""
        auth_header = request.headers.get("Authorization", "")
        
        if not auth_header.startswith("Bearer "):
            return None
        
        session_token = auth_header[7:]  # Enlever "Bearer "
        
        if session_token not in self.authenticated_sessions:
            return None
        
        session = self.authenticated_sessions[session_token]
        
        # Vérification de l'expiration
        if time.time() > session.expires_at:
            del self.authenticated_sessions[session_token]
            self.security_metrics["active_sessions"] = len(self.authenticated_sessions)
            return None
        
        return session
    
    def _check_access_permission(self, session: AuthenticatedSession, resource: CloudResource) -> bool:
        """Vérifie les permissions d'accès à une ressource"""
        # Vérification du niveau d'accès
        access_levels = {
            AccessLevel.PUBLIC: 0,
            AccessLevel.AUTHENTICATED: 1,
            AccessLevel.PRIVILEGED: 2,
            AccessLevel.ADMIN: 3
        }
        
        required_level = access_levels[resource.access_level]
        session_level = access_levels[session.access_level]
        
        if session_level < required_level:
            return False
        
        # Vérification des attributs requis
        for required_attr in resource.required_attributes:
            if required_attr not in session.attributes:
                print(f"❌ Attribut manquant: {required_attr}")
                return False
        
        return True
    
    async def handle_public_info(self, request: web.Request) -> web.Response:
        """Endpoint public sans authentification"""
        public_info = {
            "service_name": self.service_name,
            "service_version": "1.0.0",
            "authentication_methods": [method.value for method in self.supported_auth_methods],
            "public_endpoints": ["/public/info", "/health"],
            "timestamp": time.time()
        }
        
        return web.json_response(public_info)
    
    async def handle_health_check(self, request: web.Request) -> web.Response:
        """Endpoint de santé du service"""
        health_status = {
            "status": "healthy",
            "service": self.service_name,
            "uptime": time.time() - self.security_metrics.get("service_start_time", time.time()),
            "active_sessions": len(self.authenticated_sessions),
            "crypto_interfaces": {
                "zkp_available": self.zkp_interface is not None,
                "mpc_available": self.mpc_interface is not None,
                "cert_validator_available": self.certificate_validator is not None
            }
        }
        
        return web.json_response(health_status)
    
    async def handle_metrics(self, request: web.Request) -> web.Response:
        """Endpoint de métriques (authentification requise)"""
        session = await self._validate_session(request)
        if not session or session.access_level != AccessLevel.ADMIN:
            return web.json_response({"error": "Admin access required"}, status=403)
        
        return web.json_response(self.security_metrics)
    
    async def handle_logout(self, request: web.Request) -> web.Response:
        """Déconnexion et invalidation de session"""
        session = await self._validate_session(request)
        if session:
            del self.authenticated_sessions[session.session_id]
            self.security_metrics["active_sessions"] = len(self.authenticated_sessions)
            print(f"👋 Déconnexion: {session.client_id}")
        
        return web.json_response({"status": "logged_out"})
    
    async def _cleanup_routine(self):
        """Routine de nettoyage périodique"""
        while True:
            try:
                await asyncio.sleep(300)  # Toutes les 5 minutes
                
                current_time = time.time()
                
                # Nettoyage des challenges expirés
                expired_challenges = [
                    chal_id for chal_id, challenge in self.active_challenges.items()
                    if current_time > challenge.expires_at
                ]
                
                for chal_id in expired_challenges:
                    del self.active_challenges[chal_id]
                
                # Nettoyage des sessions expirées
                expired_sessions = [
                    sess_id for sess_id, session in self.authenticated_sessions.items()
                    if current_time > session.expires_at
                ]
                
                for sess_id in expired_sessions:
                    del self.authenticated_sessions[sess_id]
                
                self.security_metrics["active_sessions"] = len(self.authenticated_sessions)
                
                # Nettoyage des tentatives échouées
                for client_id in list(self.failed_attempts.keys()):
                    self.failed_attempts[client_id] = [
                        t for t in self.failed_attempts[client_id]
                        if current_time - t < 3600
                    ]
                    if not self.failed_attempts[client_id]:
                        del self.failed_attempts[client_id]
                
                if expired_challenges or expired_sessions:
                    print(f"🧹 Nettoyage: {len(expired_challenges)} challenges, "
                          f"{len(expired_sessions)} sessions expirées")
                
            except Exception as e:
                print(f"❌ Erreur nettoyage: {e}")

# Client de test pour le service cloud
class CloudServiceClient:
    """Client pour tester le service cloud"""
    
    def __init__(self, service_url: str = "https://localhost:8443"):
        self.service_url = service_url
        self.session_token: Optional[str] = None
        
    async def request_challenge(self, client_id: str, method: str = "zkp_only") -> Dict[str, Any]:
        """Demande un challenge d'authentification"""
        async with ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            async with session.post(
                f"{self.service_url}/auth/challenge",
                json={"client_id": client_id, "method": method}
            ) as response:
                return await response.json()
    
    async def authenticate_zkp(self, challenge_id: str, client_id: str) -> Dict[str, Any]:
        """Authentification ZKP simulée"""
        # Simulation d'une preuve ZKP valide
        zkp_proof = {
            "proof": {"a": "0x123...", "b": "0x456...", "c": "0x789..."},
            "public_signals": ["1", "2", "3"],
            "verification_key": {"alpha": "0xabc...", "beta": "0xdef..."},
            "valid": True
        }
        
        auth_data = {
            "challenge_id": challenge_id,
            "client_id": client_id,
            "zkp_proof": zkp_proof,
            "public_key_x": "0x" + secrets.token_hex(32),
            "public_key_y": "0x" + secrets.token_hex(32),
            "nonce_commitment": "0x" + secrets.token_hex(32)
        }
        
        async with ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            async with session.post(
                f"{self.service_url}/auth/zkp-verify",
                json=auth_data
            ) as response:
                result = await response.json()
                if response.status == 200:
                    self.session_token = result.get("session_token")
                return result
    
    async def access_protected_resource(self, endpoint: str) -> Dict[str, Any]:
        """Accède à une ressource protégée"""
        if not self.session_token:
            return {"error": "Not authenticated"}
        
        headers = {"Authorization": f"Bearer {self.session_token}"}
        
        async with ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            async with session.get(
                f"{self.service_url}{endpoint}",
                headers=headers
            ) as response:
                return await response.json()

# Exemple d'utilisation
if __name__ == "__main__":
    async def test_cloud_service():
        # Démarrage du service cloud
        service = CloudService("DemoAPI", 8443)
        
        # Configuration des interfaces (simulation)
        service.zkp_interface = type('MockZKP', (), {
            'verify_proof': lambda self, proof: True
        })()
        
        print("🧪 Test du service cloud avec authentification ZKP")
        
        # Démarrage du service en arrière-plan
        service_task = asyncio.create_task(service.start_service())
        
        # Attendre que le service démarre
        await asyncio.sleep(2)
        
        try:
            # Test client
            client = CloudServiceClient()
            
            # 1. Demande de challenge
            challenge_response = await client.request_challenge("test_client", "zkp_only")
            print(f"Challenge reçu: {challenge_response.get('challenge_id')}")
            
            # 2. Authentification ZKP
            if challenge_response.get("challenge_id"):
                auth_response = await client.authenticate_zkp(
                    challenge_response["challenge_id"], 
                    "test_client"
                )
                print(f"Authentification: {auth_response.get('status')}")
                
                # 3. Accès aux ressources
                if auth_response.get("status") == "authenticated":
                    user_data = await client.access_protected_resource("/api/user-data")
                    print(f"Données utilisateur: {user_data.get('user_id')}")
                    
                    public_info = await client.access_protected_resource("/public/info")
                    print(f"Info publique: {public_info.get('service_name')}")
        
        except Exception as e:
            print(f"❌ Erreur test: {e}")
        
        finally:
            service_task.cancel()
    
    # Exécution du test
    # asyncio.run(test_cloud_service())
    print("💡 Pour tester le service, décommentez la ligne asyncio.run() ci-dessus")
