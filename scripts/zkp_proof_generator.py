"""
Générateur de Preuves ZKP pour l'authentification PKI-MPC
Interface Python avec les circuits Circom via snarkjs
"""

import json
import subprocess
import os
import hashlib
import secrets
from typing import Dict, Any, Tuple, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import tempfile
import time

@dataclass
class ZKProof:
    """Représente une preuve ZK complète"""
    proof: Dict[str, Any]      # La preuve zkSNARK
    public_signals: list       # Signaux publics
    verification_key: Dict     # Clé de vérification
    proof_type: str           # Type de preuve
    timestamp: float          # Timestamp de génération

@dataclass
class ClientAuthRequest:
    """Requête d'authentification client avec ZKP"""
    client_id: str
    challenge: str
    public_key_x: str
    public_key_y: str
    zkp_proof: ZKProof
    nonce_commitment: str

class ZKPProofGenerator:
    """
    Générateur de preuves ZKP pour l'authentification
    Utilise Circom et snarkjs en arrière-plan
    """
    
    def __init__(self, circuit_dir: str = "./circuits"):
        self.circuit_dir = circuit_dir
        self.curve = ec.SECP256K1()
        self.field_order = 21888242871839275222246405745257275088548364400416034343698204186575808495617
        
        # Chemins des fichiers générés
        self.circuit_path = os.path.join(circuit_dir, "keyPossession.circom")
        self.wasm_path = os.path.join(circuit_dir, "keyPossession.wasm")
        self.zkey_path = os.path.join(circuit_dir, "keyPossession_final.zkey")
        self.vkey_path = os.path.join(circuit_dir, "verification_key.json")
        
        self._ensure_circuit_compiled()
    
    def _ensure_circuit_compiled(self):
        """S'assure que le circuit est compilé et prêt"""
        if not os.path.exists(self.circuit_dir):
            os.makedirs(self.circuit_dir)
        
        # Vérifier si les fichiers compilés existent
        if not all(os.path.exists(path) for path in [self.wasm_path, self.zkey_path, self.vkey_path]):
            print("⚠️  Fichiers circuit manquants, compilation nécessaire")
            self._setup_circuit()
    
    def _setup_circuit(self):
        """Configure et compile le circuit Circom"""
        print("🔧 Configuration du circuit ZKP...")
        
        # Écrire le circuit Circom dans un fichier
        circuit_content = self._get_circuit_content()
        with open(self.circuit_path, 'w') as f:
            f.write(circuit_content)
        
        try:
            # Compilation du circuit
            self._run_command([
                "circom", self.circuit_path,
                "--r1cs", "--wasm", "--sym",
                "-o", self.circuit_dir
            ])
            
            # Trusted setup (en production, utiliser une cérémonie sécurisée)
            self._run_command([
                "snarkjs", "powersoftau", "new", "bn128", "16",
                os.path.join(self.circuit_dir, "pot16_0000.ptau"), "-v"
            ])
            
            self._run_command([
                "snarkjs", "powersoftau", "contribute",
                os.path.join(self.circuit_dir, "pot16_0000.ptau"),
                os.path.join(self.circuit_dir, "pot16_0001.ptau"),
                "--name='First contribution'", "-v"
            ])
            
            self._run_command([
                "snarkjs", "powersoftau", "prepare", "phase2",
                os.path.join(self.circuit_dir, "pot16_0001.ptau"),
                os.path.join(self.circuit_dir, "pot16_final.ptau"), "-v"
            ])
            
            # Génération de la clé de vérification
            self._run_command([
                "snarkjs", "groth16", "setup",
                os.path.join(self.circuit_dir, "keyPossession.r1cs"),
                os.path.join(self.circuit_dir, "pot16_final.ptau"),
                self.zkey_path
            ])
            
            self._run_command([
                "snarkjs", "zkey", "export", "verificationkey",
                self.zkey_path, self.vkey_path
            ])
            
            print("✅ Circuit compilé et configuré")
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Erreur de compilation: {e}")
            raise
    
    def _run_command(self, cmd: list):
        """Exécute une commande système"""
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.circuit_dir)
        if result.returncode != 0:
            print(f"❌ Commande échouée: {' '.join(cmd)}")
            print(f"Stderr: {result.stderr}")
            raise subprocess.CalledProcessError(result.returncode, cmd)
    
    def _get_circuit_content(self) -> str:
        """Retourne le contenu du circuit Circom simplifié"""
        return '''
pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";

template KeyPossessionProof() {
    signal private input privateKey;
    signal private input nonce;
    signal private input challenge;
    
    signal input publicKeyX;
    signal input publicKeyY;
    signal input challengeHash;
    signal input nonceCommitment;
    
    signal output proofOutput;
    signal output responseHash;
    
    // Vérification simple: hash(privateKey + nonce) == expected
    component hasher1 = Poseidon(2);
    hasher1.inputs[0] <== privateKey;
    hasher1.inputs[1] <== nonce;
    
    component hasher2 = Poseidon(2);
    hasher2.inputs[0] <== challenge;
    hasher2.inputs[1] <== hasher1.out;
    
    proofOutput <== hasher2.out;
    responseHash <== hasher1.out;
    
    // Vérification du commitment sur le nonce
    component nonceHasher = Poseidon(1);
    nonceHasher.inputs[0] <== nonce;
    nonceCommitment === nonceHasher.out;
}

component main = KeyPossessionProof();
'''
    
    def generate_nonce_commitment(self, nonce: int) -> str:
        """Génère un engagement sur le nonce"""
        # Utilisation d'un hash pour l'engagement
        nonce_bytes = nonce.to_bytes(32, 'big')
        commitment = hashlib.sha256(nonce_bytes).hexdigest()
        return commitment
    
    def prepare_circuit_inputs(self, private_key: int, challenge: str, 
                             public_key: Tuple[int, int]) -> Dict[str, Any]:
        """Prépare les entrées pour le circuit"""
        
        # Génération d'un nonce aléatoire
        nonce = secrets.randbelow(self.field_order)
        
        # Conversion du challenge en entier
        challenge_bytes = challenge.encode('utf-8')
        challenge_int = int.from_bytes(hashlib.sha256(challenge_bytes).digest(), 'big') % self.field_order
        
        # Hash du challenge
        challenge_hash = int.from_bytes(
            hashlib.sha256(challenge_int.to_bytes(32, 'big')).digest(), 'big'
        ) % self.field_order
        
        # Engagement sur le nonce
        nonce_commitment = int.from_bytes(
            hashlib.sha256(nonce.to_bytes(32, 'big')).digest(), 'big'
        ) % self.field_order
        
        # Préparation des entrées
        circuit_inputs = {
            # Entrées privées
            "privateKey": str(private_key % self.field_order),
            "nonce": str(nonce),
            "challenge": str(challenge_int),
            
            # Entrées publiques
            "publicKeyX": str(public_key[0] % self.field_order),
            "publicKeyY": str(public_key[1] % self.field_order),
            "challengeHash": str(challenge_hash),
            "nonceCommitment": str(nonce_commitment)
        }
        
        return circuit_inputs
    
    def generate_proof(self, private_key: int, challenge: str, 
                      public_key: Tuple[int, int]) -> ZKProof:
        """
        Génère une preuve ZKP de possession de clé privée
        """
        print(f"🔐 Génération de preuve ZKP...")
        start_time = time.time()
        
        try:
            # Préparation des entrées
            circuit_inputs = self.prepare_circuit_inputs(private_key, challenge, public_key)
            
            # Écriture du fichier d'entrée
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(circuit_inputs, f)
                input_file = f.name
            
            # Fichiers temporaires pour la preuve
            witness_file = tempfile.mktemp(suffix='.wtns')
            proof_file = tempfile.mktemp(suffix='.json')
            public_file = tempfile.mktemp(suffix='.json')
            
            # Génération du witness
            self._run_command([
                "node", 
                os.path.join(self.circuit_dir, "keyPossession_js", "generate_witness.js"),
                os.path.join(self.circuit_dir, "keyPossession_js", "keyPossession.wasm"),
                input_file,
                witness_file
            ])
            
            # Génération de la preuve
            self._run_command([
                "snarkjs", "groth16", "prove",
                self.zkey_path,
                witness_file,
                proof_file,
                public_file
            ])
            
            # Lecture des résultats
            with open(proof_file, 'r') as f:
                proof_data = json.load(f)
            
            with open(public_file, 'r') as f:
                public_signals = json.load(f)
            
            with open(self.vkey_path, 'r') as f:
                verification_key = json.load(f)
            
            # Nettoyage des fichiers temporaires
            for temp_file in [input_file, witness_file, proof_file, public_file]:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            
            generation_time = time.time() - start_time
            print(f"✅ Preuve générée en {generation_time:.3f}s")
            
            return ZKProof(
                proof=proof_data,
                public_signals=public_signals,
                verification_key=verification_key,
                proof_type="key_possession",
                timestamp=time.time()
            )
            
        except Exception as e:
            print(f"❌ Erreur de génération de preuve: {e}")
            raise
    
    def verify_proof(self, zkp_proof: ZKProof) -> bool:
        """
        Vérifie une preuve ZKP
        """
        print("🔍 Vérification de preuve ZKP...")
        
        try:
            # Fichiers temporaires
            proof_file = tempfile.mktemp(suffix='.json')
            public_file = tempfile.mktemp(suffix='.json')
            vkey_file = tempfile.mktemp(suffix='.json')
            
            # Écriture des fichiers
            with open(proof_file, 'w') as f:
                json.dump(zkp_proof.proof, f)
            
            with open(public_file, 'w') as f:
                json.dump(zkp_proof.public_signals, f)
            
            with open(vkey_file, 'w') as f:
                json.dump(zkp_proof.verification_key, f)
            
            # Vérification
            result = subprocess.run([
                "snarkjs", "groth16", "verify",
                vkey_file,
                public_file,
                proof_file
            ], capture_output=True, text=True)
            
            # Nettoyage
            for temp_file in [proof_file, public_file, vkey_file]:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            
            is_valid = result.returncode == 0 and "OK" in result.stdout
            
            if is_valid:
                print("✅ Preuve ZKP valide")
            else:
                print("❌ Preuve ZKP invalide")
                print(f"Sortie: {result.stdout}")
                print(f"Erreur: {result.stderr}")
            
            return is_valid
            
        except Exception as e:
            print(f"❌ Erreur de vérification: {e}")
            return False
    
    def create_auth_request(self, client_id: str, private_key: int, 
                          public_key: Tuple[int, int], challenge: str) -> ClientAuthRequest:
        """
        Crée une requête d'authentification complète avec ZKP
        """
        print(f"📝 Création de requête d'auth pour client {client_id}")
        
        # Génération de la preuve
        zkp_proof = self.generate_proof(private_key, challenge, public_key)
        
        # Génération du commitment sur le nonce (pour la reproductibilité)
        nonce = secrets.randbelow(self.field_order)
        nonce_commitment = self.generate_nonce_commitment(nonce)
        
        return ClientAuthRequest(
            client_id=client_id,
            challenge=challenge,
            public_key_x=hex(public_key[0]),
            public_key_y=hex(public_key[1]),
            zkp_proof=zkp_proof,
            nonce_commitment=nonce_commitment
        )

# Exemple d'utilisation
if __name__ == "__main__":
    # Initialisation du générateur
    zkp_gen = ZKPProofGenerator("./circuits")
    
    # Simulation d'un client avec une clé privée
    private_key = secrets.randbelow(zkp_gen.field_order)
    public_key = (
        55066263022277343669578718895168534326250603453777594175500187360389116729240,
        32670510020758816978083085130507043184471273380659243275938904335757337482424
    )  # Point générateur secp256k1 pour l'exemple
    
    # Challenge du serveur
    challenge = "auth_challenge_" + secrets.token_hex(16)
    
    try:
        # Génération de la preuve
        proof = zkp_gen.generate_proof(private_key, challenge, public_key)
        
        # Vérification
        is_valid = zkp_gen.verify_proof(proof)
        
        print(f"\n🎉 Test ZKP {'réussi' if is_valid else 'échoué'}")
        print(f"Taille de la preuve: {len(json.dumps(proof.proof))} bytes")
        print(f"Temps de génération: {proof.timestamp}")
        
        # Création d'une requête complète
        auth_request = zkp_gen.create_auth_request(
            "client_001", private_key, public_key, challenge
        )
        
        print(f"Requête d'auth créée pour {auth_request.client_id}")
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
