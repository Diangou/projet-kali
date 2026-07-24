import subprocess
import sys
import json
import re
import threading
import time
from threading import Thread

class Animation:
    def __init__(self):
        self.running = False
        self.thread = None
        self.chars = ['|', '/', '-', '\\']
        
    def start(self):
        self.running = True
        self.thread = Thread(target=self._animate)
        self.thread.daemon = True
        self.thread.start()
        
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
            
    def _animate(self):
        while self.running:
            for char in self.chars:
                print(f'\r🔍 Analyse en cours... {char}', end='', flush=True)
                time.sleep(0.1)
        print('\r✅ Analyse terminée         ', end='', flush=True)

def run_nuclei_scan(target_url, severity=None):
    # Commande pour exécuter Nuclei
    cmd = f"nuclei -u {target_url}"
    
    # Ajout des filtres de gravité si spécifié
    if severity:
        cmd += f" -severity {severity}"
    
    try:
        print(f"🔍 Lancement du scan sur {target_url}...")
        
        # Création de l'animation
        anim = Animation()
        anim.start()
        
        # Exécution de la commande
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # Arrêt de l'animation
        anim.stop()
        
        if result.returncode == 0:
            print("\n✅ Scan terminé avec succès\n")
            analyze_results(result.stdout)
        else:
            print("\n❌ Erreur lors du scan :")
            print(result.stderr)
            
    except Exception as e:
        print(f"Erreur lors de l'exécution : {str(e)}")

def analyze_results(output):
    """Analyse et affiche les résultats du scan"""
    if not output.strip():
        print("⚠️ Aucun résultat trouvé")
        return
        
    print("📋 Résultats du scan :\n")
    results = []
    
    for line in output.strip().split('\n'):
        if line.strip():
            # Extraction des informations avec regex
            match = re.match(r'\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+(.*)', line.strip())
            if match:
                template_id, category, severity, details = match.groups()
                
                # Stockage des résultats
                results.append({
                    'template_id': template_id,
                    'category': category,
                    'severity': severity,
                    'details': details
                })
                
                # Affichage formaté
                print(f"🔍 [{severity.upper()}] {template_id}")
                print(f"   Catégorie : {category}")
                print(f"   Détails : {details}\n")
    
    if results:
        print(f"📊 Total : {len(results)} vulnérabilités trouvées")
    else:
        print("✅ Aucune vulnérabilité trouvée")

# Exemple d'utilisation
if __name__ == "__main__":
    target_url = "http://localhost:3000"
    severity = None
    
    # Vérification des arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "-severity":
            if len(sys.argv) > 2:
                severity = sys.argv[2]
            else:
                print("⚠️ Spécifiez une gravité (info, low, medium, high, critical)")
                sys.exit(1)
    
    run_nuclei_scan(target_url, severity)