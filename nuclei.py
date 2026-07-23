import subprocess
import sys
import json
import re
import threading
import time
from threading import Thread

class ProgressBar:
    def __init__(self, total):
        self.total = total
        self.current = 0
        self.lock = threading.Lock()

    def update(self, increment=1):
        with self.lock:
            self.current += increment
            self._display()

    def _display(self):
        percentage = (self.current / self.total) * 100
        bar_length = 50
        filled_length = int(bar_length * self.current // self.total)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        print(f'\r[{bar}] {percentage:.1f}% ({self.current}/{self.total})', end='', flush=True)

def run_nuclei_scan(target_url, severity=None):
    # Commande pour exécuter Nuclei
    cmd = f"nuclei -u {target_url}"

    # Ajout des filtres de gravité si spécifié
    if severity:
        cmd += f" -severity {severity}"

    try:
        print(f"🔍 Lancement du scan sur {target_url}...")

        # Création de la barre de progression
        progress = ProgressBar(100)
        progress_thread = Thread(target=progress._display)
        progress_thread.daemon = True
        progress_thread.start()

        # Exécution de la commande
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        # Lecture en continu de la sortie
        output_lines = []
        while True:
            line = process.stdout.readline()
            if line:
                output_lines.append(line)
                progress.update()
            if process.poll() is not None:
                break

        # Attendre la fin du processus
        process.wait()

        # Afficher le reste de la sortie
        remaining_output = process.stdout.read()
        if remaining_output:
            output_lines.append(remaining_output)
            progress.update()

        # Afficher le résultat final
        print("\n✅ Scan terminé !")
        analyze_results(''.join(output_lines))

    except Exception as e:
        print(f"\n❌ Erreur lors de l'exécution : {str(e)}")

def analyze_results(output):
    """Analyse et affiche les résultats du scan"""
    if not output.strip():
        print("⚠️ Aucun résultat trouvé")
        return

    print("\n📋 Résultats du scan :\n")
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
