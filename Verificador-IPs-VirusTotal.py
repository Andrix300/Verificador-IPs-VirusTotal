import requests
import time
import json

# Tu clave de API de VirusTotal
API_KEY = '427ff9b67a33614876d2a7949fe540f41f17dff99cdc034df83495d212ba4def'

# Lista de IPs que quieres verificar
ips = [
       
    '181.36.220.143'


    # Agrega más IPs a la lista
]

# URL base de la API de VirusTotal
url = 'https://www.virustotal.com/api/v3/ip_addresses/'

# Cabeceras necesarias para autenticar la solicitud
headers = {
    'x-apikey': API_KEY
}

# Función para consultar la API de VirusTotal
def check_ip(ip):
    try:
        response = requests.get(url + ip, headers=headers)
        response.raise_for_status()  # Lanza un error si el status no es 200
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error al consultar la IP {ip}: {e}")
        return None

# Función para mostrar la información organizada
def print_results(ip, data):
    if not data:
        print(f"\n[ERROR] No se pudieron obtener datos para la IP {ip}.")
        return

    # Información básica
    print(f"\n{('-'*50)}")
    print(f"Análisis de la IP: {ip}")
    print(f"{('-'*50)}")

    # Información general
    last_analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    total_detections = last_analysis_stats.get("malicious", 0) + last_analysis_stats.get("suspicious", 0)

    print(f"Detecciones: {total_detections} de {len(last_analysis_stats)} motores.")
    print(f"Estado: {'Maliciosa' if total_detections > 0 else 'Segura'}")

    # Detalles de la respuesta de VirusTotal
    if total_detections > 0:
        print("\nMotores de detección afectados:")
        engines = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
        for engine, result in engines.items():
            if result.get("category") in ['malicious', 'suspicious']:
                print(f"- {engine}: {result.get('category')} (Motivo: {result.get('engine_name')})")

    # Información adicional
    print("\nDetalles del análisis:")
    print(f"- Fecha del último análisis: {data.get('data', {}).get('attributes', {}).get('last_analysis_date')}")
    print(f"- Países que podrían estar relacionados con la IP: {data.get('data', {}).get('attributes', {}).get('country', 'Desconocido')}")

    print(f"{('-'*50)}")

# Validación de todas las IPs
def validate_ips():
    for ip in ips:
        result = check_ip(ip)
        print_results(ip, result)
        time.sleep(15)  # Espera 15 segundos entre consultas para no exceder el límite de la API

if __name__ == "__main__":
    validate_ips()