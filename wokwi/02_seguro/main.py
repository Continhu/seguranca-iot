# =============================================================
#  VERSÃO SEGURA — mesmo projeto da aula, com as falhas corrigidas
#  Raspberry Pi Pico W + DHT22 -> ThingSpeak (MicroPython / Wokwi)
#
#  Cada correção está marcada com "CORREÇÃO n", e o número
#  corresponde ao "PROBLEMA n" da versão insegura.
# =============================================================
import machine
import time
import urequests
import network
import ujson
import dht

# CORREÇÃO 1: os segredos ficam num arquivo separado (config_secreta.py),
#   que está no .gitignore e não vai para o GitHub. No repositório só vai
#   o modelo config_secreta_exemplo.py.
try:
    from config_secreta import WIFI_SSID, WIFI_PASSWORD, THINGSPEAK_API_KEY
except ImportError:
    raise SystemExit("Crie config_secreta.py a partir de config_secreta_exemplo.py")

# CORREÇÃO 2: HTTPS (TLS). A chave e os dados viajam criptografados.
#   Obs.: no MicroPython o TLS cifra a conexão, mas por padrão NÃO valida
#   o certificado do servidor. Para produção, embarque o certificado da
#   CA e use ssl.SSLContext com verify_mode = ssl.CERT_REQUIRED.
THINGSPEAK_URL = "https://api.thingspeak.com/update"

INTERVALO_S = 15          # limite do plano gratuito do ThingSpeak
ESPERA_MAX_S = 120        # teto do backoff quando há falhas seguidas
TIMEOUT_WIFI_S = 20
TIMEOUT_HTTP_S = 10

# Faixa física do DHT22 (datasheet): -40 a 80 °C e 0 a 100 % de umidade.
TEMP_MIN, TEMP_MAX = -40.0, 80.0
UMID_MIN, UMID_MAX = 0.0, 100.0

dht_sensor = dht.DHT22(machine.Pin(4))

# CORREÇÃO 7: o watchdog reinicia a placa sozinho se o programa travar.
#   No RP2040 o tempo máximo é ~8,3 s, por isso o loop "alimenta" o
#   watchdog a cada segundo enquanto espera.
try:
    wdt = machine.WDT(timeout=8000)
except Exception:
    wdt = None  # se o simulador não tiver watchdog, segue sem ele


def alimentar_watchdog():
    if wdt:
        wdt.feed()


def esperar(segundos):
    """Dorme em passos de 1 s para não deixar o watchdog disparar."""
    for _ in range(int(segundos)):
        alimentar_watchdog()
        time.sleep(1)


def mascarar(segredo):
    # CORREÇÃO 5: o log nunca mostra a chave inteira.
    return segredo[:2] + "****" if segredo else "(vazio)"


def conectar_wifi(wifi):
    # CORREÇÃO 6: a conexão tem tempo-limite; se estourar, tenta de novo mais tarde.
    if wifi.isconnected():
        return True
    wifi.connect(WIFI_SSID, WIFI_PASSWORD)
    for _ in range(TIMEOUT_WIFI_S):
        if wifi.isconnected():
            print("Wi-Fi conectado:", wifi.ifconfig()[0])
            return True
        esperar(1)
    print("Wi-Fi: tempo esgotado")
    return False


def ler_sensor():
    # CORREÇÃO 3: trata falha do sensor e descarta valores fora da faixa física.
    try:
        dht_sensor.measure()
        t = dht_sensor.temperature()
        h = dht_sensor.humidity()
    except OSError as e:
        print("Falha na leitura do DHT22:", e)
        return None
    if not (TEMP_MIN <= t <= TEMP_MAX and UMID_MIN <= h <= UMID_MAX):
        print("Leitura descartada (fora da faixa):", t, h)
        return None
    return t, h


def enviar_thingspeak(t, h):
    dados = {"api_key": THINGSPEAK_API_KEY, "field1": t, "field2": h}
    resposta = None
    try:
        resposta = urequests.post(
            THINGSPEAK_URL,
            data=ujson.dumps(dados),
            headers={"Content-Type": "application/json"},
            timeout=TIMEOUT_HTTP_S,
        )
        # CORREÇÃO 4: confere a resposta. O ThingSpeak devolve o id da
        #   entrada (> 0) quando aceita e "0" quando recusa (chave errada,
        #   limite de envio estourado...).
        ok = resposta.status_code == 200 and resposta.text.strip() != "0"
        print("ThingSpeak:", resposta.status_code, resposta.text.strip(),
              "| chave", mascarar(THINGSPEAK_API_KEY))
        return ok
    except Exception as e:
        print("Erro no envio:", e)
        return False
    finally:
        if resposta:
            resposta.close()


def main():
    wifi = network.WLAN(network.STA_IF)
    wifi.active(True)
    espera = INTERVALO_S

    while True:
        alimentar_watchdog()
        try:
            sucesso = False
            if conectar_wifi(wifi):
                leitura = ler_sensor()
                if leitura:
                    sucesso = enviar_thingspeak(*leitura)
            # Backoff exponencial: com falhas seguidas, espera cada vez mais
            # (sem martelar o servidor); no primeiro sucesso, volta ao normal.
            espera = INTERVALO_S if sucesso else min(espera * 2, ESPERA_MAX_S)
        except Exception as e:
            # CORREÇÃO 7 (cont.): um erro inesperado não derruba o dispositivo.
            print("Erro inesperado:", e)
            espera = min(espera * 2, ESPERA_MAX_S)
        esperar(espera)


main()
