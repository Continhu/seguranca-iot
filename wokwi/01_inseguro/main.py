# =============================================================
#  VERSÃO INSEGURA — igual à feita em aula (05/11)
#  Raspberry Pi Pico W + DHT22 -> ThingSpeak (MicroPython / Wokwi)
#
#  Funciona, mas tem várias falhas de segurança, marcadas
#  com "PROBLEMA n". A versão corrigida está em ../02_seguro/
# =============================================================
import machine
import time
import urequests
import network
import ujson
import dht

# PROBLEMA 1: credenciais escritas direto no código-fonte.
#   Basta publicar o código no GitHub para a chave vazar
#   e qualquer pessoa poder escrever dados falsos no canal.
WIFI_SSID = "Wokwi-GUEST"
WIFI_PASSWORD = ""
THINGSPEAK_API_KEY = "COLOQUE_SUA_WRITE_API_KEY_AQUI"

# PROBLEMA 2: HTTP sem criptografia.
#   A API key e as leituras trafegam em texto puro, e quem estiver
#   na mesma rede (Wi-Fi aberto, roteador comprometido) consegue ler
#   tudo com um sniffer como o Wireshark.
THINGSPEAK_URL = "http://api.thingspeak.com/update"

dht_sensor = dht.DHT22(machine.Pin(4))


def read_temperature_and_humidity():
    # PROBLEMA 3: nenhum tratamento de erro ou validação.
    #   Se o sensor falhar ou devolver lixo (ou for adulterado),
    #   o valor é enviado mesmo assim ou o programa quebra.
    dht_sensor.measure()
    temperature = dht_sensor.temperature()
    humidity = dht_sensor.humidity()
    return temperature, humidity


def send_data_to_thingspeak(temperature, humidity):
    data = {
        "api_key": THINGSPEAK_API_KEY,
        "field1": temperature,
        "field2": humidity,
    }
    # PROBLEMA 4: não confere a resposta do servidor nem tem timeout.
    response = urequests.post(
        THINGSPEAK_URL,
        data=ujson.dumps(data),
        headers={"Content-Type": "application/json"},
    )
    response.close()
    # PROBLEMA 5: o log imprime a chave secreta no console.
    print("Enviado:", data)


wifi = network.WLAN(network.STA_IF)
wifi.active(True)
wifi.connect(WIFI_SSID, WIFI_PASSWORD)

# PROBLEMA 6: espera infinita. Sem Wi-Fi, o dispositivo trava aqui para sempre.
while not wifi.isconnected():
    pass
print("Conectado ao Wi-Fi")

try:
    while True:
        temperature, humidity = read_temperature_and_humidity()
        send_data_to_thingspeak(temperature, humidity)
        time.sleep(15)  # limite do plano gratuito do ThingSpeak
except Exception as e:
    # PROBLEMA 7: qualquer erro derruba o dispositivo,
    #   que só volta a funcionar se alguém reiniciar na mão.
    print("Erro:", e)
