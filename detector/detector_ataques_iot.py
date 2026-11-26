"""
Detector de ataques em tráfego IoT com MLP (scikit-learn)
==========================================================

Ideia: o tráfego de um dispositivo IoT é muito previsível. Um sensor manda
um pacote pequeno para a nuvem a cada 15 s e quase nada mais. Quando o
dispositivo é infectado (como no Mirai), esse padrão muda bastante:
aparecem varreduras, tentativas de login por Telnet e inundações (DDoS).

Este script:
  1. gera um dataset SINTÉTICO de janelas de tráfego (10 s por dispositivo),
     com 4 classes: normal, varredura, força bruta Telnet e DDoS;
  2. treina uma MLP, o mesmo MLPClassifier da aula de 12/11 (Iris/Wine);
  3. mostra acurácia, relatório por classe e a matriz de confusão.

Os dados são simulados para fins didáticos. Para dados reais, veja os datasets
CICIoT2023, N-BaIoT e TON_IoT (links no README).

Rodar:  python detector_ataques_iot.py      (ou cole no Google Colab)
"""
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # salva as figuras em arquivo (funciona sem tela)
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (ConfusionMatrixDisplay, accuracy_score,
                             classification_report, confusion_matrix)
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # acentos corretos no terminal do Windows

SEMENTE = 42
PASTA = Path(__file__).resolve().parent
SAIDA = PASTA / "resultados"
SAIDA.mkdir(exist_ok=True)

FEATURES = [
    "pacotes_por_s",         # volume de pacotes na janela
    "bytes_medio_pacote",    # tamanho médio do pacote
    "ips_destino",           # quantos IPs diferentes o dispositivo contatou
    "portas_destino",        # quantas portas de destino diferentes
    "fracao_syn",            # fração de conexões abertas sem resposta (SYN)
    "tentativas_telnet",     # conexões nas portas 23/2323 (alvo do Mirai)
    "fracao_saida",          # fração do tráfego que SAI do dispositivo
    "duracao_conexao_s",     # duração média das conexões
]
CLASSES = ["Normal", "Varredura", "Força bruta Telnet", "DDoS"]

rng = np.random.default_rng(SEMENTE)


def gerar_classe(classe, n):
    """Sorteia n janelas de tráfego com o 'perfil' típico de cada classe."""
    if classe == "Normal":
        # 70% sensores mandando dados para a nuvem + 30% câmeras transmitindo
        # vídeo (normal, mas pesado, o que confunde com ataques de volume)
        n_cam = int(n * 0.3)
        n_sen = n - n_cam
        sensor = [rng.lognormal(np.log(2), 0.6, n_sen), rng.normal(300, 120, n_sen),
                  rng.poisson(1.5, n_sen) + 1, rng.poisson(1.0, n_sen) + 1,
                  rng.beta(1, 20, n_sen), rng.poisson(0.05, n_sen),
                  rng.beta(5, 5, n_sen), rng.lognormal(np.log(2), 0.5, n_sen)]
        camera = [rng.lognormal(np.log(120), 0.6, n_cam), rng.normal(900, 300, n_cam),
                  rng.poisson(1.5, n_cam) + 1, rng.poisson(1.5, n_cam) + 1,
                  rng.beta(2, 12, n_cam), rng.poisson(0.1, n_cam),
                  rng.beta(12, 2, n_cam), rng.lognormal(np.log(8), 0.6, n_cam)]
        cols = [np.concatenate([s, c]) for s, c in zip(sensor, camera)]
    elif classe == "Varredura":     # procurando outros alvos na rede (inclui Telnet)
        cols = [rng.lognormal(np.log(50), 0.8, n), rng.normal(75, 25, n),
                rng.poisson(30, n) + 3, rng.poisson(20, n) + 2,
                rng.beta(12, 4, n), rng.poisson(10, n),
                rng.beta(9, 1.5, n), rng.lognormal(np.log(0.1), 0.6, n)]
    elif classe == "Força bruta Telnet":  # testando senhas padrão (Mirai)
        cols = [rng.lognormal(np.log(25), 0.7, n), rng.normal(110, 35, n),
                rng.poisson(15, n) + 1, rng.poisson(2, n) + 1,
                rng.beta(6, 4, n), rng.poisson(40, n),
                rng.beta(7, 3, n), rng.lognormal(np.log(0.8), 0.6, n)]
    else:                           # DDoS: inundando uma única vítima
        cols = [rng.lognormal(np.log(900), 0.8, n), rng.normal(500, 400, n),
                rng.poisson(1, n) + 1, rng.poisson(2, n) + 1,
                rng.beta(8, 3, n), np.zeros(n),
                rng.beta(30, 1, n), rng.lognormal(np.log(0.05), 0.7, n)]
    return np.column_stack(cols)


def gerar_dataset():
    tamanhos = {"Normal": 3000, "Varredura": 1000,
                "Força bruta Telnet": 1000, "DDoS": 1000}  # desbalanceado, como na vida real
    X_partes, y_partes = [], []
    for i, classe in enumerate(CLASSES):
        X = gerar_classe(classe, tamanhos[classe])
        if classe != "Normal":
            # 12% dos ataques são "discretos" (low-and-slow): parecem tráfego
            # normal de propósito, para fugir da detecção. São os casos difíceis.
            disc = rng.random(len(X)) < 0.12
            mistura = rng.uniform(0.03, 0.3, (disc.sum(), 1))
            X[disc] = mistura * X[disc] + (1 - mistura) * gerar_classe("Normal", disc.sum())
        X_partes.append(X)
        y_partes.append(np.full(len(X), i))
    X = np.clip(np.vstack(X_partes), 0, None)
    X[:, 4] = np.clip(X[:, 4], 0, 1)
    X[:, 6] = np.clip(X[:, 6], 0, 1)
    return X, np.concatenate(y_partes)


def main():
    # 1) Dados
    X, y = gerar_dataset()
    df = pd.DataFrame(X, columns=FEATURES).round(3)
    df["classe"] = [CLASSES[i] for i in y]
    df.to_csv(SAIDA / "trafego_iot_sintetico.csv", index=False)
    print(f"Dataset: {X.shape[0]} janelas x {X.shape[1]} features")
    print(df["classe"].value_counts().to_string(), "\n")

    # 2) Treino x teste (80/20), igual à aula do Iris
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=SEMENTE, stratify=y)

    # 3) MLP: entrada = 8 neurônios (features), ocultas 32 e 16, saída = 4 classes.
    #    O StandardScaler coloca todas as features na mesma escala, o que é
    #    essencial porque "pacotes_por_s" chega a milhares e "fracao_syn" vai de 0 a 1.
    modelo = make_pipeline(
        StandardScaler(),
        MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=1000, random_state=SEMENTE))
    modelo.fit(X_train, y_train)
    y_pred = modelo.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print(f"Acurácia COM normalização: {acc:.3f}")

    # Comparação: a mesma rede sem normalização dos dados
    sem_norm = MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=1000, random_state=SEMENTE)
    sem_norm.fit(X_train, y_train)
    print(f"Acurácia SEM normalização: {accuracy_score(y_test, sem_norm.predict(X_test)):.3f}\n")

    print(classification_report(y_test, y_pred, target_names=CLASSES, digits=3))

    # 4) Matriz de confusão
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(7, 6), dpi=150)
    ConfusionMatrixDisplay(cm, display_labels=CLASSES).plot(ax=ax, cmap="Blues", colorbar=False)
    ax.set_title(f"Matriz de confusão: MLP (acurácia {acc:.1%})")
    ax.set_xlabel("Classe prevista")
    ax.set_ylabel("Classe real")
    plt.setp(ax.get_xticklabels(), rotation=20, ha="right")
    fig.tight_layout()
    fig.savefig(SAIDA / "matriz_confusao.png")

    ataques_reais = y_test != 0
    perdidos = int(((y_pred == 0) & ataques_reais).sum())
    alarmes_falsos = int(((y_pred != 0) & ~ataques_reais).sum())
    print(f"Ataques que passaram como 'Normal' (falsos negativos): {perdidos} de {int(ataques_reais.sum())}")
    print(f"Tráfego normal acusado como ataque (falsos positivos): {alarmes_falsos} de {int((~ataques_reais).sum())}\n")

    # 5) Testando janelas novas, escritas à mão
    exemplos = pd.DataFrame([
        # pps, bytes, ips, portas, syn, telnet, saída, duração
        [1.5, 320, 1, 1, 0.0, 0, 0.55, 2.1],     # o nosso Pico W mandando para o ThingSpeak
        [35, 100, 18, 2, 0.6, 52, 0.75, 0.7],    # câmera infectada testando senhas por Telnet
        [1500, 60, 1, 1, 0.9, 0, 0.99, 0.03],    # dispositivo participando de um DDoS
    ], columns=FEATURES)
    for (_, linha), pred, prob in zip(exemplos.iterrows(), modelo.predict(exemplos.values),
                                      modelo.predict_proba(exemplos.values)):
        print(f"{CLASSES[pred]:<20} (confiança {prob.max():.1%})  <- {linha.values.tolist()}")

    print(f"\nArquivos salvos em: {SAIDA}")


if __name__ == "__main__":
    main()
