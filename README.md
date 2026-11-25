# 🛡️ Sistema Multi-Agente de Ciberseguridad Preventiva 24/7 — La Paz

Sistema de diagnóstico preventivo y priorización de mitigaciones en ciberseguridad diseñado para **Centros Comunitarios, Unidades Educativas y MYPES de La Paz (Bolivia)**. Combina un orquestador multi-agente con **DeepSeek API**, modelos de **Machine Learning** (detección de intrusiones en red y detección de URLs de phishing), consulta de vulnerabilidades reales (**NIST NVD v2.0**, **FIRST EPSS**, **CISA KEV** y **URLhaus**), optimización mediante **Algoritmo Genético** bajo restricciones de presupuesto/horas y **Guardrails deterministas**.

---

## 📁 Estructura del Proyecto

```text
Proy-IA/
├── app.py                     # Interfaz web en Streamlit
├── requirements.txt           # Dependencias de Python
├── .env.example               # Plantilla de variables de entorno
├── .gitignore                 # Exclusiones para Git (secretos, .venv, modelos y CSVs pesados)
├── data/
│   ├── cve_cache.json         # Caché de CVEs reales (NVD + EPSS)
│   ├── perfiles_lapaz.json    # 12 perfiles operativos de La Paz
│   └── known_exploited_vulnerabilities.csv  # Catálogo CISA KEV
├── datasets/
│   └── NUSW-NB15_features.csv # Definición de columnas UNSW-NB15
├── models/
│   ├── ml_metrics.json        # Métricas del modelo de tráfico de red (UNSW-NB15)
│   └── phishing_metrics.json  # Métricas del modelo de phishing en URLs (PhiUSIIL)
├── src/
│   ├── agent.py               # Orquestador Multi-Agente (Planificador + Síntesis + Guardrails)
│   ├── api.py                 # API REST con FastAPI (/health, /diagnosticar)
│   ├── build_data.py          # Generación de cve_cache.json y perfiles_lapaz.json
│   ├── guardrails.py          # Validación determinista de entrada y salida
│   ├── tools.py               # Herramientas: ML red, ML phishing/URLhaus, CVEs y Algoritmo Genético
│   ├── train_ml.py            # Entrenamiento del clasificador de tráfico (UNSW-NB15)
│   ├── train_phishing.py      # Entrenamiento del clasificador de phishing (PhiUSIIL)
│   ├── test_deepseek.py       # Prueba rápida de conexión a DeepSeek API
│   └── extraer_alertas_agetic.py  # Script opcional (Playwright) para alertas de csirt.gob.bo
└── evals/
    ├── eval_dataset.json      # 15 casos de evaluación end-to-end
    ├── eval_results.json      # Últimos resultados de evaluación
    ├── run_evals.py           # Script de evaluación automática
    ├── test_guardrails.py     # Tests unitarios de guardrails
    └── test_tools.py          # Tests unitarios de Algoritmo Genético y Phishing/URLhaus
```

---

## ⚙️ Requisitos Previos

- **Python 3.10+** (recomendado 3.11 o superior)
- **Git**
- Una **API Key de DeepSeek** ([platform.deepseek.com](https://platform.deepseek.com/))

---

## 🚀 Instalación Paso a Paso (para el equipo)

### 1. Clonar el repositorio

```bash
git clone <URL_DEL_REPOSITORIO>
cd Proy-IA
```

### 2. Crear y activar el entorno virtual

En **Linux / macOS**:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

En **Windows (PowerShell)**:
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Instalar dependencias

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configurar variables de entorno

Copia el archivo de ejemplo y agrega tu clave de DeepSeek:

```bash
cp .env.example .env
```

Edita `.env`:
```env
DEEPSEEK_API_KEY=sk-tu-api-key-real
DEEPSEEK_MODEL=deepseek-chat
```

Verifica la conexión con DeepSeek:
```bash
python -m src.test_deepseek
```

---

## 📊 Datos y Modelos de Machine Learning

Por tamaño, los **datasets crudos** y los **modelos `.joblib` compilados** no se suben al repositorio (están en `.gitignore`).

### Archivos ya incluidos en Git
- `data/cve_cache.json` y `data/perfiles_lapaz.json` (si deseas regenerarlos desde NVD/EPSS, ejecuta `python -m src.build_data`).
- `data/known_exploited_vulnerabilities.csv` (catálogo CISA KEV).

### Cómo obtener los datasets pesados y entrenar los modelos `.joblib`

1. **Modelo de detección de intrusiones (`models/modelo_red_unsw.joblib`)**:
   - Descarga `UNSW_NB15_training-set.csv` y `UNSW_NB15_testing-set.csv` y colócalos en `data/`.
   - Entrena el modelo:
     ```bash
     python -m src.train_ml
     ```

2. **Modelo de detección de phishing en URLs (`models/modelo_phishing_url.joblib`)**:
   - Descarga el dataset **PhiUSIIL Phishing URL** (`PhiUSIIL_Phishing_URL_Dataset.csv`) y colócalo en `data/`.
   - Entrena el modelo:
     ```bash
     python -m src.train_phishing
     ```

3. **Feed de URLs maliciosas (`data/urlhaus_recent.csv`)** *(usado por la herramienta de phishing/URLhaus)*:
   - Descarga el CSV reciente de URLhaus (`https://urlhaus.abuse.ch/downloads/csv_recent/`) y guárdalo como `data/urlhaus_recent.csv`.

> **Nota:** Si solo vas a probar la consulta de CVEs, el Algoritmo Genético y la interfaz conversacional con DeepSeek sin enviar features de tráfico ni URLs, el sistema funciona directamente con los archivos incluidos en Git.

---

## ▶️ Cómo Ejecutar el Proyecto

### Opción A: Interfaz Web (Streamlit)

```bash
streamlit run app.py
```
Disponible por defecto en `http://localhost:8501`.

### Opción B: API REST (FastAPI + Uvicorn)

```bash
uvicorn src.api:app --host 0.0.0.0 --port 8000 --reload
```

- Healthcheck: `GET http://localhost:8000/health`
- Documentación interactiva (Swagger UI): `http://localhost:8000/docs`
- Endpoint principal: `POST http://localhost:8000/diagnosticar`

Ejemplo de petición `curl`:
```bash
curl -X POST http://localhost:8000/diagnosticar \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Diagnostica vulnerabilidades para router Wi-Fi y WordPress con $40 USD y 4 horas.",
    "perfil_id": "LPZ-MY-01"
  }'
```

---

## 🧪 Pruebas y Evaluaciones

### Tests unitarios (`pytest`)

```bash
pytest evals/test_guardrails.py
```

Si ya entrenaste `modelo_phishing_url.joblib` y descargaste `data/urlhaus_recent.csv`, puedes correr toda la suite:
```bash
pytest
```

### Suite de evaluación end-to-end (requiere `DEEPSEEK_API_KEY` configurada)

```bash
python evals/run_evals.py
```
Genera el resumen de métricas y guarda el detalle en `evals/eval_results.json`.

---

## 📝 Notas Adicionales

- **Script opcional de AGETIC (`src/extraer_alertas_agetic.py`)**: utiliza `playwright` (no incluido en `requirements.txt` por ser opcional). Si deseas ejecutarlo:
  ```bash
  pip install playwright
  playwright install chromium
  python -m src.extraer_alertas_agetic
  ```
- **Seguridad**: nunca subas el archivo `.env` con tu `DEEPSEEK_API_KEY` al repositorio.
