# 🛡️ Sistema Multi-Agente de Ciberseguridad Preventiva 24/7 — La Paz (Bolivia)

Sistema inteligente híbrido de diagnóstico preventivo y priorización de mitigaciones en ciberseguridad diseñado para **Centros Comunitarios, Unidades Educativas y MYPES de la ciudad y el departamento de La Paz** (La Paz, El Alto y Viacha).

Combina un orquestador multi-agente **multi-proveedor** (DeepSeek, OpenAI/GPT, Google Gemini, Anthropic/Claude, OpenCode, OpenRouter, Groq, Ollama o cualquier endpoint OpenAI-compatible) con modelos de **Machine Learning supervisado** (`Random Forest`), inteligencia de amenazas verificada (**NIST NVD v2.0, FIRST EPSS, CISA KEV y URLhaus**), contexto local boliviano (**CGII/AGETIC, ATT, ASFI, INE-MYPES y Tipo de Cambio Oficial del BCB en vivo**), optimización combinatoria mediante **Algoritmo Genético** y **Guardrails deterministas** anti-alucinación.

---

## ✨ Capacidades Principales

- **Orquestación Multi-Agente agnóstica de modelo (`src/agent.py` + `src/llm_provider.py`):**
  - Soporta **DeepSeek**, **OpenAI (GPT / o-series)**, **Google Gemini**, **Anthropic (Claude)**, **OpenCode (Zen / Console)**, **OpenRouter**, **Groq**, **Ollama local** y cualquier API **OpenAI-compatible**.
  - Detección automática por `.env` (`LLM_PROVIDER=auto`) o selección en caliente desde Streamlit y la API REST.
- **Machine Learning supervisado sobre datasets reales (`src/tools.py`):**
  - **Tráfico de red (`UNSW-NB15`)**: clasificación de flujos anómalos.
  - **Phishing y *Quishing* QR (`PhiUSIIL` + `URLhaus` + heurística Bolivia)**: detecta URLs maliciosas y suplantaciones de entidades bolivianas (ASFI, Banco Unión, BCB, AGETIC, Impuestos, Entel, Tigo, pagos QR falsos, etc.).
- **Contexto Boliviano y Tipo de Cambio Oficial BCB en vivo:**
  - Consulta en tiempo real el **Tipo de Cambio Oficial (TCO)** diario del Banco Central de Bolivia mediante APIs públicas (con respaldo local configurable), expresando presupuestos y costos de remediación tanto en **USD** como en **Bolivianos (`Bs`)**.
  - Integra estadísticas sectoriales de MYPES de La Paz ([`data/INE-MYPES_DEPTO.xls`](data/INE-MYPES_DEPTO.xls)) y canales oficiales de reporte (**CGII/AGETIC CSIRT, ATT y ASFI**).
- **Optimización con Algoritmo Genético:** selecciona el subconjunto óptimo de controles y parches maximizando la reducción de riesgo (`CVSS × EPSS` + bonos CISA KEV / AGETIC CSIRT) sin exceder el presupuesto (`USD` / `Bs`) ni las horas técnicas disponibles.
- **Guardrails deterministas + Evals:** bloquea solicitudes ofensivas o fuera de alcance, exige trazabilidad literal de CVEs y cifras contra la salida de herramientas y declara explícitamente la ausencia de estadísticas barriales no disponibles.

---

## 📁 Estructura del Proyecto

```text
Proy-IA/
├── app.py                     # Interfaz web en Streamlit (selector multi-proveedor, TCO en vivo y diagnóstico)
├── requirements.txt           # Dependencias de Python
├── .env.example               # Plantilla de variables de entorno multi-proveedor y TCO BCB
├── .gitignore                 # Exclusiones para Git (secretos, .venv, modelos y CSVs pesados)
├── data/
│   ├── contexto_bolivia_lapaz.json        # Canales oficiales (CGII/AGETIC, ATT, ASFI) y reglas anti-suplantación
│   ├── cve_cache.json                     # Caché verificada de CVEs reales (NVD + EPSS + KEV)
│   ├── INE-MYPES_DEPTO.xls                # Estadísticas de MYPES manufactureras en La Paz (INE/SIIP)
│   ├── known_exploited_vulnerabilities.csv # Catálogo CISA KEV
│   └── perfiles_lapaz.json                # 14 perfiles operativos (La Paz, El Alto y Viacha)
├── datasets/
│   └── NUSW-NB15_features.csv             # Definición de columnas UNSW-NB15
├── models/
│   ├── ml_metrics.json                    # Métricas del modelo de tráfico de red (UNSW-NB15)
│   └── phishing_metrics.json              # Métricas del modelo de phishing en URLs (PhiUSIIL)
├── src/
│   ├── llm_provider.py                    # Adaptador universal multi-proveedor LLM
│   ├── agent.py                           # Orquestador Multi-Agente (Planificador + Tools + Redactor + Verificador)
│   ├── api.py                             # API REST FastAPI (/health, /tipo-cambio, /proveedores-llm, /diagnosticar)
│   ├── build_data.py                      # Generación de cve_cache.json y perfiles_lapaz.json
│   ├── guardrails.py                      # Guardrails deterministas de entrada y salida
│   ├── tools.py                           # ML red, ML phishing/URLhaus/quishing, CVEs, TCO BCB y Algoritmo Genético
│   ├── train_ml.py                        # Entrenamiento del clasificador de tráfico (UNSW-NB15)
│   ├── train_phishing.py                  # Entrenamiento del clasificador de phishing (PhiUSIIL)
│   ├── test_deepseek.py                   # Verificación rápida por CLI de cualquier proveedor LLM configurado
│   └── extraer_alertas_agetic.py          # Script opcional (Playwright) para alertas de csirt.gob.bo
└── evals/
    ├── eval_dataset.json                  # 15 casos de evaluación end-to-end
    ├── eval_results.json                  # Últimos resultados de evaluación
    ├── run_evals.py                       # Runner de evaluación automática
    ├── test_guardrails.py                 # Tests unitarios de guardrails
    ├── test_llm_provider.py               # Tests unitarios del adaptador multi-proveedor LLM
    └── test_tools.py                      # Tests unitarios de AG, Phishing/Quishing Bolivia y API BCB
```

---

## ⚙️ Requisitos Previos

- **Python 3.10+** (probado en Python 3.11 – 3.14)
- **Git**
- Al menos una **API Key** de cualquiera de los proveedores soportados (DeepSeek, OpenAI/GPT, Google Gemini, Anthropic/Claude, OpenCode, OpenRouter, Groq) o **Ollama** ejecutándose localmente.

---

## 🚀 Instalación Paso a Paso

### 1. Clonar el repositorio

```bash
git clone https://github.com/HzuDev/Proy-IA.git
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

### 4. Configurar variables de entorno (`.env`)

Copia el archivo de ejemplo:
```bash
cp .env.example .env
```

Configura **la clave del proveedor que prefieras** en `.env` (con `LLM_PROVIDER=auto` el sistema detecta automáticamente cuál estás usando):

```env
LLM_PROVIDER=auto

# Elige uno o varios según tu preferencia:
DEEPSEEK_API_KEY=sk-tu-api-key-de-deepseek
# OPENAI_API_KEY=sk-proj-...
# GEMINI_API_KEY=AIza...
# ANTHROPIC_API_KEY=sk-ant-...
# OPENCODE_API_KEY=...

# Respaldo local del Tipo de Cambio Oficial BCB si no hay conexión a las APIs públicas
TIPO_CAMBIO_BOB=11.83
```

Verifica la conexión desde terminal (funciona con tu configuración en `.env` o pasando `--provider` y `--model`):
```bash
python -m src.test_deepseek
# Ejemplo con otro proveedor/modelo:
python -m src.test_deepseek --provider gemini --model gemini-2.5-flash
```

---

## 📊 Datos y Modelos de Machine Learning

Por tamaño, los **datasets crudos** y los **modelos `.joblib` entrenados** se excluyen en `.gitignore`.

### Archivos ya incluidos en Git
- `data/cve_cache.json` y `data/perfiles_lapaz.json` (regenerables con `python -m src.build_data`).
- `data/contexto_bolivia_lapaz.json` y `data/INE-MYPES_DEPTO.xls`.
- `data/known_exploited_vulnerabilities.csv` (catálogo CISA KEV).

### Cómo entrenar los modelos `.joblib` localmente

1. **Detección de intrusiones (`models/modelo_red_unsw.joblib`)**:
   - Coloca `UNSW_NB15_training-set.csv` y `UNSW_NB15_testing-set.csv` en `data/`.
   - Ejecuta:
     ```bash
     python -m src.train_ml
     ```

2. **Detección de phishing en URLs (`models/modelo_phishing_url.joblib`)**:
   - Coloca `PhiUSIIL_Phishing_URL_Dataset.csv` en `data/`.
   - Ejecuta:
     ```bash
     python -m src.train_phishing
     ```

3. **Feed reciente de URLhaus (`data/urlhaus_recent.csv`)**:
   - Descarga el CSV reciente desde [urlhaus.abuse.ch/downloads/csv_recent/](https://urlhaus.abuse.ch/downloads/csv_recent/) y guárdalo en `data/urlhaus_recent.csv`.

---

## ▶️ Cómo Ejecutar el Proyecto

### Opción A: Interfaz Web (Streamlit)

```bash
streamlit run app.py
```

Disponible en `http://localhost:8501`. Desde la barra lateral puedes:
- Elegir el **Proveedor de IA y Modelo** (o pegar otra API Key sin tocar `.env`).
- Visualizar y ajustar el **Tipo de Cambio Oficial del BCB (`Bs / USD`)**.
- Seleccionar cualquiera de los **14 perfiles de La Paz, El Alto y Viacha**.

### Opción B: API REST (FastAPI + Uvicorn)

```bash
uvicorn src.api:app --host 0.0.0.0 --port 8000 --reload
```

Endpoints disponibles:
- `GET http://localhost:8000/health` — estado del servicio.
- `GET http://localhost:8000/tipo-cambio` — Tipo de Cambio Oficial (TCO) diario del BCB en vivo.
- `GET http://localhost:8000/proveedores-llm` — lista de proveedores soportados y estado de configuración.
- `GET http://localhost:8000/docs` — documentación interactiva (Swagger UI).
- `POST http://localhost:8000/diagnosticar` — ejecuta el pipeline multi-agente.

Ejemplo con `curl`:
```bash
curl -X POST http://localhost:8000/diagnosticar \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Diagnostica vulnerabilidades para router Wi-Fi y WordPress con Bs 450 y 4 horas.",
    "perfil_id": "LPZ-MY-01",
    "url_sospechosa": "https://asfi-renta.com/pago-qr",
    "llm_provider": "auto"
  }'
```

---

## 🧪 Pruebas y Evaluaciones

### Tests unitarios (`pytest`)

```bash
python -m pytest -v
```

*(Nota: si aún no entrenaste `modelo_phishing_url.joblib`, puedes correr `python -m pytest evals/test_guardrails.py evals/test_llm_provider.py -v`.)*

### Suite de evaluación end-to-end (15 escenarios)

```bash
python evals/run_evals.py
```

Genera el resumen de fidelidad, bloqueos de guardrail, reducción promedio de riesgo del Algoritmo Genético y latencia en `evals/eval_results.json`.

---

## 📝 Notas Adicionales

- **Script opcional de AGETIC (`src/extraer_alertas_agetic.py`)**: usa `playwright` (no incluido en `requirements.txt` por ser opcional) para extraer alertas desde `csirt.gob.bo`:
  ```bash
  pip install playwright
  playwright install chromium
  python -m src.extraer_alertas_agetic
  ```
- **Seguridad**: nunca subas el archivo `.env` con tus API keys reales al repositorio.
