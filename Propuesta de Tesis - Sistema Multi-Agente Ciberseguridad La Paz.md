# **Sistema Multi-Agente con Guardrails, Aprendizaje Automático y Algoritmos Genéticos para el Diagnóstico Preventivo de Ciberseguridad 24/7 en Centros Comunitarios y MYPES de la Ciudad de La Paz**

# **1\. Introducción**

La transformación digital en la ciudad de La Paz ha incrementado el uso de plataformas de gestión, servicios web, redes inalámbricas y pagos electrónicos en centros comunitarios, unidades educativas y micro y pequeñas empresas (MYPES). Sin embargo, estas organizaciones suelen operar sin equipos dedicados de ciberseguridad, quedando expuestas a amenazas frecuentes como phishing, intrusiones en redes locales y configuraciones inseguras.

Para abordar esta brecha sin recurrir a modelos generativos propensos a alucinaciones o respuestas genéricas, este proyecto propone un sistema inteligente híbrido disponible 24/7. La solución combina una arquitectura multi-agente con guardrails y evaluación automatizada (evals) junto con herramientas computacionales de Inteligencia Artificial clásica y metaheurística —Machine Learning supervisado para clasificación de amenazas y Algoritmos Genéticos para optimización de controles defensivos— alimentadas por datasets reales verificados y perfiles operativos representativos del entorno paceño.

# **2\. Planteamiento del problema**

Los centros comunitarios, unidades educativas y MYPES de la ciudad de La Paz presentan una alta exposición a riesgos digitales frente a una baja capacidad técnica y presupuestaria para prevenir incidentes. La ausencia de personal especializado y la restricción de horarios de soporte dificultan la detección oportuna de tráfico anómalo, enlaces maliciosos o vulnerabilidades críticas en sus servicios.

Por otra parte, el uso aislado de modelos de lenguaje (LLMs) en ciberseguridad resulta insuficiente y riesgoso: carecen de precisión matemática para optimizar recursos limitados, pueden inventar identificadores de vulnerabilidades o métricas sin sustento y tienden a desviarse del objetivo técnico si no existen controles estrictos. Sin una metodología que integre análisis estadístico/algorítmico sobre datasets reales, reglas de verificación (guardrails) y métricas sistemáticas de evaluación (evals), no es posible ofrecer diagnósticos preventivos confiables en modalidad 24/7.

De ello surge la pregunta de investigación: ¿cómo diseñar e implementar un sistema multi-agente disponible 24/7 que integre modelos de Machine Learning, Algoritmos Genéticos, guardrails y evaluación automatizada sobre datasets reales para brindar diagnósticos preventivos de ciberseguridad confiables en centros comunitarios y MYPES de la ciudad de La Paz?

# **3\. Objetivos**

## **Objetivo General**

Diseñar e implementar un sistema multi-agente de diagnóstico preventivo en ciberseguridad con disponibilidad 24/7, sustentado en una metodología híbrida de Inteligencia Artificial (orquestación agéntica con guardrails, Machine Learning supervisado y Algoritmos Genéticos) y evaluación automatizada (evals), orientado a centros comunitarios, unidades educativas y MYPES de la ciudad de La Paz.

## **Objetivos Específicos**

1. **Implementar la arquitectura multi-agente 24/7 (Plan-and-Execute / ReAct):** Desarrollar el flujo de orquestación con agentes especializados (planificador, ejecutor de herramientas y verificador) accesible de forma continua vía web/API.  
2. **Entrenar e integrar herramientas de IA basadas en datasets reales:** Incorporar modelos de Machine Learning supervisado (ej. Random Forest / XGBoost) entrenados sobre datasets reales de tráfico de red (UNSW-NB15 / CIC-IDS) y phishing (PhishTank / URLhaus), junto con consultas verificadas a NIST NVD (CVE) y FIRST EPSS.  
3. **Desarrollar un módulo de optimización mediante Algoritmos Genéticos (AG):** Implementar una herramienta metaheurística en Python que calcule combinaciones óptimas de controles y parches defensivos maximizando la reducción de riesgo (CVSS/EPSS) bajo restricciones reales de presupuesto y tiempo.  
4. **Establecer guardrails y una metodología de evaluación (evals):** Implementar validaciones estrictas de trazabilidad contra los resultados de las herramientas y construir un benchmark de pruebas para medir fidelidad, tasa de alucinación, adherencia al alcance y reproducibilidad matemática.  
5. **Validar el sistema en escenarios representativos de la ciudad de La Paz:** Evaluar el prototipo mediante perfiles técnicos estructurados que modelan la infraestructura típica de centros comunitarios, unidades educativas y MYPES paceñas.

# **4\. Justificación Social**

En la ciudad de La Paz, los centros comunitarios, unidades educativas y pequeños negocios gestionan datos personales de ciudadanos, estudiantes y clientes, además de utilizar redes Wi-Fi y pagos digitales en su operación diaria. Al no contar con áreas de seguridad informática, cualquier incidente de phishing o compromiso de red afecta directamente la continuidad de sus actividades y la confianza de su comunidad.

Contar con una plataforma inteligente disponible 24/7 permite que encargados de soporte, responsables comunitarios o emprendedores paceños analicen alertas, evalúen riesgos de red o enlaces sospechosos y obtengan un plan de acción priorizado según sus recursos reales en cualquier momento del día. De este modo, se democratiza el acceso al diagnóstico preventivo en ciberseguridad y se fortalece la resiliencia digital de organizaciones locales con bajo presupuesto.

# **5\. Justificación Técnica**

Desde una perspectiva técnica, la propuesta aporta valor real en redes y ciberseguridad al evitar que el modelo de lenguaje actúe como única fuente de cálculo o conocimiento. En su lugar, se emplea una arquitectura modular donde cada técnica de IA resuelve aquello para lo que es más eficiente: el orquestador agéntico coordina el flujo y traduce resultados; los modelos de Machine Learning clasifican tráfico de red y URLs sospechosas sobre variables reales; los Algoritmos Genéticos resuelven la optimización combinatoria de controles defensivos bajo restricciones presupuestarias; y los guardrails junto con los evals garantizan que ninguna cifra o vulnerabilidad sea inventada.

## **Evaluación: Qué tengo y qué no tengo**

| Componente | Qué tengo (disponible / de partida) | Qué no tengo (por construir, integrar o validar) |
| :---- | :---- | :---- |
| **Metodología y algoritmos de IA** | Conocimientos en redes/ciberseguridad, Python/estadística, fundamentos de Machine Learning, Algoritmos Genéticos y diseño de agentes con tools, guardrails y evals. | El pipeline integrado en producción que conecte el orquestador multi-agente con los modelos entrenados, el algoritmo genético y la suite de evals. |
| **Datasets reales y fuentes** | Acceso abierto a NIST NVD (CVE), FIRST EPSS, CIC-IDS / UNSW-NB15 (tráfico e intrusiones) y PhishTank / URLhaus (phishing). | Un dataset público masivo de incidentes reales por zona en La Paz; se suplirá con perfiles operativos estructurados (10–15 escenarios representativos de centros comunitarios y MYPES paceñas) explícitamente etiquetados en los guardrails. |
| **Infraestructura y operación 24/7** | Entorno de desarrollo en Python, Jupyter Notebooks para entrenamiento/estadística y alternativas de despliegue web/API. | Servicio desplegado 24/7 con monitoreo continuo, control de cuotas de API y almacenamiento auditado de logs y evaluaciones. |
| **Validación experimental** | Definición de métricas de evaluación técnica (fidelidad, precisión ML, convergencia AG, anti-divagación). | Ejecución completa del benchmark de pruebas y validación con los perfiles operativos definidos para La Paz. |

# **6\. Justificación Económica**

El acceso a auditorías o consultorías especializadas en ciberseguridad implica costos elevados para centros comunitarios, unidades educativas y MYPES en La Paz. Este proyecto demuestra viabilidad económica al utilizar exclusivamente herramientas de código abierto (Python, Scikit-learn/XGBoost, librerías de algoritmos evolutivos, FastAPI/Streamlit y Jupyter) y datasets públicos sin costo de licencia.

## **Estimación de costos del proyecto (ciclo de 6 meses y operación 24/7)**

* **Infraestructura de alojamiento 24/7 (VPS / Cloud básico para API y web):** Entre \$0 y \$15 USD/mes (aprovechando capas gratuitas/créditos estudiantiles o servidor virtual ligero), totalizando \$0 – \$90 USD en 6 meses.  
* **Consumo de API de modelos de lenguaje para orquestación:** Entre \$0 y \$20 USD/mes (mediante niveles gratuitos, caché de consultas y modelos eficientes), totalizando \$0 – \$120 USD en 6 meses.  
* **Datasets, librerías de IA/ML y software base:** \$0 USD (100% open-source y repositorios científicos/técnicos abiertos).  
* **Inversión total estimada:** Entre \$0 USD (escenario con créditos académicos y despliegue ligero gratuito) y \$210 USD (escenario con servidor VPS dedicado 24/7 y consumo continuo de API durante 6 meses).

# **7\. Límites y Alcances**

## **Alcances**

* Operación continua 24/7 mediante interfaz web y API para diagnóstico preventivo y análisis de riesgos en ciberseguridad.  
* Integración efectiva de Machine Learning supervisado (detección de anomalías/tráfico y phishing), Algoritmos Genéticos (optimización de remediación) y consulta verificada a bases CVE/EPSS.  
* Implementación de guardrails de trazabilidad y una suite reproducible de evaluación (evals) en Python/Jupyter.  
* Aplicación prioritaria en perfiles operativos representativos de centros comunitarios, unidades educativas y MYPES de la ciudad de La Paz (apoyados en datasets públicos verificados).

## **Límites**

* **Enfoque strictly defensivo:** El sistema no ejecuta ataques, explotación de vulnerabilidades ni escaneos intrusivos sobre infraestructuras de terceros.  
* **Carácter orientativo y preventivo:** No sustituye auditorías formales de certificación normativa, regulación financiera ni peritajes legales.  
* **Transparencia sobre cobertura de datos locales:** Ante consultas sobre estadísticas territoriales de La Paz no contenidas en los datasets verificados, el guardrail obliga a declarar la ausencia del dato sin realizar estimaciones inventadas.

# **8\. Delimitación temática**

El proyecto se circunscribe a la intersección entre ciberseguridad defensiva, redes de datos e Inteligencia Artificial aplicada:

6. **Ciberseguridad y redes:** Análisis preventivo de flujos de red, detección de phishing, evaluación de vulnerabilidades (CVE/CVSS/EPSS) y priorización de controles defensivos.  
7. **Metodologías de Inteligencia Artificial:** Orquestación multi-agente (Plan-and-Execute / ReAct), aprendizaje automático supervisado (clasificación tabular), optimización metaheurística mediante Algoritmos Genéticos, guardrails y evaluación automatizada (evals).  
8. **Delimitación geográfica y social:** Prioridad en centros comunitarios, unidades educativas y MYPES de la ciudad de La Paz (y de forma secundaria el departamento de La Paz).

Quedan excluidos el desarrollo de herramientas ofensivas/malware, el diseño físico de infraestructura de telecomunicaciones, entidades financieras sujetas a regulación bancaria y asistentes conversacionales generales sin respaldo algorítmico.

# **9\. Entorno de aplicación**

El desarrollo, entrenamiento y validación se realizarán en un entorno reproducible compuesto por:

* **Entorno de ciencia de datos e ingeniería:** Python, Jupyter Notebooks (entrenamiento de modelos ML, ejecución del Algoritmo Genético, análisis estadístico y gráficas de evals), FastAPI y una interfaz web ligera para consultas 24/7.  
* **Conjuntos de datos reales y escenarios de prueba:** Datasets públicos (NIST NVD, FIRST EPSS, UNSW-NB15 / CIC-IDS, PhishTank / URLhaus) articulados con perfiles técnicos estructurados de centros comunitarios y MYPES de la ciudad de La Paz.  
* **Entorno de despliegue 24/7:** Contenedor/servidor activo continuamente con registro estructurado de invocaciones a tools, bloqueos de guardrails y métricas de evaluación.

# **10\. Código y Aporte**

## **Código**

* **Módulo de Orquestación Multi-Agente:** Implementación del flujo Planificador \-\> Ejecutor de Tools \-\> Verificador (Guardrail) \-\> Redactor Técnico.  
* **Módulo de Machine Learning (Detección):** Pipelines en Python/Jupyter de preprocesamiento, entrenamiento y evaluación (Precision, Recall, F1-Score, ROC-AUC) sobre datasets reales de red y phishing.  
* **Módulo de Algoritmos Genéticos (Optimización):** Codificación cromosómica de controles defensivos, función de aptitud (fitness) basada en reducción de riesgo CVSS/EPSS sujeto a restricciones de presupuesto/tiempo, operadores de selección, cruce y mutación.  
* **Módulo de Consulta Verificada y Guardrails:** Conectores a NVD/EPSS y validadores automáticos que exigen correspondencia exacta entre salidas del agente y resultados JSON de las herramientas.  
* **Suite de Evaluación (Evals) y Despliegue 24/7:** Scripts automatizados de benchmark (fidelidad, anti-alucinación, adherencia al alcance sobre perfiles de La Paz) y servicio web/API continuo.

## **Aporte**

El aporte original del trabajo consiste en articular una arquitectura multi-agente confiable 24/7 que delega el análisis numérico, la clasificación de amenazas y la optimización de mitigación a algoritmos especializados de Inteligencia Artificial (Machine Learning supervisado y Algoritmos Genéticos) entrenados y validados con datasets reales, bajo un marco formal de guardrails y evals adaptado a las limitaciones presupuestarias y operativas de centros comunitarios, unidades educativas y MYPES de la ciudad de La Paz.