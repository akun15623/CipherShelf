FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DEFAULT_TIMEOUT=120

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd --gid 1000 svault && useradd --uid 1000 --gid svault --no-create-home svault

COPY --chown=svault:svault crypto.py app.py encrypt.py decrypt.py ./
COPY --chown=svault:svault static/ static/

ENV VAULT_ROOT=/data \
    PORT=8080

EXPOSE 8080

USER svault

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
