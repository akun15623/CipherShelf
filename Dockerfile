FROM python:3.13-slim

WORKDIR /app

# 国内镜像加速（受限网络环境）
ENV PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    PIP_DEFAULT_TIMEOUT=120

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY crypto.py app.py encrypt.py decrypt.py ./
COPY static/ static/

ENV VAULT_ROOT=/data \
    PORT=8080

EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
